"""
notifier.py
Background email alerts for live errors, delivered over SMTP (e.g. Brevo's
smtp-relay.brevo.com).

Config (env vars, loaded by app.py via python-dotenv):

    NOTIFY_ENABLED          1/0 master switch (default off)
    SMTP_HOST               e.g. smtp-relay.brevo.com
    SMTP_PORT               587 (STARTTLS) or 465 (SSL)
    SMTP_TLS                1 = STARTTLS after connect
    SMTP_SSL                1 = implicit SSL on connect (465)
    SMTP_USER               Brevo SMTP login OR SMTP key
    SMTP_PASSWORD           Brevo master password / SMTP key (may be empty
                            when the SMTP key is used as the username)
    MAIL_FROM               sender address (must be verified in Brevo)
    MAIL_TO                 comma-separated recipients
    NOTIFY_INTERVAL_HOURS   resend cooldown for a recurring error (default 3)

Anti-spam / dedup behaviour (per server_id + gid):

    * first occurrence                       -> email immediately
    * recurrence within the interval         -> no email
    * recurrence after the interval AND the
      count grew since the last email
      ("still not fixed")                    -> resend with the updated count

Delivery runs on a background worker thread fed by a bounded queue, so a
slow/unreachable SMTP server never blocks the log pollers.
"""

import logging
import os
import queue
import smtplib
import threading
from datetime import datetime
from email.message import EmailMessage
from typing import Dict, Optional, Tuple

log = logging.getLogger("notifier")


def _flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _interval_hours() -> float:
    try:
        return float(os.environ.get("NOTIFY_INTERVAL_HOURS", "3") or 3)
    except ValueError:
        return 3.0


def _enabled() -> bool:
    if not _flag("NOTIFY_ENABLED"):
        return False
    if not os.environ.get("MAIL_TO", "").strip():
        return False
    return True


class Notifier:
    """Queue + worker that dedups and sends error alert emails."""

    def __init__(self):
        self._events: "queue.Queue[dict]" = queue.Queue(maxsize=2000)
        self._lock = threading.Lock()
        # (server_id, gid) -> {"last_sent_at": datetime, "count": int}
        self._sent: Dict[Tuple[str, str], dict] = {}
        self._thread: Optional[threading.Thread] = None
        self._sender = None  # injectable for tests (subject, body) -> None

    # -- public API ---------------------------------------------------
    def notify(self, server, group) -> None:
        """Cheap, non-blocking: snapshot the group and enqueue an alert
        event. The worker decides whether a mail should actually go out."""
        if not _enabled():
            return
        snap = _snapshot(server, group)
        if snap is None:
            return
        try:
            self._events.put_nowait(snap)
        except queue.Full:
            log.warning("notifier queue full; dropped alert for %s", snap.get("gid"))
        self._ensure_worker()

    # -- worker --------------------------------------------------------
    def _ensure_worker(self) -> None:
        if self._thread is None or not self._thread.is_alive():
            self._thread = threading.Thread(
                target=self._run, daemon=True, name="error-notifier"
            )
            self._thread.start()

    def _run(self) -> None:
        while True:
            snap = self._events.get()
            try:
                self._maybe_send(snap)
            except Exception:  # noqa: BLE001 — never let the worker die
                log.exception("notifier failed for %s", snap.get("gid"))

    def _maybe_send(self, snap: dict) -> None:
        key = (snap["server_id"], snap["gid"])
        now = datetime.utcnow()
        with self._lock:
            prev = self._sent.get(key)
            if prev is None:
                # First time we've seen this error -> inform the user once.
                self._sent[key] = {"last_sent_at": now, "count": snap["count"]}
                should_send = True
            else:
                elapsed_h = (now - prev["last_sent_at"]).total_seconds() / 3600.0
                # Cooldown elapsed AND it kept happening -> resend, with the
                # updated occurrence count ("still not fixed").
                if elapsed_h >= _interval_hours() and snap["count"] > prev["count"]:
                    self._sent[key] = {"last_sent_at": now, "count": snap["count"]}
                    should_send = True
                else:
                    should_send = False
        if should_send:
            self._deliver(snap)

    def _deliver(self, snap: dict) -> None:
        subject, body = _subject(snap), _body(snap)
        if self._sender is not None:
            self._sender(subject, body)
            return
        _send_smtp(subject, body)

    # -- tests ----------------------------------------------------------
    def reset(self) -> None:
        with self._lock:
            self._sent.clear()
        while True:
            try:
                self._events.get_nowait()
            except queue.Empty:
                break
def _snapshot(server, group) -> Optional[dict]:
    if server is None or group is None:
        return None
    return {
        "server_id": getattr(server, "id", ""),
        "server_name": getattr(server, "name", "?"),
        "server_host": getattr(server, "host", ""),
        "server_port": getattr(server, "port", ""),
        "server_path": getattr(server, "log_path", ""),
        "gid": group.gid,
        "severity": group.severity,
        "exception_class": group.exception_class,
        "message": group.message,
        "top_frame": group.top_frame,
        "count": group.count,
        "first_seen": _iso(group.first_seen),
        "last_seen": _iso(group.last_seen),
        "sample": (group.sample_raw_text or "")[:2000],
    }


def _iso(dt) -> str:
    if not dt:
        return ""
    if hasattr(dt, "isoformat"):
        return dt.isoformat(timespec="seconds")
    return str(dt)


def _subject(snap: dict) -> str:
    sev = str(snap.get("severity") or "error").upper()
    exc = snap.get("exception_class") or "Error"
    return f"[Hybris Monitor] {sev}: {exc} on {snap.get('server_name')}"


def _body(snap: dict) -> str:
    lines = [
        f"Server          : {snap['server_name']} ({snap['server_host']}:{snap['server_port']})",
        f"Log file        : {snap['server_path']}",
        f"Severity        : {snap['severity']}",
        "",
        f"Error           : {snap['exception_class']}",
        f"Message         : {snap['message']}",
    ]
    if snap.get("top_frame"):
        lines.append(f"At              : {snap['top_frame']}")
    lines += [
        "",
        f"Occurrences     : {snap['count']}",
        f"First seen      : {snap['first_seen'] or '—'}",
        f"Last seen       : {snap['last_seen'] or '—'}",
    ]
    if snap.get("sample"):
        lines += ["", "--- log snippet ---", snap["sample"][:1500]]
    return "\n".join(lines)

def _send_smtp(subject: str, body: str) -> None:
    host = os.environ.get("SMTP_HOST", "").strip()
    port = int(os.environ.get("SMTP_PORT", "587") or 587)
    user = os.environ.get("SMTP_USER", "").strip()
    password = os.environ.get("SMTP_PASSWORD", "").strip()
    mail_from = os.environ.get("MAIL_FROM", "").strip()
    to_list = [x.strip() for x in os.environ.get("MAIL_TO", "").split(",") if x.strip()]
    if not host or not mail_from or not to_list:
        raise RuntimeError("SMTP alerts not configured: SMTP_HOST, MAIL_FROM, MAIL_TO")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = mail_from
    msg["To"] = ", ".join(to_list)
    msg.set_content(body)

    # Brevo also accepts the SMTP key (xsmtpsib-...) as the username with an
    # EMPTY password. Try the configured pair first, then the key/empty form.
    attempts = [(user, password)]
    if user.startswith("xsmtpsib-"):
        attempts.append((user, ""))

    last_err = None
    for uname, pwd in attempts:
        try:
            _smtp_send(host, port, uname, pwd, msg)
            log.info("alert email sent to %s (subject=%r)", to_list, subject)
            return
        except smtplib.SMTPAuthenticationError as exc:
            last_err = exc
            log.warning("SMTP auth rejected for user %r; trying empty password", uname)
            continue
    raise last_err or RuntimeError("SMTP send failed")


def _smtp_send(host: str, port: int, user: str, password: str, msg: EmailMessage) -> None:
    use_ssl = _flag("SMTP_SSL")
    use_tls = _flag("SMTP_TLS")
    if use_ssl:
        with smtplib.SMTP_SSL(host, port, timeout=30) as smtp:
            if user:
                smtp.login(user, password)
            smtp.send_message(msg)
        return
    with smtplib.SMTP(host, port, timeout=30) as smtp:
        if use_tls:
            smtp.starttls()
        if user:
            smtp.login(user, password)
        smtp.send_message(msg)


# Module singleton used by the pollers.
notifier = Notifier()


def notify(server, group) -> None:
    """Fire-and-forget entry point called from poller._record_entry."""
    notifier.notify(server, group)

