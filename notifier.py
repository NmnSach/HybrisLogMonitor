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

    * First occurrence                       -> email immediately
    * Recurrence within the interval         -> no email (suppressed to prevent spam)
    * Recurrence after the interval AND the
      count grew since the last email
      ("still not fixed")                    -> resend with updated count & last seen

Delivery runs on a background worker thread fed by a bounded queue, so a
slow/unreachable SMTP server never blocks the log pollers.
"""

import html
import logging
import os
import queue
import smtplib
import threading
from datetime import datetime
from email.message import EmailMessage
from typing import Dict, List, Optional, Tuple

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
    """Queue + worker that dedups, throttles, and sends error alert emails."""

    def __init__(self):
        self._events: "queue.Queue[dict]" = queue.Queue(maxsize=2000)
        self._lock = threading.Lock()
        # (server_id, gid) -> {"last_sent_at": datetime, "count": int, "initial_sent_at": datetime, "resend_count": int}
        self._sent: Dict[Tuple[str, str], dict] = {}
        self._thread: Optional[threading.Thread] = None
        self._sender = None  # injectable for tests: (subject, body_plain, body_html) -> None

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
        should_send = False
        is_resend = False
        old_record = None

        with self._lock:
            prev = self._sent.get(key)
            if prev is None:
                # First time we've seen this error -> inform the user once.
                should_send = True
                is_resend = False
                old_record = None
                self._sent[key] = {
                    "last_sent_at": now,
                    "count": snap["count"],
                    "initial_sent_at": now,
                    "resend_count": 0,
                }
            else:
                elapsed_h = (now - prev["last_sent_at"]).total_seconds() / 3600.0
                # Cooldown elapsed AND it kept happening -> resend with updated count ("still not fixed")
                if elapsed_h >= _interval_hours() and snap["count"] > prev["count"]:
                    should_send = True
                    is_resend = True
                    old_record = dict(prev)
                    self._sent[key] = {
                        "last_sent_at": now,
                        "count": snap["count"],
                        "initial_sent_at": prev.get("initial_sent_at", now),
                        "resend_count": prev.get("resend_count", 0) + 1,
                    }
                else:
                    should_send = False

        if should_send:
            snap["is_resend"] = is_resend
            try:
                self._deliver(snap)
            except Exception:
                # Rollback on delivery failure so we don't silence alerts for 3h if SMTP temporarily failed
                with self._lock:
                    if old_record is not None:
                        self._sent[key] = old_record
                    else:
                        self._sent.pop(key, None)
                raise

    def _deliver(self, snap: dict) -> None:
        subject = _subject(snap)
        body_plain = _body(snap)
        body_html = _html_body(snap)
        if self._sender is not None:
            self._sender(subject, body_plain, body_html)
            return
        _send_smtp(subject, body_plain, body_html)

    # -- tests & diagnostics --------------------------------------------
    def reset(self) -> None:
        with self._lock:
            self._sent.clear()
        while True:
            try:
                self._events.get_nowait()
            except queue.Empty:
                break

    def get_status(self) -> dict:
        with self._lock:
            tracked_errors = len(self._sent)
        return {
            "enabled": _enabled(),
            "smtp_host": os.environ.get("SMTP_HOST", ""),
            "smtp_port": int(os.environ.get("SMTP_PORT", "587") or 587),
            "mail_from": os.environ.get("MAIL_FROM", ""),
            "mail_to": [x.strip() for x in os.environ.get("MAIL_TO", "").split(",") if x.strip()],
            "interval_hours": _interval_hours(),
            "tracked_error_signatures": tracked_errors,
        }


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
    if hasattr(dt, "strftime"):
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    return str(dt)


def _subject(snap: dict) -> str:
    sev = str(snap.get("severity") or "error").upper()
    exc = snap.get("exception_class") or "Error"
    server = snap.get("server_name") or "?"
    count = snap.get("count", 1)

    if snap.get("is_resend"):
        return f"[Hybris Monitor] [RECURRING - {count} occurrences] {sev}: {exc} on {server}"
    return f"[Hybris Monitor] [{sev}] {exc} on {server}"


def _body(snap: dict) -> str:
    is_resend = snap.get("is_resend", False)
    status_label = f"RECURRING ALERT (Still not fixed - {snap['count']} occurrences)" if is_resend else "NEW ALERT"

    lines = [
        "================================================================================",
        f"HYBRIS LOG MONITOR - {status_label}",
        "================================================================================",
        f"Server          : {snap['server_name']} ({snap['server_host']}:{snap['server_port']})",
        f"Log file        : {snap['server_path']}",
        f"Severity        : {str(snap['severity']).upper()}",
        "",
        "--------------------------------------------------------------------------------",
        "ERROR STATEMENT & DETAILS",
        "--------------------------------------------------------------------------------",
        f"Exception Class : {snap['exception_class']}",
        f"Message         : {snap['message']}",
    ]
    if snap.get("top_frame"):
        lines.append(f"Location (Frame): {snap['top_frame']}")

    lines += [
        "",
        "--------------------------------------------------------------------------------",
        "OCCURRENCE METRICS",
        "--------------------------------------------------------------------------------",
        f"Occurrences     : {snap['count']} times",
        f"First Seen      : {snap['first_seen'] or '—'}",
        f"Last Seen       : {snap['last_seen'] or '—'}",
        f"Notification    : {'Recurring reminder (> ' + str(_interval_hours()) + 'h since first alert)' if is_resend else 'First occurrence alert'}",
    ]

    if snap.get("sample"):
        lines += [
            "",
            "--------------------------------------------------------------------------------",
            "LOG SNIPPET / STACK TRACE",
            "--------------------------------------------------------------------------------",
            snap["sample"][:1800],
        ]

    lines.append("================================================================================")
    return "\n".join(lines)


def _html_body(snap: dict) -> str:
    is_resend = snap.get("is_resend", False)
    sev = str(snap.get("severity") or "error").upper()
    badge_bg = "#e01e5a" if sev == "ERROR" else "#ecb22e"
    badge_color = "#ffffff"
    status_text = f"RECURRING ALERT &bull; {snap['count']} OCCURRENCES" if is_resend else "NEW ERROR DETECTED"
    status_bg = "#611f69" if not is_resend else "#b81446"

    sample_html = html.escape(snap.get("sample", "")[:1800]) if snap.get("sample") else ""
    exc_html = html.escape(str(snap.get("exception_class") or "Error"))
    msg_html = html.escape(str(snap.get("message") or "No message provided"))
    frame_html = html.escape(str(snap.get("top_frame") or ""))
    server_name_html = html.escape(str(snap.get("server_name") or "Unknown Server"))
    server_host_html = html.escape(str(snap.get("server_host") or ""))
    server_port_html = html.escape(str(snap.get("server_port") or ""))
    server_path_html = html.escape(str(snap.get("server_path") or ""))

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    margin: 0; padding: 0; background-color: #f4f5f7; color: #1d1c1d; line-height: 1.5;
  }}
  .container {{
    max-width: 680px; margin: 24px auto; background: #ffffff; border-radius: 8px;
    overflow: hidden; border: 1px solid #e1e4e8; box-shadow: 0 2px 8px rgba(0,0,0,0.05);
  }}
  .header {{
    background: {status_bg}; color: #ffffff; padding: 20px 24px;
  }}
  .header-tag {{
    font-size: 11px; font-weight: 800; letter-spacing: 1px; text-transform: uppercase;
    opacity: 0.9; margin-bottom: 6px;
  }}
  .header h1 {{
    margin: 0; font-size: 19px; font-weight: 700; color: #ffffff;
  }}
  .content {{
    padding: 24px;
  }}
  .error-box {{
    background: #fff5f5; border: 1px solid #fed7d7; border-left: 4px solid {badge_bg};
    border-radius: 6px; padding: 16px; margin-bottom: 20px;
  }}
  .error-class {{
    font-size: 16px; font-weight: 700; color: #c53030; margin-bottom: 6px; font-family: SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  }}
  .error-msg {{
    font-size: 14px; color: #2d3748; white-space: pre-wrap; word-break: break-word;
  }}
  .frame-box {{
    font-size: 12px; color: #4a5568; background: #edf2f7; padding: 8px 12px;
    border-radius: 4px; font-family: SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    margin-top: 10px; word-break: break-all;
  }}
  .section-title {{
    font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;
    color: #495057; margin: 18px 0 8px; border-bottom: 1px solid #edf2f7; padding-bottom: 4px;
  }}
  .info-table {{
    width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 13px;
  }}
  .info-table td {{
    padding: 6px 0; vertical-align: top;
  }}
  .info-table td.label {{
    width: 110px; color: #718096; font-weight: 600;
  }}
  .info-table td.value {{
    color: #2d3748; font-weight: 500;
  }}
  .metric-card {{
    background: #f8f9fa; border: 1px solid #e9ecef;
    border-radius: 6px; padding: 12px 14px;
  }}
  .metric-label {{
    font-size: 11px; font-weight: 700; text-transform: uppercase; color: #6c757d; margin-bottom: 4px;
  }}
  .metric-val {{
    font-size: 17px; font-weight: 800; color: #1d1c1d;
  }}
  .code-snippet {{
    background: #1e1e1e; color: #d4d4d4; padding: 14px; border-radius: 6px;
    font-family: SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px;
    line-height: 1.45; overflow-x: auto; white-space: pre-wrap; word-break: break-word;
    max-height: 320px;
  }}
  .badge {{
    display: inline-block; padding: 3px 8px; font-size: 11px; font-weight: 700;
    border-radius: 4px; text-transform: uppercase; background: {badge_bg}; color: {badge_color};
  }}
  .footer {{
    background: #fafbfc; border-top: 1px solid #e1e4e8; padding: 14px 24px;
    font-size: 11.5px; color: #6a737d; text-align: center;
  }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="header-tag">{status_text}</div>
    <h1>{server_name_html} &bull; {exc_html}</h1>
  </div>
  <div class="content">
    <div class="error-box">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
        <span class="error-class">{exc_html}</span>
        <span class="badge">{sev}</span>
      </div>
      <div class="error-msg">{msg_html}</div>
      {f'<div class="frame-box">at {frame_html}</div>' if frame_html else ''}
    </div>

    <table class="info-table" style="width: 100%;">
      <tr>
        <td style="width: 50%; padding-right: 8px;">
          <div class="metric-card">
            <div class="metric-label">Occurrences Till Now</div>
            <div class="metric-val" style="color: {badge_bg};">{snap['count']}</div>
          </div>
        </td>
        <td style="width: 50%; padding-left: 8px;">
          <div class="metric-card">
            <div class="metric-label">Last Seen</div>
            <div class="metric-val" style="font-size: 14px; font-weight: 700; padding-top: 2px;">{snap['last_seen'] or '—'}</div>
          </div>
        </td>
      </tr>
    </table>

    <div class="section-title">Server Details</div>
    <table class="info-table">
      <tr>
        <td class="label">Server Name:</td>
        <td class="value"><b>{server_name_html}</b></td>
      </tr>
      <tr>
        <td class="label">Host & Port:</td>
        <td class="value">{server_host_html}:{server_port_html}</td>
      </tr>
      <tr>
        <td class="label">Log Path:</td>
        <td class="value"><code style="font-size: 12px; background: #f0f1f3; padding: 2px 6px; border-radius: 3px;">{server_path_html}</code></td>
      </tr>
      <tr>
        <td class="label">First Seen:</td>
        <td class="value">{snap['first_seen'] or '—'}</td>
      </tr>
    </table>

    {f'''<div class="section-title">Log Snippet / Trace</div>
    <div class="code-snippet">{sample_html}</div>''' if sample_html else ''}
  </div>
  <div class="footer">
    Hybris Log Monitor &bull; Alert interval cooldown: {_interval_hours():g} hours &bull; Delivered via Brevo SMTP
  </div>
</div>
</body>
</html>
"""


def _send_smtp(subject: str, body_plain: str, body_html: Optional[str] = None, override_to: Optional[str] = None) -> None:
    host = os.environ.get("SMTP_HOST", "").strip()
    port = int(os.environ.get("SMTP_PORT", "587") or 587)
    user = os.environ.get("SMTP_USER", "").strip()
    password = os.environ.get("SMTP_PASSWORD", "").strip()
    mail_from = os.environ.get("MAIL_FROM", "").strip()

    if override_to:
        to_list = [x.strip() for x in override_to.split(",") if x.strip()]
    else:
        to_list = [x.strip() for x in os.environ.get("MAIL_TO", "").split(",") if x.strip()]

    if not host or not mail_from or not to_list:
        raise RuntimeError("SMTP alerts not configured: SMTP_HOST, MAIL_FROM, MAIL_TO")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = mail_from
    msg["To"] = ", ".join(to_list)
    msg.set_content(body_plain)

    if body_html:
        msg.add_alternative(body_html, subtype="html")

    # Brevo accepts SMTP login + master key/password, or key as username with empty password.
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
            log.warning("SMTP auth rejected for user %r; trying fallback auth", uname)
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


def send_test_email(to_email: Optional[str] = None) -> Tuple[bool, str]:
    """Test utility to verify Brevo SMTP configuration with a real email."""
    if not os.environ.get("SMTP_HOST"):
        return False, "SMTP_HOST is not configured"
    if not os.environ.get("MAIL_FROM"):
        return False, "MAIL_FROM is not configured"

    target_to = to_email or os.environ.get("MAIL_TO", "")
    if not target_to.strip():
        return False, "MAIL_TO is not configured"

    test_snap = {
        "server_id": "test_server",
        "server_name": "Production Hybris (Test Node)",
        "server_host": "hybris-app01.prod.internal",
        "server_port": 22,
        "server_path": "/opt/hybris/log/tomcat/console-20260819.log",
        "gid": "test_gid_001",
        "severity": "error",
        "exception_class": "de.hybris.platform.servicelayer.search.exceptions.FlexibleSearchException",
        "message": "Test Alert: Brevo SMTP error notification pipeline is active and working properly.",
        "top_frame": "de.hybris.platform.servicelayer.search.impl.DefaultFlexibleSearchService.search(DefaultFlexibleSearchService.java:142)",
        "count": 1,
        "first_seen": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "last_seen": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "sample": "2026-08-19 18:30:00,123 ERROR [hybris-exec-1] [DefaultFlexibleSearchService] FlexibleSearchException: Test error simulated to verify Brevo notification.\n    at de.hybris.platform.servicelayer.search.impl.DefaultFlexibleSearchService.search(DefaultFlexibleSearchService.java:142)\n    at com.hybris.storefront.controllers.ProductController.get(ProductController.java:88)",
        "is_resend": False,
    }

    try:
        subject = f"[Hybris Monitor Test] SMTP Alert Verification - {datetime.utcnow().strftime('%H:%M:%S')}"
        body_plain = _body(test_snap)
        body_html = _html_body(test_snap)
        _send_smtp(subject, body_plain, body_html, override_to=target_to)
        return True, f"Test email sent successfully to {target_to}"
    except Exception as exc:
        log.exception("send_test_email failed")
        return False, f"SMTP Test Failed: {exc}"


# Module singleton used by pollers.
notifier = Notifier()


def notify(server, group) -> None:
    """Fire-and-forget entry point called from poller._record_entry."""
    notifier.notify(server, group)
