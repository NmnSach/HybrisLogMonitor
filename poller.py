"""
poller.py
Background live-tailing for registered servers.

For each Server:
  1. start_poller() does an initial full parse of whatever's already in
     the log file ("check the logs that exist when the application
     starts running") to seed the error/warning list. This is streamed
     in chunks (see sftp_client.iter_full_text_chunks), so even a large
     backlog doesn't get held in memory as one string.
  2. It then loops forever at POLL_INTERVAL_SECONDS: read only the bytes
     appended since the last poll (a seek+read, not a re-download), feed
     them through the same IncrementalParser, and fold any new
     error/warning entries into a per-server, per-fingerprint aggregate
     (LiveErrorGroup). A recurring error's count/last_seen just updates
     in place — O(1) memory per distinct error, however many times it
     recurs over a long monitoring session — rather than the in-memory
     list growing without bound.

Only entries with severity error/warning are ever stored. Plain
info/debug entries are still parsed (needed to find entry boundaries and
to catch severity escalation inside a stack trace) but never retained.

Historical (already-rotated) files are handled separately, in app.py,
via a one-off log_parser.analyze() call — no polling, since a file that's
no longer being written to will never have anything new to pick up.
"""

import hashlib
import os
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Dict, Optional
from zoneinfo import ZoneInfo

if TYPE_CHECKING:
    from models import Server

import log_parser
import notifier
import sftp_client

POLL_INTERVAL_SECONDS = 15
MAX_GROUPS_PER_SERVER = 2000  # safety cap for pathologically noisy logs

# The day boundary of the dated log files is NOT the app machine's local
# midnight (and not UTC) — Hybris nodes typically rotate their dated logs
# at midnight in the node's timezone (e.g. CDT/CST). E.g. with logs on
# America/Chicago time, console-20260814.log stays live until 10:30 AM IST
# on Aug 15, then console-20260815.log appears. So "today" (which file is
# currently live) must be computed in this timezone. Override with the
# LOG_TIMEZONE env var if your nodes rotate on another zone.
LOG_TIMEZONE = os.environ.get("LOG_TIMEZONE", "America/Chicago")

# Matches date-rotated log files following the console-YYYYMMDD.log
# convention (e.g. console-20260810.log). Used so the live monitor can
# automatically jump to the next day's file once the current day is over.
_DATED_FILE_RE = re.compile(r"^(?P<prefix>.*?)(?P<date>\d{8})(?P<suffix>\.log)$")


def _dated_match(server) -> Optional[re.Match]:
    """Return the _DATED_FILE_RE match for `server.log_path`, or None when
    the log isn't date-rotated (or the date portion isn't a real date)."""
    base = os.path.basename((server.log_path or "").replace("\\", "/"))
    m = _DATED_FILE_RE.match(base)
    if not m:
        return None
    try:
        datetime.strptime(m.group("date"), "%Y%m%d")
    except ValueError:
        return None
    return m


def dated_file_base(server) -> Optional[str]:
    """Return the fixed base path of a date-rotated log, i.e. everything
    before the date — e.g. '/opt/hybris/log/tomcat/console-' for
    console-20260812.log. Returns None for any non-date-rotated file
    (plain console.log) so callers know the log never rolls forward.

    Remote SFTP paths are always POSIX (forward slashes), regardless of the
    OS the app runs on, so this is built with explicit '/' — never
    os.path.join(), which would insert a backslash on Windows."""
    m = _dated_match(server)
    if m is None:
        return None
    remote = (server.log_path or "").replace("\\", "/")
    directory, _, _filename = remote.rpartition("/")
    prefix = m.group("prefix")
    if directory:
        return directory.rstrip("/") + "/" + prefix
    return prefix


def dated_file_path(server, when: datetime) -> Optional[str]:
    """The full path for a date-rotated log on the given date `when` —
    base + YYYYMMDD + .log (e.g. console-20260811.log for Aug 11 2026).
    Returns None for any non-date-rotated file."""
    base_prefix = dated_file_base(server)
    if base_prefix is None:
        return None
    return f"{base_prefix}{when.strftime('%Y%m%d')}.log"


def now_in_log_tz() -> datetime:
    """Current wall-clock time (naive) in LOG_TIMEZONE — the zone the dated
    log files are named after. This is what decides which day's file is
    'today'. Falls back to UTC if the configured zone is invalid."""
    try:
        return datetime.now(ZoneInfo(LOG_TIMEZONE)).replace(tzinfo=None)
    except Exception:  # noqa: BLE001 — bad zone name etc.
        return datetime.utcnow()


def _file_date(path: str) -> Optional[datetime]:
    """The date embedded in a dated file path (console-20260812.log -> Aug 12)."""
    normalized = str(path or "").replace("\\", "/")
    m = _DATED_FILE_RE.match(os.path.basename(normalized))
    if m is None:
        return None
    try:
        return datetime.strptime(m.group("date"), "%Y%m%d")
    except ValueError:
        return None


@dataclass
class LiveErrorGroup:
    fingerprint: str
    gid: str
    severity: str
    exception_class: str
    message: str
    top_frame: Optional[str]
    sample_raw_text: str
    count: int
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]


@dataclass
class ServerPollState:
    server_id: str
    offset: int = 0
    current_path: str = ""  # the remote file currently being tailed
    parser: Optional["log_parser.IncrementalParser"] = None
    groups: Dict[str, LiveErrorGroup] = field(default_factory=dict)  # gid -> group
    # Populated on demand by /api/servers/<id>/history in app.py, so a
    # historical row's "Get AI suggestion" button has something to look
    # up server-side, the same way live rows do.
    historical_groups: Dict[str, "log_parser.ErrorGroup"] = field(default_factory=dict)
    suggestions: Dict[str, dict] = field(default_factory=dict)  # gid -> suggestion
    lock: threading.RLock = field(default_factory=threading.RLock)
    thread: Optional[threading.Thread] = None
    stop_event: threading.Event = field(default_factory=threading.Event)
    status: str = "starting"  # starting | live | error | stopped
    last_error: str = ""
    last_polled_at: Optional[datetime] = None
    total_entries_seen: int = 0
    stall_polls: int = 0  # consecutive polls with no new bytes written
    server: Optional["Server"] = None  # for email notifications
    is_live: bool = False  # True once the initial backlog parse has finished


_STATES: Dict[str, ServerPollState] = {}
_STATES_LOCK = threading.Lock()


def _gid_for(fingerprint: str) -> str:
    return hashlib.sha1(fingerprint.encode("utf-8")).hexdigest()[:12]


def _record_entry(state: ServerPollState, entry) -> None:
    if not entry.is_issue:
        return
    fp = entry.fingerprint()
    gid = _gid_for(fp)
    with state.lock:
        existing = state.groups.get(gid)
        if existing is None:
            if len(state.groups) >= MAX_GROUPS_PER_SERVER:
                # Would mean thousands of *distinct* recurring error
                # signatures — vanishingly unlikely, but bail out
                # gracefully instead of growing forever.
                return
            state.groups[gid] = LiveErrorGroup(
                fingerprint=fp,
                gid=gid,
                severity=entry.severity,
                exception_class=entry.root_cause_class or entry.exception_class or "UnknownError",
                message=entry.message,
                top_frame=entry.top_frame,
                sample_raw_text=entry.raw_text,
                count=1,
                first_seen=entry.timestamp,
                last_seen=entry.timestamp,
            )
        else:
            existing.count += 1
            if entry.timestamp:
                if existing.first_seen is None or entry.timestamp < existing.first_seen:
                    existing.first_seen = entry.timestamp
                if existing.last_seen is None or entry.timestamp > existing.last_seen:
                    existing.last_seen = entry.timestamp

    # Email alert (fire-and-forget). Only once the monitor is "live" so the
    # initial backlog parse doesn't spam the inbox on startup/restart.
    if state.is_live and state.server is not None:
        group = state.groups.get(gid)
        if group is not None:
            notifier.notify(state.server, group)


def _initial_parse(server, state: ServerPollState, path: Optional[str] = None) -> None:
    """Parse whatever's already in the file when we start watching it. The
    remote path defaults to the file the state currently tracks, so this
    can also seed a freshly rotated-to dated file."""
    path = path or state.current_path or server.log_path
    state.current_path = path
    parser = None
    for chunk in sftp_client.iter_full_text_chunks(server, path):
        if parser is None:
            pattern = log_parser.sniff_pattern_from_text(chunk)
            parser = log_parser.IncrementalParser(pattern)
        for entry in parser.feed(chunk):
            state.total_entries_seen += 1
            _record_entry(state, entry)

    state.parser = parser  # stays None if the file was empty
    state.offset = sftp_client.stat_size(server, path)


def _retarget(server, state: ServerPollState, new_path: str) -> None:
    """Point the live poller at `new_path` (a new day's dated file or a
    user-chosen date). Flushes whatever entry was still open in the old
    file, then re-seeds the new file from scratch."""
    with state.lock:
        if state.parser is not None:
            pending = state.parser.flush()
            if pending is not None:
                state.total_entries_seen += 1
                _record_entry(state, pending)
        state.parser = None
        state.offset = 0
        state.current_path = new_path
    _initial_parse(server, state, path=new_path)


def retarget_date(server, state: ServerPollState, when: datetime) -> Optional[str]:
    """Re-point the live poller at `base + YYYYMMDD + .log` for `when`.
    Returns the new path, or None if this server's log isn't date-rotated.
    Called by the app's date-picker endpoint so an operator can jump the
    live monitor to a specific date. Raises FileNotFoundError if the
    target date's file doesn't exist on the server yet."""
    new_path = dated_file_path(server, when)
    if new_path is None:
        return None
    if not sftp_client.file_exists(server, new_path):
        raise FileNotFoundError(
            f"No log file exists on the server for {when:%Y%m%d}: {new_path}"
        )
    _retarget(server, state, new_path)
    return new_path


def _maybe_switch_dated(server, state: ServerPollState) -> None:
    """For date-rotated logs (console-YYYYMMDD.log), once the day in the
    file we're tailing has ended, automatically jump to the *next* day's
    file and start studying it. This is what lets the live monitor roll
    from console-20260814.log to console-20260815.log.

    'Day ended' is evaluated in LOG_TIMEZONE (the node's zone — e.g. the
    log rotates at midnight CDT/CST, which may be 10:30 AM IST), NOT in
    UTC or the app machine's local zone. The poller only advances forward
    (never backwards to a file that's 'today' but older than the one being
    manually tailed), and only once the target file exists remotely."""
    today = now_in_log_tz()
    today_path = dated_file_path(server, today)
    if today_path is None or today_path == state.current_path:
        return

    # Only advance when the file we're tailing is from BEFORE today in the
    # log's timezone. This prevents a manual "jump to a future date" from
    # being immediately yanked back to today.
    current_date = _file_date(state.current_path)
    if current_date is not None and current_date.date() >= today.date():
        return

    # Only switch once the target file actually exists on the server.
    if not sftp_client.file_exists(server, today_path):
        return
    _retarget(server, state, today_path)


STALL_POLLS_BEFORE_FLUSH = 2  # ~2 poll intervals of silence before we
                               # assume nothing more is coming for the
                               # still-open entry and surface it anyway


def _poll_once(server, state: ServerPollState) -> None:
    path = state.current_path or server.log_path
    if state.parser is None:
        # File was empty when we started (or still is) — check whether
        # there's content yet, and if so, detect the format now.
        size = sftp_client.stat_size(server, path)
        if size == 0:
            state.last_polled_at = datetime.utcnow()
            return
        data, new_size = sftp_client.read_range(server, path, 0)
        text = data.decode("utf-8", errors="replace")
        pattern = log_parser.sniff_pattern_from_text(text)
        state.parser = log_parser.IncrementalParser(pattern)
        for entry in state.parser.feed(text):
            state.total_entries_seen += 1
            _record_entry(state, entry)
        state.offset = new_size
        state.last_polled_at = datetime.utcnow()
        return

    new_size = sftp_client.stat_size(server, path)

    if new_size < state.offset:
        # File was rotated/truncated (rollover to a new file, or a
        # log4j2-style size-based roll). Keep everything already shown to
        # the user, but first make sure whatever entry was still "open"
        # in the old file at the moment of rotation doesn't get silently
        # lost — flush() closes it out, and (unlike an ordinary poll) we
        # know for certain no more data is coming for it, so it's safe
        # to record right away.
        leftover_entry = state.parser.flush()
        if leftover_entry is not None:
            state.total_entries_seen += 1
            _record_entry(state, leftover_entry)
        state.offset = 0
        state.stall_polls = 0
        data, new_size = sftp_client.read_range(server, path, 0)
    elif new_size == state.offset:
        # Nothing new written since last poll. If there's an entry still
        # sitting "open" (waiting for a following line to prove it's
        # complete) and the file has gone quiet for a couple of poll
        # cycles, surface it anyway rather than leaving a real error
        # invisible indefinitely just because nothing else got logged
        # after it. flush() is safe here specifically because we've
        # confirmed no new bytes have shown up across multiple polls.
        state.stall_polls += 1
        if state.stall_polls >= STALL_POLLS_BEFORE_FLUSH:
            leftover_entry = state.parser.flush()
            if leftover_entry is not None:
                state.total_entries_seen += 1
                _record_entry(state, leftover_entry)
            state.stall_polls = 0
        state.last_polled_at = datetime.utcnow()
        return
    else:
        state.stall_polls = 0
        data, new_size = sftp_client.read_range(server, path, state.offset)

    text = data.decode("utf-8", errors="replace")
    for entry in state.parser.feed(text):
        state.total_entries_seen += 1
        _record_entry(state, entry)

    state.offset = new_size
    state.last_polled_at = datetime.utcnow()


def _poll_loop(server, state: ServerPollState) -> None:
    try:
        state.status = "starting"
        _initial_parse(server, state)
        state.status = "live"
    except Exception as exc:  # noqa: BLE001
        state.status = "error"
        state.last_error = f"Initial parse failed: {exc}"

    state.is_live = True  # from here on, newly-recorded entries may alert

    while not state.stop_event.is_set():
        if state.stop_event.wait(POLL_INTERVAL_SECONDS):
            break
        try:
            _maybe_switch_dated(server, state)
            _poll_once(server, state)
            if state.status == "error":
                state.status = "live"
                state.last_error = ""
        except Exception as exc:  # noqa: BLE001
            state.status = "error"
            state.last_error = str(exc)

    state.status = "stopped"


def start_poller(server) -> ServerPollState:
    with _STATES_LOCK:
        existing = _STATES.get(server.id)
        if existing is not None and existing.thread and existing.thread.is_alive():
            return existing
        state = ServerPollState(server_id=server.id, current_path=server.log_path, server=server)
        _STATES[server.id] = state

    thread = threading.Thread(target=_poll_loop, args=(server, state), daemon=True)
    state.thread = thread
    thread.start()
    return state


def stop_poller(server_id: str) -> None:
    with _STATES_LOCK:
        state = _STATES.get(server_id)
    if state is not None:
        state.stop_event.set()


def get_state(server_id: str) -> Optional[ServerPollState]:
    return _STATES.get(server_id)


def start_all(server_store) -> None:
    for server in server_store.list():
        start_poller(server)


def query_groups(server_id: str, text_query: str = "", severity: str = "all", sort: str = "recent"):
    state = get_state(server_id)
    if state is None:
        return []
    q = text_query.strip().lower()
    with state.lock:
        rows = list(state.groups.values())

    if severity in ("error", "warning"):
        rows = [g for g in rows if g.severity == severity]

    if q:
        rows = [
            g for g in rows
            if q in g.message.lower()
            or q in (g.exception_class or "").lower()
            or q in (g.top_frame or "").lower()
        ]

    if sort == "count":
        rows.sort(key=lambda g: g.count, reverse=True)
    else:  # "recent" (default) — most useful for live monitoring
        rows.sort(key=lambda g: g.last_seen or datetime.min, reverse=True)

    return rows
