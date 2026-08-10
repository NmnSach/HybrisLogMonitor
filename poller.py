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
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Optional

import log_parser
import sftp_client

POLL_INTERVAL_SECONDS = 15
MAX_GROUPS_PER_SERVER = 2000  # safety cap for pathologically noisy logs


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


def _initial_parse(server, state: ServerPollState) -> None:
    """Parse whatever's already in the file when we start watching it."""
    parser = None
    for chunk in sftp_client.iter_full_text_chunks(server, server.log_path):
        if parser is None:
            pattern = log_parser.sniff_pattern_from_text(chunk)
            parser = log_parser.IncrementalParser(pattern)
        for entry in parser.feed(chunk):
            state.total_entries_seen += 1
            _record_entry(state, entry)

    state.parser = parser  # stays None if the file was empty
    state.offset = sftp_client.stat_size(server, server.log_path)


STALL_POLLS_BEFORE_FLUSH = 2  # ~2 poll intervals of silence before we
                               # assume nothing more is coming for the
                               # still-open entry and surface it anyway


def _poll_once(server, state: ServerPollState) -> None:
    if state.parser is None:
        # File was empty when we started (or still is) — check whether
        # there's content yet, and if so, detect the format now.
        size = sftp_client.stat_size(server, server.log_path)
        if size == 0:
            state.last_polled_at = datetime.utcnow()
            return
        data, new_size = sftp_client.read_range(server, server.log_path, 0)
        text = data.decode("utf-8", errors="replace")
        pattern = log_parser.sniff_pattern_from_text(text)
        state.parser = log_parser.IncrementalParser(pattern)
        for entry in state.parser.feed(text):
            state.total_entries_seen += 1
            _record_entry(state, entry)
        state.offset = new_size
        state.last_polled_at = datetime.utcnow()
        return

    new_size = sftp_client.stat_size(server, server.log_path)

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
        data, new_size = sftp_client.read_range(server, server.log_path, 0)
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
        data, new_size = sftp_client.read_range(server, server.log_path, state.offset)

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

    while not state.stop_event.is_set():
        if state.stop_event.wait(POLL_INTERVAL_SECONDS):
            break
        try:
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
        state = ServerPollState(server_id=server.id)
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
