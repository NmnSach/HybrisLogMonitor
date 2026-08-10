"""
log_parser.py
Parses Hybris/Tomcat-style wrapper.log files (and standard log4j2-formatted
hybris.log files), isolates errors within a time window, and clusters
similar errors together.

Supported line format (Tanuki JVM wrapper, e.g. wrapper.log):
    INFO   | jvm 1    | main    | 2026/07/20 00:00:10.287 | <content>

Also handles the more common log4j2 format used in hybris.log:
    2026-07-20 14:32:10,123 ERROR [http-nio-9002-exec-3] SomeClass : message

Add more patterns to LINE_PATTERNS if your environment uses a different
log4j2 pattern layout.

---------------------------------------------------------------------------
PERFORMANCE NOTES (read this if you're wiring this into app.py)
---------------------------------------------------------------------------
This module is built around a single streaming pipeline so that, for the
common case of "pull a large file, keep a small time window", you never
hold more than one entry's worth of lines in memory at a time:

    lines (file object / list)
        -> iter_parse()         parses + applies the time window inline
        -> cluster_errors()     consumes the parser generator directly

The old two-step API (parse_log() -> filter_by_window() -> cluster_errors())
is still here and still works, but it forces the whole file into memory as
a list of LogEntry objects before you can filter or cluster. Prefer
`analyze()` or `iter_parse()` + `cluster_errors()` for new/updated code
(see docstrings below for details and an app.py integration example).
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from itertools import chain
from typing import Iterable, Iterator, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Line-level patterns. Each has a compiled regex with named groups:
#   ts (timestamp string), content (rest of the line)
# and a matching strptime format for ts.
# ---------------------------------------------------------------------------
LINE_PATTERNS = [
    {
        "name": "wrapper_log",
        "regex": re.compile(
            r"^(?P<level>\w+)\s*\|\s*jvm\s*\d+\s*\|\s*[\w\-]*\s*\|\s*"
            r"(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s*\|\s?(?P<content>.*)$"
        ),
        "ts_formats": ["%Y/%m/%d %H:%M:%S.%f"],
    },
    {
        "name": "log4j2_standard",
        "regex": re.compile(
            r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[,.]\d{3})\s+"
            r"(?P<level>[A-Z]+)\s+(?P<content>.*)$"
        ),
        "ts_formats": ["%Y-%m-%d %H:%M:%S,%f", "%Y-%m-%d %H:%M:%S.%f"],
    },
]

# A continuation line belongs to the previous entry rather than starting a
# new one: stack frames, "Caused by:", and "... N more" truncation markers.
CONTINUATION_RE = re.compile(r"^\s*(at\s|Caused by:|\.\.\.\s*\d+\s+more)")

LEVEL_ALIASES = {
    "TRACE": "trace",
    "DEBUG": "debug",
    "INFO": "info",
    "WARN": "warning",
    "WARNING": "warning",
    "ERROR": "error",
    "FATAL": "error",
}

SEVERITY_PRIORITY = {
    "trace": 0,
    "debug": 1,
    "info": 2,
    "warning": 3,
    "error": 4,
}
MAX_SEVERITY = "error"  # highest key in SEVERITY_PRIORITY; used to short-circuit

CONTENT_LEVEL_RE = re.compile(r"^\s*\[?(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL)\]?\b[:\s-]*")

ERROR_CONTENT_RE = re.compile(
    r"(?:^|\s)([\w$]+\.)*[\w$]*(Exception|Error)\b|"
    r"\b(ERROR|FATAL|SEVERE|FAILED|FAILURE)\b|"
    r"\bCaused by:"
)
WARNING_CONTENT_RE = re.compile(
    r"\bWARN(?:ING)?\b|"
    r"\b(DEPRECATED|TIMEOUT|RETRY(?:ING)?|SLOW|UNAVAILABLE|BLOCKED)\b"
)

# Extracts a fully-qualified exception/error class name, e.g.
# "de.hybris.platform.jalo.JaloBusinessException"
EXCEPTION_CLASS_RE = re.compile(r"(([\w$]+\.)+[\w$]*(?:Exception|Error))\b")

# Extracts the class+method from a stack frame line, ignoring the line number,
# e.g. "at de.hybris.platform.jalo.media.Media.getDataFromStream(Media.java:773)"
#   -> "de.hybris.platform.jalo.media.Media.getDataFromStream"
STACK_FRAME_RE = re.compile(r"at\s+([\w$.<>]+)\(")

# Normalizes dynamic tokens (numeric IDs, hex, long digit runs) in messages
# so that otherwise-identical errors with different IDs cluster together.
DYNAMIC_TOKEN_RE = re.compile(r"\b(0x[0-9a-fA-F]+|\d+)\b")


def normalize_level(level: Optional[str]) -> Optional[str]:
    if not level:
        return None
    return LEVEL_ALIASES.get(level.strip().upper())


def parse_timestamp(ts_str: str, ts_formats: List[str]) -> Optional[datetime]:
    for fmt in ts_formats:
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    return None


def infer_content_level(content: str) -> Optional[str]:
    match = CONTENT_LEVEL_RE.match(content)
    if match:
        return normalize_level(match.group(1))
    if ERROR_CONTENT_RE.search(content):
        return "error"
    if WARNING_CONTENT_RE.search(content):
        return "warning"
    return None


def pick_severity(*levels: Optional[str]) -> str:
    candidates = [level for level in levels if level]
    if not candidates:
        return "info"
    return max(candidates, key=lambda level: SEVERITY_PRIORITY.get(level, -1))


@dataclass(slots=True)
class LogEntry:
    timestamp: Optional[datetime]
    severity: str = "info"
    declared_level: Optional[str] = None
    raw_lines: List[str] = field(default_factory=list)
    content_lines: List[str] = field(default_factory=list)

    # Computed lazily, on first access, by _compute_signature() — exactly
    # like the original's separate @property scans, EXCEPT all three
    # (exception_class / root_cause_class / top_frame) are extracted in a
    # single pass over content_lines instead of three independent ones,
    # and the result is cached. This matters for entries with long stack
    # traces. Crucially it stays lazy: plain info/debug entries (the vast
    # majority of a log) never pay for this at all, same as the original,
    # since nothing here runs unless one of the properties below is
    # actually read (cluster_errors() only reads them for is_issue entries).
    _sig_computed: bool = False
    _exception_class: Optional[str] = None
    _root_cause_class: Optional[str] = None
    _top_frame: Optional[str] = None
    _message: Optional[str] = None
    _fingerprint: Optional[str] = None

    @property
    def first_content(self) -> str:
        return self.content_lines[0] if self.content_lines else ""

    @property
    def is_error(self) -> bool:
        return self.severity == "error"

    @property
    def is_warning(self) -> bool:
        return self.severity == "warning"

    @property
    def is_issue(self) -> bool:
        return self.severity in {"error", "warning"}

    @property
    def raw_text(self) -> str:
        return "\n".join(self.raw_lines)

    def _compute_signature(self) -> None:
        if self._sig_computed:
            return

        exception_class: Optional[str] = None
        root_cause_class: Optional[str] = None
        top_frame: Optional[str] = None

        for line in self.content_lines:
            need_class = exception_class is None
            is_caused_by = False
            # Cheap check first; only pay for the regex when it can matter.
            if line and (need_class or line.lstrip().startswith("Caused by:")):
                is_caused_by = line.lstrip().startswith("Caused by:")
                m = EXCEPTION_CLASS_RE.search(line)
                if m:
                    if need_class:
                        exception_class = m.group(1)
                    if is_caused_by:
                        root_cause_class = m.group(1)
            if top_frame is None:
                fm = STACK_FRAME_RE.search(line)
                if fm:
                    top_frame = fm.group(1)

        self._exception_class = exception_class
        self._root_cause_class = root_cause_class
        self._top_frame = top_frame

        content = CONTENT_LEVEL_RE.sub("", self.first_content, count=1).strip()
        m = EXCEPTION_CLASS_RE.search(content)
        if m:
            self._message = content[m.end():].lstrip(": ").strip()
        else:
            self._message = content

        self._sig_computed = True

    @property
    def exception_class(self) -> Optional[str]:
        self._compute_signature()
        return self._exception_class

    @property
    def root_cause_class(self) -> Optional[str]:
        self._compute_signature()
        return self._root_cause_class

    @property
    def top_frame(self) -> Optional[str]:
        self._compute_signature()
        return self._top_frame

    @property
    def message(self) -> str:
        self._compute_signature()
        return self._message

    def fingerprint(self) -> str:
        """Groups occurrences of 'the same' error, ignoring IDs/values.
        Cached after first call."""
        if self._fingerprint is None:
            self._compute_signature()
            cause = self._root_cause_class or self._exception_class or (
                "Warning" if self.is_warning else "UnknownError"
            )
            frame = self._top_frame or ""
            norm_msg = DYNAMIC_TOKEN_RE.sub("#", self._message)[:120]
            self._fingerprint = f"{self.severity}|{cause}|{frame}|{norm_msg}"
        return self._fingerprint


def detect_pattern(sample_lines: List[str]):
    """Pick the line pattern that matches the most lines in a sample."""
    best, best_score = None, 0
    for pat in LINE_PATTERNS:
        score = sum(1 for ln in sample_lines if pat["regex"].match(ln))
        if score > best_score:
            best, best_score = pat, score
    return best


def _sniff_and_chain(lines: Iterable[str]):
    """Peek up to 200 lines to detect the format, then hand back an
    iterator over the *whole* stream (sample + remainder) without ever
    materializing more than the sample in memory. Works identically
    whether `lines` is a plain list (already-loaded text) or a one-shot
    generator (e.g. reading directly off an SFTP file handle)."""
    it = iter(lines)
    sample: List[str] = []
    for line in it:
        sample.append(line)
        if len(sample) >= 200:
            break
    pattern = detect_pattern(sample)
    if pattern is None:
        raise ValueError(
            "Could not detect a known log format. Add a new entry to "
            "LINE_PATTERNS in log_parser.py for this log's layout."
        )
    return pattern, chain(sample, it)


def _window_bounds_as_strings(
    start: datetime, end: datetime, ts_format: str
) -> Tuple[str, str]:
    """Format start/end as strings comparable (lexicographically) to the raw
    `ts` capture group text, at the same precision the log actually writes
    (milliseconds), so we can reject most out-of-window lines with a plain
    string comparison instead of paying for strptime on every single line.
    Safe because all supported ts_formats are fixed-width, zero-padded,
    left-to-right significant (year first), so string order == chrono order.
    """
    lo = start.strftime(ts_format)
    hi = end.strftime(ts_format)
    if "%f" in ts_format:
        # strftime always expands %f to 6 digits; the log only ever writes
        # 3 (milliseconds), so trim to match widths before comparing.
        lo, hi = lo[:-3], hi[:-3]
    return lo, hi


def iter_parse(
    lines: Iterable[str],
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
) -> Iterator[LogEntry]:
    """Stream-parse log lines into LogEntry objects.

    This is the fast path: parsing and time-window filtering happen in the
    same pass. Entries outside [start, end] are dropped as early as
    possible — before the (relatively expensive) strptime call whenever a
    cheap string comparison on the raw timestamp text can already tell
    they're out of range — and are never retained in memory.

    `lines` can be a list (e.g. text.splitlines()) or any iterator of
    lines, including one that reads directly off a file/SFTP handle, so
    the caller never has to hold the whole file as one big string.

    If start/end are omitted, every entry is parsed and yielded (this is
    what parse_log() below uses).
    """
    pattern, full_lines = _sniff_and_chain(lines)
    regex = pattern["regex"]
    ts_formats = pattern["ts_formats"]
    groupdict_get = None  # perf: avoid attribute lookup in the hot loop

    windowed = start is not None and end is not None
    bounds = _window_bounds_as_strings(start, end, ts_formats[0]) if windowed else None

    current: Optional[LogEntry] = None
    current_in_window = True

    for line in full_lines:
        m = regex.match(line)
        if not m:
            # No timestamp at all on this line (e.g. raw stdout, or a
            # log4j2 stack frame, which never repeats the prefix) — it's a
            # continuation of whatever entry is currently open.
            if current is not None:
                current.raw_lines.append(line)
                current.content_lines.append(line)
            continue

        content = m.group("content")
        is_continuation = current is not None and CONTINUATION_RE.match(content)

        if is_continuation:
            # IMPORTANT: even when `current` is a discarded/out-of-window
            # entry, it must stay the tracked "current" object so that
            # wrapper.log continuation lines (which carry their own
            # timestamp and would otherwise pass the outer regex and look
            # like a brand-new entry) still get recognized as continuation
            # lines instead of spawning spurious fragment entries.
            if current_in_window:
                current.raw_lines.append(line)
                current.content_lines.append(content)
                # Once an entry has already hit "error" it can't go
                # higher, so skip the two regex scans (declared + inferred
                # level) that would otherwise run on every stack-trace
                # line for nothing.
                if current.severity != MAX_SEVERITY:
                    declared_level = normalize_level(m.groupdict().get("level"))
                    inferred_level = infer_content_level(content)
                    line_sev = pick_severity(declared_level, inferred_level)
                    current.severity = pick_severity(current.severity, line_sev)
            # else: continuation of an already-dropped entry — nothing to
            # store, and no severity work needed since it'll never be
            # yielded. Skipping the append also saves memory on large
            # out-of-window stack traces.
            continue

        # A new top-level entry starts here — close out the previous one.
        if current is not None and current_in_window:
            yield current

        ts_str = m.group("ts")

        if windowed:
            lo, hi = bounds
            # Cheap reject: skip strptime entirely for lines that can't
            # possibly be in range. Still set `current` to a placeholder
            # (not None!) so subsequent continuation lines are correctly
            # absorbed into it and discarded, rather than being
            # misinterpreted as new top-level entries.
            if not (lo <= ts_str <= hi):
                current = LogEntry(timestamp=None, severity="info")
                current_in_window = False
                continue

        declared_level = normalize_level(m.groupdict().get("level"))
        inferred_level = infer_content_level(content)
        severity = pick_severity(declared_level, inferred_level)
        ts = parse_timestamp(ts_str, ts_formats)

        if windowed:
            current_in_window = ts is not None and start <= ts <= end
        else:
            current_in_window = True

        if ts is None and current is not None:
            # Preserve original behavior: an unparseable timestamp on a
            # would-be new entry inherits the previous entry's timestamp
            # rather than being dropped outright (only relevant when not
            # windowed, or when the previous entry's ts happens to still
            # be in range — matches the non-streaming implementation).
            ts = current.timestamp

        current = LogEntry(
            timestamp=ts,
            severity=severity,
            declared_level=declared_level,
            raw_lines=[line],
            content_lines=[content],
        )

    if current is not None and current_in_window:
        yield current


def parse_log(text: str) -> List[LogEntry]:
    """Parse raw log text into a list of LogEntry objects (one per
    top-level statement; multi-line stack traces are kept together).

    Kept for backward compatibility / small logs and interactive use.
    For large files, prefer iter_parse()/analyze() so you're not forced
    to materialize every entry in the file before filtering."""
    return list(iter_parse(text.splitlines()))


def parse_stream(
    fileobj,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
) -> Iterator[LogEntry]:
    """Like iter_parse(), but reads directly from a file-like object
    (e.g. `sftp.open(remote_path)`) one line at a time, so the raw file
    contents are never held in memory as a single string.

    Example (replacing the old "read whole file, then parse" flow in
    app.py's fetch_via_sftp + parse_log):

        with sftp.open(remote_path) as f:
            f.set_pipelined()
            entries_in_window = log_parser.parse_stream(f, start, end)
            groups = log_parser.cluster_errors(entries_in_window)
    """

    def _decoded_lines():
        for raw in fileobj:
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", errors="replace")
            yield raw.rstrip("\r\n")

    return iter_parse(_decoded_lines(), start=start, end=end)


def filter_by_window(entries: List[LogEntry], start: datetime, end: datetime) -> List[LogEntry]:
    """Kept for backward compatibility with code that already has a fully
    materialized entries list. Prefer passing start/end directly to
    iter_parse()/parse_stream()/analyze() in new code — filtering during
    parsing avoids ever allocating LogEntry objects for out-of-window
    lines in the first place."""
    return [e for e in entries if e.timestamp and start <= e.timestamp <= end]


@dataclass(slots=True)
class ErrorGroup:
    fingerprint: str
    severity: str
    exception_class: str
    message: str
    sample_entry: LogEntry
    occurrences: List[LogEntry] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.occurrences)

    @property
    def first_seen(self) -> datetime:
        return min(e.timestamp for e in self.occurrences)

    @property
    def last_seen(self) -> datetime:
        return max(e.timestamp for e in self.occurrences)


def cluster_errors(entries: Iterable[LogEntry]) -> List[ErrorGroup]:
    """Group warning/error entries that represent the same underlying issue.

    `entries` can be a list OR a generator (e.g. iter_parse(...) directly).
    Passing a generator lets non-issue (info/debug) entries get garbage
    collected immediately after the is_issue check instead of sitting in
    memory as part of a fully materialized list."""
    groups = {}
    for e in entries:
        if not e.is_issue:
            continue
        fp = e.fingerprint()
        if fp not in groups:
            groups[fp] = ErrorGroup(
                fingerprint=fp,
                severity=e.severity,
                exception_class=e.root_cause_class or e.exception_class or "UnknownError",
                message=e.message,
                sample_entry=e,
            )
        groups[fp].occurrences.append(e)

    # Most frequent first
    return sorted(groups.values(), key=lambda g: g.count, reverse=True)


@dataclass(slots=True)
class AnalysisResult:
    total_entries: int
    error_count: int
    warning_count: int
    groups: List[ErrorGroup]


def analyze(
    lines: Iterable[str],
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
) -> AnalysisResult:
    """One-pass fetch -> parse -> window-filter -> cluster pipeline. This
    is the recommended entry point for app.py: it never materializes a
    full list of entries, only the (much smaller) set of distinct error
    groups and their occurrences.

        result = log_parser.analyze(sftp.open(path), start, end)
        # or, for an already-uploaded file:
        result = log_parser.analyze(text.splitlines(), start, end)
    """
    total = 0
    error_count = 0
    warning_count = 0
    groups: dict = {}

    for e in iter_parse(lines, start=start, end=end):
        total += 1
        if not e.is_issue:
            continue
        if e.is_error:
            error_count += 1
        else:
            warning_count += 1
        fp = e.fingerprint()
        if fp not in groups:
            groups[fp] = ErrorGroup(
                fingerprint=fp,
                severity=e.severity,
                exception_class=e.root_cause_class or e.exception_class or "UnknownError",
                message=e.message,
                sample_entry=e,
            )
        groups[fp].occurrences.append(e)

    sorted_groups = sorted(groups.values(), key=lambda g: g.count, reverse=True)
    return AnalysisResult(
        total_entries=total,
        error_count=error_count,
        warning_count=warning_count,
        groups=sorted_groups,
    )


# ---------------------------------------------------------------------------
# Live-tailing support
#
# Everything above this point assumes the whole input (a file, or a known
# byte range of one) is available up front. A live-tailed file is
# different: new bytes show up in arbitrary chunks (whatever a poll cycle
# happened to read), and a chunk boundary can land in the middle of a
# multi-line stack trace. IncrementalParser below is a small stateful
# wrapper that makes that safe: feed() can be called repeatedly with
# whatever text just came in, and it only ever yields entries it's sure
# are complete (the *next* top-level line has already started). The
# entry currently being written to the log is deliberately held back
# until that confirmation arrives, rather than being finalized on a
# timer — a poll-interval's worth of latency on the very newest entry is
# a small price for never misclassifying a stack trace that's still
# mid-flight.
# ---------------------------------------------------------------------------


def _step_line(
    line: str, pattern, current: Optional[LogEntry]
) -> Tuple[Optional[LogEntry], Optional[LogEntry]]:
    """Process one line against `pattern`, given the currently-open entry
    (or None if nothing is open yet). Returns (finalized, new_current):
    `finalized` is the entry this line just closed out (because it starts
    a new top-level entry), or None if this line was a continuation of
    `current` (or the very first line of the stream)."""
    regex = pattern["regex"]
    m = regex.match(line)
    if not m:
        if current is not None:
            current.raw_lines.append(line)
            current.content_lines.append(line)
        return None, current

    content = m.group("content")
    is_continuation = current is not None and CONTINUATION_RE.match(content)

    if is_continuation:
        current.raw_lines.append(line)
        current.content_lines.append(content)
        if current.severity != MAX_SEVERITY:
            declared_level = normalize_level(m.groupdict().get("level"))
            inferred_level = infer_content_level(content)
            line_sev = pick_severity(declared_level, inferred_level)
            current.severity = pick_severity(current.severity, line_sev)
        return None, current

    finalized = current
    ts_str = m.group("ts")
    declared_level = normalize_level(m.groupdict().get("level"))
    inferred_level = infer_content_level(content)
    severity = pick_severity(declared_level, inferred_level)
    ts = parse_timestamp(ts_str, pattern["ts_formats"])
    if ts is None and finalized is not None:
        ts = finalized.timestamp

    new_current = LogEntry(
        timestamp=ts,
        severity=severity,
        declared_level=declared_level,
        raw_lines=[line],
        content_lines=[content],
    )
    return finalized, new_current


def sniff_pattern_from_text(text: str):
    """Detect the log line format from a text sample (e.g. the first
    chunk read off a live-tailed file). Used to prime an IncrementalParser
    once so later poll cycles don't need to re-detect the format."""
    sample_lines = text.splitlines()[:200]
    pattern = detect_pattern(sample_lines)
    if pattern is None:
        raise ValueError(
            "Could not detect a known log format from the sample. Add a "
            "new entry to LINE_PATTERNS in log_parser.py for this log's layout."
        )
    return pattern


class IncrementalParser:
    """Stateful parser for a live-tailed file. Construct once (after
    sniffing the format with sniff_pattern_from_text), then call feed()
    once per poll cycle with whatever new text was read.

        parser = IncrementalParser(sniff_pattern_from_text(first_chunk))
        for entry in parser.feed(first_chunk):
            ...
        # ... next poll cycle, some time later ...
        for entry in parser.feed(next_chunk):
            ...

    Call flush() only when you're certain no more data is coming for the
    currently-open entry (the remote file was rotated/truncated, or the
    poller is shutting down for good) — not on every ordinary poll cycle,
    or you'll risk cutting a stack trace short.
    """

    def __init__(self, pattern):
        self.pattern = pattern
        self._current: Optional[LogEntry] = None
        self._leftover = ""

    def feed(self, text_chunk: str) -> List[LogEntry]:
        data = self._leftover + text_chunk
        lines = data.split("\n")
        self._leftover = lines.pop()  # possibly a partial line; held for next feed()
        finalized = []
        for line in lines:
            entry, self._current = _step_line(line.rstrip("\r"), self.pattern, self._current)
            if entry is not None:
                finalized.append(entry)
        return finalized

    def flush(self) -> Optional[LogEntry]:
        """Force-close whatever entry is currently open (see class
        docstring for when this is/isn't appropriate)."""
        entry = self._current
        self._current = None
        self._leftover = ""
        return entry


if __name__ == "__main__":
    # Quick self-test against sample.log
    import sys

    path = sys.argv[1] if len(sys.argv) > 1 else "sample_logs/wrapper_sample.log"
    with open(path, "r", errors="replace") as f:
        text = f.read()

    entries = parse_log(text)
    print(f"Parsed {len(entries)} entries")

    errors = [e for e in entries if e.is_error]
    print(f"Found {len(errors)} error entries")

    groups = cluster_errors(entries)
    print(f"Clustered into {len(groups)} distinct error group(s)\n")
    for g in groups:
        print(f"[{g.count}x] {g.exception_class}")
        print(f"    message: {g.message[:100]}")
        print(f"    first: {g.first_seen}  last: {g.last_seen}")
        print(f"    top frame: {g.sample_entry.top_frame}")
        print()
