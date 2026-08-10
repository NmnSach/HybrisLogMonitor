# Hybris Log Monitor

Live SFTP-based log monitoring for Hybris server nodes. Register a
server, and the app parses whatever's already in its active log file,
then keeps polling for new lines for as long as the process runs.
Only error/warning entries are ever surfaced — plain info/debug noise
is parsed (needed to find entry boundaries) but discarded. Already
-rotated log files can be browsed and parsed once, in full, with no
polling.

## Setup

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...      # optional, enables "Get AI suggestion"
python app.py
```

Then open **http://127.0.0.1:5000** — it redirects to `/servers`.

### Optional environment variables

| Variable | Purpose | Default |
|---|---|---|
| `ANTHROPIC_API_KEY` | Enables `suggest_fix()` calls | none — suggestion button will error without it |
| `SERVERS_STORE_PATH` | Where registered servers are persisted | `servers.json` in the working directory |
| `SFTP_KEY_PASSPHRASE` | Passphrase for an encrypted private key, if using key auth with a protected key | none |

## Using it

1. **`/servers`** — lists every registered node with a live status dot
   (starting / live / error / stopped) and its distinct error-group
   count. "+ Add server" goes to `/new`.
2. **`/new`** — enter host/port/username, either a password or an SSH
   private key path, and the path to the *actively-written* log file
   (e.g. `wrapper.log` or `console.log` — whichever one your node is
   currently appending to). The connection and file are checked before
   saving. On success you're redirected straight to `/analytics/<id>`.
3. **`/analytics/<id>`** — the live dashboard:
   - Auto-refreshes every 6 seconds.
   - Search box + severity filter + sort (most recent / most frequent).
   - Click a row to expand it; "Get AI suggestion" fires exactly one
     Claude API call for that error group, cached server-side so
     re-opening the row (or another user hitting the same report) never
     re-bills it.
   - "Historical files" section browses other files in the same remote
     directory (e.g. yesterday's rotated log) and parses one, in full,
     on demand — a static snapshot, not live.

## Project layout

```
app.py            Flask routes + JSON API
poller.py         Background per-server tailing threads
sftp_client.py     paramiko wrappers (short-lived connections per call)
models.py         Server model + JSON-file persistence
log_parser.py      Batch + incremental log parsing (see below)
llm_suggest.py     Calls out to Claude for a root-cause/fix suggestion
templates/         servers.html, new_server.html, analytics.html
```

## How live tailing works

Each registered server gets one background thread
(`poller._poll_loop`). On start, it streams the log file's existing
content through `log_parser.IncrementalParser` to seed the error list
("check the logs that exist when the app starts"). Every 15 seconds
after that (`poller.POLL_INTERVAL_SECONDS`), it re-stats the file and,
if it's grown, reads *only the new bytes* (a seek+read, not a
re-download) and feeds them to the same parser.

Only entries with severity `error`/`warning` are ever stored, grouped
by a fingerprint (exception type + root cause + top stack frame, with
IDs/numbers normalized out) so a recurring error's count just increments
in place rather than the in-memory list growing without bound over a
long monitoring session.

**A structural nuance worth knowing:** the parser deliberately does not
finalize the *most recent* entry in the file until a following line
proves it's complete — otherwise a multi-line stack trace mid-write
could get cut short and misclassified. Two consequences, both handled:

- **Rotation**: if the file shrinks between polls (rotated/rolled over),
  whatever was pending gets force-flushed and recorded before switching
  to reading the new file from byte 0.
- **Quiet logs**: if nothing new gets written for ~2 poll cycles, the
  pending entry is force-flushed anyway, so a single error on an
  otherwise quiet node doesn't sit invisible indefinitely.

Historical file views don't have this problem at all — `log_parser.analyze()`
reads the whole (static) file in one pass and always finalizes the
trailing entry, since there's no "more data coming" ambiguity for a file
nothing is appending to.

## Known gaps / things to adjust for your environment

- **Credentials are stored in plaintext** in `servers.json` (or
  wherever `SERVERS_STORE_PATH` points). Fine for a local single-user
  tool; swap for a real secrets store before running this anywhere
  shared or network-reachable.
- **`llm_suggest.py` is a stub.** `app.py`'s `_normalize_group()` shows
  exactly what attributes it calls `suggest_fix(issue_description, group)`
  with (`fingerprint`, `severity`, `exception_class`, `message`,
  `top_frame`, `count`) — swap in your real implementation against that
  shape, or adjust the adapter to match your real signature.
- **Poll interval / group cap** (`poller.POLL_INTERVAL_SECONDS = 15`,
  `MAX_GROUPS_PER_SERVER = 2000`) are reasonable defaults, not tuned to
  any particular log volume — adjust for your nodes' actual write rate.
- **This app is single-process, in-memory state.** Restarting it drops
  all poller state (each server's group counts/suggestions cache) and
  starts fresh, though it does still auto-resume tailing every
  persisted server via `poller.start_all()` on boot.
- **Multi-node (5-node) rollout**: right now each node is added and
  monitored independently via `/new` + `/analytics/<id>`. There's no
  cross-node aggregated view yet — if you want one dashboard showing
  errors across all 5 nodes at once, that's a natural next addition
  (a `/analytics` route with no id, unioning `poller.query_groups()`
  across every registered server).
