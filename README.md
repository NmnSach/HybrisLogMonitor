# Hybris Log Monitor

Live SFTP-based log monitoring for Hybris server nodes. Register a
server, and the app parses whatever's already in its active log file,
then keeps polling for new lines for as long as the process runs.
Only error/warning entries are ever surfaced — plain info/debug noise
is parsed (needed to find entry boundaries) but discarded.

The **live monitor** and **legacy file study** are two separate views:
- `/analytics/<id>` is the live dashboard and only ever watches the
  actively-written log file. For date-rotated logs
  (`console-YYYYMMDD.log`) it **automatically jumps to the next day's
  file** when the current day ends.
- `/legacy/<id>` is where you browse and parse earlier, already-rotated
  logs (e.g. yesterday's file) once, in full, as a static snapshot.

Every page shares a Slack-styled top navbar (**⬢ Hybris Log Monitor**)
with **Servers**, **Add server**, and **Legacy files** links — the
`/legacy` entry point lists every node so you can pick which one to dig
into.

## Setup

```bash
pip install -r requirements.txt
export GROQ_API_KEY=gsk_...            # enables the "Analyze with AI" feature (Groq)
python app.py
```

Then open **http://127.0.0.1:5000** — it redirects to `/servers`.

### Optional environment variables

| Variable | Purpose | Default |
|---|---|---|
| `GROQ_API_KEY` | Enables AI analysis via the Groq API | none — the Analyze button will error without it |
| `GROQ_MODEL` | Groq model used for analysis | `llama-3.3-70b-versatile` |
| `GROQ_API_URL` | Groq (OpenAI-compatible) endpoint override | `https://api.groq.com/openai/v1/chat/completions` |
| `LOG_TIMEZONE` | Timezone the dated log files rotate in (the auto-advance day boundary) | `America/Chicago` (CDT/CST) |
| `SERVERS_STORE_PATH` | Where registered servers are persisted | `servers.json` in the working directory |
| `SFTP_KEY_PASSPHRASE` | Passphrase for an encrypted private key, if using key auth with a protected key | none |
| `NOTIFY_ENABLED` | Master toggle for live error email alerts (`1` or `0`) | `0` |
| `SMTP_HOST` | Brevo SMTP host | `smtp-relay.brevo.com` |
| `SMTP_PORT` | Brevo SMTP port (`587` with STARTTLS or `465` with SSL) | `587` |
| `SMTP_TLS` | Enable STARTTLS on port 587 (`1` or `0`) | `1` |
| `SMTP_SSL` | Enable implicit SSL on port 465 (`1` or `0`) | `0` |
| `SMTP_USER` | Brevo SMTP login or API key username | none |
| `SMTP_PASSWORD` | Brevo SMTP password / key (`xsmtpsib-...`) | none |
| `MAIL_FROM` | Verified Brevo sender email address | none |
| `MAIL_TO` | Comma-separated recipient email address(es) | none |
| `NOTIFY_INTERVAL_HOURS` | Cooldown interval before resending recurring errors with updated counts | `3` (hours) |

### Email Notifications (Brevo SMTP)

Live error alerting delivers alerts via Brevo SMTP (`smtp-relay.brevo.com`):
- **First occurrence**: Sends an alert email immediately (formatted in both plain text and rich HTML).
- **Anti-spam suppression**: Repeated occurrences within `NOTIFY_INTERVAL_HOURS` (default 3 hours) are silenced.
- **Cooldown resend**: If the error keeps occurring after 2–3 hours, a recurring alert email is sent with the updated occurrence count and latest last-seen timestamp.
- **Test Email**: Verify your email pipeline from the `/servers` dashboard with the **Send Test Email** button or `POST /api/notify/test`.

## Using it

1. **`/servers`** — lists every registered node with a live status dot
   (starting / live / error / stopped) and its distinct error-group
   count. "+ Add server" goes to `/new`.
2. **`/new`** — enter host/port/username and either a password or an SSH
   private key, plus a **date picker** for the log you want to tail. The
   live log path is built from a fixed base (`/opt/hybris/log/tomcat/console-`)
   plus the chosen date in `YYYYMMDD` — e.g. picking 2026-08-08 gives
   `/opt/hybris/log/tomcat/console-20260808.log`. The connection and
   file are checked before saving. On success you land on a
   **"server added"** page that offers **Open live monitor** or
   **Check previous log files**.
3. **`/analytics/<id>`** — the live dashboard (Slack-styled two-pane UI):
   - Errors are listed on the **left** with their severity, frequency
     (count) and a relevance label (High / Medium / Low, combining
     severity + frequency + how recently the error fired).
   - Click an error to see its full details, stack-trace snippet and an
     **"Analyze with AI"** button on the **right**; the analysis (via
     Groq) renders *under* those details on the right pane.
   - A **date picker** in the toolbar lets you jump the live monitor to
     any date's dated file.
   - **Auto-advances** to the next day's file (e.g.
     `console-20260812.log` → `console-20260813.log`) automatically once
     the day is over, as long as the next file exists on the server.
4. **`/legacy` + `/legacy/<id>`** — separate legacy-file study page: the
   `/legacy` index lists every registered node, and `/legacy/<id>` lets
   you browse a node's log directory, pick an earlier file, and parse it
   in full as a static snapshot with the same left/right + AI analysis
   UI. No polling.
5. **Drag & drop on `/legacy`** — no server needed: drop a local log file
   onto the `/legacy` page (or click to browse) and it is parsed once in
   full as a static snapshot, with the same error/warning list, details,
   and AI analysis as node-backed files. Posted via `POST /api/upload`;
   groups are cached in memory (bounded) and AI analysis reuses the same
   Groq pipeline via `GET /api/upload/suggest/<token>/<gid>`.

## Project layout

```
app.py            Flask routes + JSON API
poller.py         Background per-server tailing threads (incl. dated-file auto-advance)
sftp_client.py     paramiko wrappers (short-lived connections per call)
models.py         Server model + JSON-file persistence
log_parser.py      Batch + incremental log parsing (see below)
llm_suggest.py     Calls Groq for a root-cause/fix analysis
templates/         _nav.html (shared Slack navbar), servers.html, new_server.html,
                   server_added.html, legacy_index.html, analytics.html, legacy.html
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

**Date-rotated files.** If the monitored log path follows the
`console-YYYYMMDD.log` naming convention, the live monitor checks each
poll cycle whether the current day is over and the next day's dated file
has appeared on the server; when both are true it automatically closes
out the old file and starts tailing the new one (e.g. `console-20260814.log`
→ `console-20260815.log`).

The day boundary is evaluated in the **log's own timezone**
(`LOG_TIMEZONE`, default `America/Chicago` — CDT/CST). Hybris nodes
rotate at *their* midnight, so with Central-time logs `console-20260814.log`
stays live until 10:30 AM IST on Aug 15, then `console-20260815.log`
appears and the monitor rolls over. The advance is strictly forward
(it never yanks a manually-selected file back) and only happens once the
next file actually exists remotely. Non-dated files (plain `console.log`)
keep the existing behaviour unchanged.

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
- **AI analysis requires a Groq API key.** `llm_suggest.py` calls Groq's
  OpenAI-compatible endpoint; set `GROQ_API_KEY` (and optionally
  `GROQ_MODEL`) or the "Analyze with AI" button will show an error.
  `app.py`'s `_normalize_group()` passes it a duck-typed group
  (`fingerprint`, `severity`, `exception_class`, `message`, `top_frame`,
  `count`, `sample_raw_text`).
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
