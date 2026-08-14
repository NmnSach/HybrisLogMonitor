"""
app.py
Live Hybris log monitoring.

Register an SFTP-accessible server and its actively-written log file.
The app parses whatever's already in that file on startup, then keeps
polling for new lines at a fixed interval for as long as the process
runs. Only error/warning entries are ever surfaced — plain info/debug
noise is parsed (needed to find entry boundaries) but discarded.

The /analytics page is the live dashboard: errors on the left, details +
AI analysis on the right, auto-refreshing. For date-rotated logs
(console-YYYYMMDD.log) the live poller automatically jumps to the next
day's file once the day ends.

Legacy (already-rotated) log files are studied separately on
/legacy/<id> — pick a file, parse it once in full (a static snapshot,
no polling), with the same left/right + AI analysis UI.

Run:
    pip install -r requirements.txt
    export GROQ_API_KEY=gsk_...               # enables AI analysis (Groq)
    python app.py
Then open http://127.0.0.1:5000
"""

import os
from datetime import datetime

from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, render_template, request, url_for

load_dotenv()

import log_parser
import poller
import sftp_client
from llm_suggest import suggest_fix
from markupsafe import escape as _esc
from models import Server, ServerStore

app = Flask(__name__)

store = ServerStore()

# Fixed base for live date-rotated logs. A date is appended to build the
# full path, e.g. LOG_BASE + "20260808" + ".log" =
# /opt/hybris/log/tomcat/console-20260808.log
LOG_BASE = "/opt/hybris/log/tomcat/console-"


@app.context_processor
def inject_globals():
    """Make LOG_BASE (and friends) available to every template."""
    return {"LOG_BASE": LOG_BASE}


def _nav(active: str = "", legacy_url: str = "", subline=None) -> dict:
    """Context for the shared Slack-style top navbar (_nav.html)."""
    return {"active": active, "legacy_url": legacy_url, "subline": subline}


def _live_nav(server, active: str = "live", include_status: bool = False, extra: str = "") -> dict:
    """Nav context for server pages, with a subline anchoring the server,
    and (on the live page) the live-status widgets the page JS updates."""
    parts = [
        f"<span><b>{_esc(server.name)}</b></span>",
        f"<span>{_esc(server.username)}@{_esc(server.host)}:{server.port}</span>",
    ]
    if include_status:
        parts += [
            '<span><span id="status-dot" class="dot not-started"></span><span id="status-label">not started</span></span>',
            f'<span>tailing <b id="current-file">{_esc(server.log_path)}</b></span>',
            '<span>last polled <b id="last-polled">—</b></span>',
            '<span><b id="total-seen">0</b> entries</span>',
        ]
    subline = "".join(parts) + extra
    return _nav(active=active, legacy_url=f"/legacy/{server.id}", subline=subline)


# ---------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------

@app.route("/")
def root():
    return redirect(url_for("servers_page"))


@app.route("/servers")
def servers_page():
    rows = []
    for s in store.list():
        state = poller.get_state(s.id)
        rows.append({
            "server": s,
            "status": state.status if state else "not started",
            "last_polled_at": state.last_polled_at if state else None,
            "last_error": state.last_error if state else "",
            "error_group_count": len(state.groups) if state else 0,
            "total_entries_seen": state.total_entries_seen if state else 0,
        })
    total = len(store.list())
    nav = _nav(
        active="servers",
        legacy_url="/legacy",
        subline=f"<span><b>{total}</b> server{'s' if total != 1 else ''} registered</span>",
    )
    return render_template("servers.html", rows=rows, nav=nav)


@app.route("/new", methods=["GET", "POST"])
def new_server():
    if request.method == "GET":
        return render_template("new_server.html", nav=_nav(active="new", legacy_url="/legacy"))

    name = request.form.get("name", "").strip()
    host = request.form.get("host", "").strip()
    port = request.form.get("port", "22").strip()
    username = request.form.get("username", "").strip()
    auth_method = request.form.get("auth_method", "password")
    password = request.form.get("password", "")
    key_path = request.form.get("key_path", "").strip()

    # The live log path is built from the fixed base + a date the user
    # picks, e.g. /opt/hybris/log/tomcat/console- + 20260808 + .log. The
    # form submits log_base + log_date (YYYY-MM-DD); we construct the full
    # path server-side so it's correct even without JS.
    log_base = request.form.get("log_base", "").strip() or LOG_BASE
    log_date = request.form.get("log_date", "").strip()
    if log_date:
        try:
            log_path = f"{log_base}{datetime.strptime(log_date, '%Y-%m-%d').strftime('%Y%m%d')}.log"
        except ValueError:
            log_path = ""
    else:
        log_path = request.form.get("log_path", "").strip()

    if not (name and host and username and log_path):
        return render_template(
            "new_server.html",
            error="Name, host, username, and log path are required.",
            form=request.form,
            nav=_nav(active="new", legacy_url="/legacy"),
        ), 400
    if auth_method == "password" and not password:
        return render_template(
            "new_server.html", error="Password is required for password auth.", form=request.form,
            nav=_nav(active="new", legacy_url="/legacy"),
        ), 400
    if auth_method == "key" and not key_path:
        return render_template(
            "new_server.html", error="Key path is required for key auth.", form=request.form,
            nav=_nav(active="new", legacy_url="/legacy"),
        ), 400

    try:
        port_int = int(port or 22)
    except ValueError:
        return render_template(
            "new_server.html", error="Port must be a number.", form=request.form,
            nav=_nav(active="new", legacy_url="/legacy"),
        ), 400

    candidate = Server(
        id="pending", name=name, host=host, port=port_int, username=username,
        password=password, log_path=log_path, auth_method=auth_method, key_path=key_path,
    )
    ok, message = sftp_client.test_connection(candidate)
    if not ok:
        return render_template(
            "new_server.html",
            error=f"Couldn't connect / find log file: {message}",
            form=request.form,
            nav=_nav(active="new", legacy_url="/legacy"),
        ), 400

    server = store.add(
        name=name, host=host, port=port_int, username=username,
        password=password, log_path=log_path, auth_method=auth_method, key_path=key_path,
    )
    poller.start_poller(server)
    return redirect(url_for("server_added_page", server_id=server.id))


@app.route("/analytics/<server_id>")
def analytics_page(server_id):
    server = store.get(server_id)
    if server is None:
        return "Server not found.", 404
    nav = _live_nav(
        server,
        active="live",
        include_status=True,
        extra=f'<span><a href="/legacy/{server.id}">Legacy files →</a></span>',
    )
    return render_template("analytics.html", server=server, nav=nav)


@app.route("/server_added/<server_id>")
def server_added_page(server_id):
    """Landing page right after a new server is added. Lets the user choose
    between jumping straight into the live monitor, or studying the node's
    previous (date-rotated) log files separately."""
    server = store.get(server_id)
    if server is None:
        return "Server not found.", 404
    nav = _nav(
        active="server_added",
        legacy_url=f"/legacy/{server.id}",
        subline=(
            f"<span>Server <b>{_esc(server.name)}</b></span>"
            f"<span>{_esc(server.username)}@{_esc(server.host)}:{server.port}</span>"
            f"<span>live log <b>{_esc(server.log_path)}</b></span>"
        ),
    )
    return render_template("server_added.html", server=server, nav=nav)


@app.route("/legacy")
def legacy_index():
    """Global entry point for studying previous log files. Lists every
    registered node so you can pick which one to dig into."""
    servers = store.list()
    nav = _nav(
        active="legacy_index",
        legacy_url="/legacy",
        subline=f"<span>Pick a node whose previous log files you want to study.</span>",
    )
    return render_template("legacy_index.html", servers=servers, nav=nav)


@app.route("/legacy/<server_id>")
def legacy_page(server_id):
    """Separate page for studying previously-rotated / dated log files. This
    is deliberately independent from the live analytics page — pick a file,
    parse it once in full (a static snapshot), and drill into the errors
    with the same left/right + AI analysis UI."""
    server = store.get(server_id)
    if server is None:
        return "Server not found.", 404
    log_dir = os.path.dirname(server.log_path) or "."
    files = []
    try:
        files = sftp_client.list_log_dir(server, log_dir)
    except Exception:  # noqa: BLE001 — show an empty picker on the page
        files = []
    current_name = os.path.basename(server.log_path)
    nav = _live_nav(
        server,
        active="legacy",
        extra=f'<span><a href="/analytics/{server.id}">Live monitor →</a></span>',
    )
    return render_template(
        "legacy.html",
        server=server,
        log_dir=log_dir,
        files=[{"name": n, "size": sz, "is_live": n == current_name} for n, sz in files],
        nav=nav,
    )


@app.route("/servers/<server_id>/delete", methods=["POST"])
def delete_server(server_id):
    poller.stop_poller(server_id)
    store.delete(server_id)
    return redirect(url_for("servers_page"))


# ---------------------------------------------------------------------
# JSON API consumed by analytics.html
# ---------------------------------------------------------------------

@app.route("/api/servers/<server_id>/status")
def api_status(server_id):
    server = store.get(server_id)
    state = poller.get_state(server_id)
    if state is None:
        return jsonify({"status": "not started"})
    return jsonify({
        "status": state.status,
        "last_error": state.last_error,
        "last_polled_at": state.last_polled_at.isoformat() if state.last_polled_at else None,
        "total_entries_seen": state.total_entries_seen,
        "group_count": len(state.groups),
        "current_path": state.current_path or (server.log_path if server else ""),
    })


@app.route("/api/servers/<server_id>/errors")
def api_errors(server_id):
    q = request.args.get("q", "")
    severity = request.args.get("severity", "all")
    sort = request.args.get("sort", "recent")
    groups = poller.query_groups(server_id, q, severity, sort)
    return jsonify({"rows": [_group_row(g) for g in groups]})


@app.route("/api/servers/<server_id>/date", methods=["POST"])
def api_set_date(server_id):
    """Re-point the live monitor at a specific date's dated log file
    (LOG_BASE + YYYYMMDD + .log). Powers the date picker on the live page
    and makes the automatic next-day roll-over easy to exercise."""
    server = store.get(server_id)
    if server is None:
        return jsonify({"error": "Server not found."}), 404
    state = poller.get_state(server_id)
    if state is None:
        return jsonify({"error": "Server is still starting up. Try again shortly."}), 503

    date_str = request.args.get("date", "")
    try:
        when = datetime.strptime(date_str, "%Y%m%d")
    except ValueError:
        return jsonify({"error": "Invalid date — use YYYYMMDD."}), 400

    try:
        new_path = poller.retarget_date(server, state, when)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": str(exc)}), 502

    if new_path is None:
        return jsonify({
            "error": "This server's log path isn't date-rotated "
                     "(<base>YYYYMMDD.log)."
        }), 400
    return jsonify({"ok": True, "date": date_str, "path": new_path})


def _relevance(severity: str, count: int, last_seen=None) -> dict:
    """A simple 0-100 heuristic for how 'relevant' an error group is to an
    investigator, combining severity, raw frequency, and (for live data)
    how recently it last fired. Returns {'score': int, 'label': str}."""
    now = datetime.utcnow()
    if isinstance(last_seen, str):
        try:
            last_seen = datetime.fromisoformat(last_seen)
        except ValueError:
            last_seen = None

    score = {"error": 40, "warning": 20}.get(severity, 0)
    if count >= 100:
        score += 40
    elif count >= 20:
        score += 30
    elif count >= 5:
        score += 20
    elif count >= 2:
        score += 10
    if last_seen is not None:
        age_min = (now - last_seen).total_seconds() / 60.0
        if age_min < 10:
            score += 20
        elif age_min < 60:
            score += 15
        elif age_min < 360:
            score += 8
    score = max(0, min(score, 100))
    label = "High" if score >= 70 else ("Medium" if score >= 40 else "Low")
    return {"score": score, "label": label}


def _group_row(g) -> dict:
    last_seen = g.last_seen if isinstance(g.last_seen, datetime) else None
    return {
        "gid": g.gid,
        "severity": g.severity,
        "exception_class": g.exception_class,
        "message": g.message,
        "count": g.count,
        "first_seen": g.first_seen.isoformat() if g.first_seen else None,
        "last_seen": last_seen.isoformat() if last_seen else None,
        "top_frame": g.top_frame,
        "sample_raw_text": getattr(g, "sample_raw_text", None),
        "relevance": _relevance(g.severity, g.count, last_seen),
    }


@app.route("/api/servers/<server_id>/suggest/<gid>")
def api_suggest(server_id, gid):
    state = poller.get_state(server_id)
    if state is None:
        return jsonify({"error": "Server is still starting up. Try again shortly."}), 503

    refresh = request.args.get("refresh") == "1"
    issue_description = request.args.get("issue_description", "")

    with state.lock:
        if not refresh and gid in state.suggestions:
            return jsonify({"gid": gid, "cached": True, **_suggestion_payload(state.suggestions[gid])})

        group = state.groups.get(gid) or state.historical_groups.get(gid)
        if group is None:
            return jsonify({"error": "Unknown error group (it may have scrolled out of an old view)."}), 404
        normalized = _normalize_group(group)

    try:
        suggestion = suggest_fix(issue_description, normalized)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": f"Suggestion failed: {exc}"}), 502

    with state.lock:
        state.suggestions[gid] = suggestion

    return jsonify({"gid": gid, "cached": False, **_suggestion_payload(suggestion)})


def _normalize_group(g):
    """suggest_fix() may be written against either LiveErrorGroup or the
    batch ErrorGroup shape (they differ slightly — e.g. top_frame is a
    direct field on one and nested under sample_entry on the other).
    Normalize both into one consistent, duck-typed shape before calling
    it, so llm_suggest.py only has to handle one interface."""
    from types import SimpleNamespace

    top_frame = getattr(g, "top_frame", None)
    if top_frame is None and hasattr(g, "sample_entry"):
        top_frame = g.sample_entry.top_frame

    raw_text = getattr(g, "sample_raw_text", None)
    if not raw_text and hasattr(g, "sample_entry"):
        raw_text = getattr(g.sample_entry, "raw_text", None)

    return SimpleNamespace(
        fingerprint=g.fingerprint,
        severity=g.severity,
        exception_class=g.exception_class,
        message=g.message,
        top_frame=top_frame,
        count=g.count,
        sample_raw_text=raw_text,
    )


def _suggestion_payload(suggestion) -> dict:
    if isinstance(suggestion, dict):
        return suggestion
    return {"suggestion": str(suggestion)}


@app.route("/api/servers/<server_id>/files")
def api_files(server_id):
    server = store.get(server_id)
    if server is None:
        return jsonify({"error": "Server not found."}), 404
    log_dir = os.path.dirname(server.log_path) or "."
    try:
        files = sftp_client.list_log_dir(server, log_dir)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": str(exc)}), 502
    current_name = os.path.basename(server.log_path)
    return jsonify({
        "dir": log_dir,
        "files": [{"name": n, "size": sz, "is_live": n == current_name} for n, sz in files],
    })


@app.route("/api/servers/<server_id>/history")
def api_history(server_id):
    """One-off, full, rigorous parse of a specific (typically already
    rotated) file. No polling — a static snapshot, refreshed only when
    the user explicitly asks for it again."""
    server = store.get(server_id)
    if server is None:
        return jsonify({"error": "Server not found."}), 404
    filename = request.args.get("file", "")
    if not filename:
        return jsonify({"error": "Missing 'file' parameter."}), 400
    if "/" in filename or filename in (".", ".."):
        return jsonify({"error": "Invalid filename."}), 400

    log_dir = os.path.dirname(server.log_path) or "."
    remote_path = f"{log_dir.rstrip('/')}/{filename}"

    try:
        lines_iter = _line_iter_from_chunks(sftp_client.iter_full_text_chunks(server, remote_path))
        result = log_parser.analyze(lines_iter)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": str(exc)}), 502

    # Cache these groups server-side (keyed by gid) so "Get AI suggestion"
    # on a historical row has something to look up, same as live rows.
    state = poller.get_state(server_id)
    if state is not None:
        with state.lock:
            for g in result.groups:
                state.historical_groups[poller._gid_for(g.fingerprint)] = g

    return jsonify({
        "file": filename,
        "total_entries": result.total_entries,
        "error_count": result.error_count,
        "warning_count": result.warning_count,
        "rows": [
            {
                "gid": poller._gid_for(g.fingerprint),
                "severity": g.severity,
                "exception_class": g.exception_class,
                "message": g.message,
                "count": g.count,
                "first_seen": g.first_seen.isoformat() if g.first_seen else None,
                "last_seen": g.last_seen.isoformat() if g.last_seen else None,
                "top_frame": g.sample_entry.top_frame,
                "sample_raw_text": g.sample_entry.raw_text,
                "relevance": _relevance(g.severity, g.count, g.last_seen),
            }
            for g in result.groups
        ],
    })


def _line_iter_from_chunks(chunks):
    """Adapts a stream of text chunks (arbitrary boundaries) into a
    stream of complete lines, for feeding into log_parser.analyze()."""
    leftover = ""
    for chunk in chunks:
        data = leftover + chunk
        lines = data.split("\n")
        leftover = lines.pop()
        for line in lines:
            yield line.rstrip("\r")
    if leftover:
        yield leftover.rstrip("\r")


if __name__ == "__main__":
    poller.start_all(store)  # resume tailing every previously-registered server
    app.run(debug=False, port=5000)
