"""
app.py
Live Hybris log monitoring.

Register an SFTP-accessible server and its actively-written log file.
The app parses whatever's already in that file on startup, then keeps
polling for new lines at a fixed interval for as long as the process
runs. Only error/warning entries are ever surfaced — plain info/debug
noise is parsed (needed to find entry boundaries) but discarded. The
/analytics page lists them in a searchable/filterable, auto-refreshing
table; clicking a row triggers a single on-demand Claude API call for a
root-cause suggestion, cached so repeat views don't re-bill.

Historical (already-rotated) log files in the same directory can be
browsed and parsed once, in full — no polling, since a file nothing is
appending to will never have anything new to pick up.

Run:
    pip install -r requirements.txt
    export ANTHROPIC_API_KEY=sk-ant-...      # optional, enables fix suggestions
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
from models import Server, ServerStore

app = Flask(__name__)

store = ServerStore()


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
    return render_template("servers.html", rows=rows)


@app.route("/new", methods=["GET", "POST"])
def new_server():
    if request.method == "GET":
        return render_template("new_server.html")

    name = request.form.get("name", "").strip()
    host = request.form.get("host", "").strip()
    port = request.form.get("port", "22").strip()
    username = request.form.get("username", "").strip()
    auth_method = request.form.get("auth_method", "password")
    password = request.form.get("password", "")
    key_path = request.form.get("key_path", "").strip()
    log_path = request.form.get("log_path", "").strip()

    if not (name and host and username and log_path):
        return render_template(
            "new_server.html",
            error="Name, host, username, and log path are required.",
            form=request.form,
        ), 400
    if auth_method == "password" and not password:
        return render_template(
            "new_server.html", error="Password is required for password auth.", form=request.form
        ), 400
    if auth_method == "key" and not key_path:
        return render_template(
            "new_server.html", error="Key path is required for key auth.", form=request.form
        ), 400

    try:
        port_int = int(port or 22)
    except ValueError:
        return render_template("new_server.html", error="Port must be a number.", form=request.form), 400

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
        ), 400

    server = store.add(
        name=name, host=host, port=port_int, username=username,
        password=password, log_path=log_path, auth_method=auth_method, key_path=key_path,
    )
    poller.start_poller(server)
    return redirect(url_for("analytics_page", server_id=server.id))


@app.route("/analytics/<server_id>")
def analytics_page(server_id):
    server = store.get(server_id)
    if server is None:
        return "Server not found.", 404
    return render_template("analytics.html", server=server)


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
    state = poller.get_state(server_id)
    if state is None:
        return jsonify({"status": "not started"})
    return jsonify({
        "status": state.status,
        "last_error": state.last_error,
        "last_polled_at": state.last_polled_at.isoformat() if state.last_polled_at else None,
        "total_entries_seen": state.total_entries_seen,
        "group_count": len(state.groups),
    })


@app.route("/api/servers/<server_id>/errors")
def api_errors(server_id):
    q = request.args.get("q", "")
    severity = request.args.get("severity", "all")
    sort = request.args.get("sort", "recent")
    groups = poller.query_groups(server_id, q, severity, sort)
    return jsonify({"rows": [_group_row(g) for g in groups]})


def _group_row(g) -> dict:
    return {
        "gid": g.gid,
        "severity": g.severity,
        "exception_class": g.exception_class,
        "message": g.message,
        "count": g.count,
        "first_seen": g.first_seen.isoformat() if g.first_seen else None,
        "last_seen": g.last_seen.isoformat() if g.last_seen else None,
        "top_frame": g.top_frame,
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
    it, so llm_suggest.py only has to handle one interface.

    NOTE: I don't have the real llm_suggest.py, so this attribute set
    (fingerprint/severity/exception_class/message/top_frame/count) is my
    best guess at what suggest_fix() expects. Adjust here (or there) if
    the real signature differs."""
    from types import SimpleNamespace

    top_frame = getattr(g, "top_frame", None)
    if top_frame is None and hasattr(g, "sample_entry"):
        top_frame = g.sample_entry.top_frame

    return SimpleNamespace(
        fingerprint=g.fingerprint,
        severity=g.severity,
        exception_class=g.exception_class,
        message=g.message,
        top_frame=top_frame,
        count=g.count,
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
