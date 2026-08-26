"""
llm_suggest.py
Calls Groq's OpenAI-compatible Chat Completions API to produce a
root-cause + remediation analysis for a single error group.

Configuration (environment variables):
    GROQ_API_KEY   required — enables AI analysis (Groq console key)
    GROQ_MODEL     optional — default "llama-3.3-70b-versatile"
    GROQ_API_URL   optional — default https://api.groq.com/openai/v1/chat/completions

Returns a dict {"root_cause": str, "fix": str}. Raises RuntimeError on
missing key / network / API errors so app.py can surface a friendly
message in the UI.
"""

import json
import os
import ssl
import urllib.error
import urllib.request

GROQ_API_URL = os.environ.get(
    "GROQ_API_URL", "https://api.groq.com/openai/v1/chat/completions"
)
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")

CALL_COUNT = {"n": 0}


def _candidate_cafiles():
    """Yield CA bundle paths worth trying, best candidates first: certifi's
    curated bundle (a complete, current PEM trust store that doesn't depend
    on the OS), then an operator-set SSL_CERT_FILE for custom/internal CAs."""
    try:
        import certifi

        yield certifi.where()
    except Exception:  # noqa: BLE001 — certifi optional
        pass
    custom = os.environ.get("SSL_CERT_FILE", "").strip()
    if custom:
        yield custom


def _ssl_context():
    """Build a best-effort HTTPS context for the GroQ call.

    macOS python.org / unsigned Homebrew Python builds often can't find a
    usable CA store and hit 'SSL: CERTIFICATE_VERIFY_FAILED ... unable to
    get local issuer certificate'. To cover every machine the app runs on
    we trust BOTH the OS store AND every candidate CA bundle (loading an
    extra file appends to, rather than replaces, the existing store), so
    either one is enough.

    If the network sits behind an SSL-tapping (MITM) filter whose private
    root CA is in none of those stores (corporate proxies such as Zscaler /
    Bluecoat), verification can't succeed no matter what. As an explicit
    escape hatch, set GROQ_SSL_NO_VERIFY=1 to skip certificate verification
    for this one Groq call (see README). Only do that if you understand and
    accept the risk.

    Never raises: on any construction failure the caller simply gets a
    context whose store is empty, and the request fails with the clear
    guidance message in suggest_fix() instead of a 500.
    """
    if os.environ.get("GROQ_SSL_NO_VERIFY", "").strip().lower() in ("1", "true", "yes", "on"):
        return ssl._create_unverified_context()

    try:
        # OS trust store first (also lets a sysadmin drop a private CA into
        # the system keychain / SSL_CERT_FILE and have it honoured here).
        ctx = ssl.create_default_context()
    except Exception:  # noqa: BLE001 — broken OS store; start clean
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    for cafile in _candidate_cafiles():
        try:
            ctx.load_verify_locations(cafile=cafile)
        except Exception:  # noqa: BLE001 — try the next candidate
            continue
    return ctx


def _group_description(group) -> str:
    """Render the normalized group object into a compact text summary the
    model can reason over. `group` is the duck-typed shape from app.py's
    _normalize_group() (plus optional sample_raw_text)."""
    lines = []
    exc = getattr(group, "exception_class", None)
    sev = getattr(group, "severity", None)
    count = getattr(group, "count", None)
    msg = getattr(group, "message", None)
    tf = getattr(group, "top_frame", None)
    fp = getattr(group, "fingerprint", None)

    parts = []
    if exc:
        parts.append(f"Exception: {exc}")
    if sev:
        parts.append(f"Severity: {sev}")
    if count is not None:
        parts.append(f"Occurrences in window: {count}")
    lines.append(" | ".join(parts) if parts else "Unknown error type.")
    if msg:
        lines.append(f"Message:\n{msg}")
    if tf:
        lines.append(f"Top stack frame:\n{tf}")

    raw = getattr(group, "sample_raw_text", None) or getattr(group, "raw_text", None)
    if raw:
        lines.append(f"Log snippet (first {min(len(raw), 3000)} chars):\n{raw[:3000]}")
    if fp:
        lines.append(f"Fingerprint: {fp}")
    return "\n\n".join(lines)


def _build_prompt(issue_description: str, group) -> str:
    prompt = (
        "You are an expert SAP Commerce (Hybris) / Apache Tomcat log analyst.\n"
        "Analyze the error grouped below and give a precise, actionable diagnosis.\n\n"
        f"{_group_description(group)}"
    )
    if issue_description:
        prompt += f"\n\nAdditional operator context: {issue_description}"
    prompt += (
        "\n\nRespond with a JSON object containing EXACTLY these two keys:\n"
        '- "root_cause": a concise explanation of the most likely root cause.\n'
        '- "fix": concrete, step-by-step remediation.\n'
    )
    return prompt


def suggest_fix(issue_description, group):
    api_key = os.environ.get("GROQ_API_KEY", "").strip()
    # A pasted Groq key occasionally ends up as "gsk A5..." with a space
    # where the underscore should be (valid keys are always gsk_...).
    # Normalize that one-character copy/paste typo so auth still works.
    if api_key.startswith("gsk ") and not api_key.startswith("gsk_"):
        api_key = "gsk_" + api_key[4:]
    if not api_key:
        raise RuntimeError(
            "GROQ_API_KEY is not set. Export it (e.g. `export GROQ_API_KEY=...`) "
            "to enable AI analysis."
        )

    CALL_COUNT["n"] += 1
    payload = {
        "model": GROQ_MODEL,
        "temperature": 0.2,
        "max_tokens": 700,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are an expert SAP Commerce (Hybris) and Apache Tomcat log "
                    "analyst. You respond only with valid JSON."
                ),
            },
            {"role": "user", "content": _build_prompt(issue_description, group)},
        ],
        "response_format": {"type": "json_object"},
    }

    req = urllib.request.Request(
        GROQ_API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            # Cloudflare (in front of Groq) blocks requests whose
            # User-Agent looks like a bare urllib client ("1010").
            "User-Agent": "hybris-log-monitor/1.0 (log analysis)",
        },
        method="POST",
    )

    raw = b""
    status = None
    try:
        with urllib.request.urlopen(req, timeout=90, context=_ssl_context()) as resp:
            status = getattr(resp, "status", 200)
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        # Non-2xx (401 bad key, 429 rate limit, 5xx...). Read the body so
        # we can surface the API's own error detail below.
        status = exc.code
        raw = exc.read()
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        if isinstance(reason, ssl.SSLCertVerificationError) or "certificate verify failed" in str(reason).lower():
            raise RuntimeError(
                "SSL certificate verification failed when connecting to Groq — "
                "the machine couldn't find/trust a CA bundle for api.groq.com. "
                "Fix options: (1) run `pip install certifi` (already in "
                "requirements.txt) so the app can use certifi's CA bundle; "
                "(2) if a corporate HTTPS proxy is intercepting the connection "
                "with its own private CA, install that root CA, or set "
                "`GROQ_SSL_NO_VERIFY=1` to skip verification for Groq calls "
                "(insecure — only as a last resort)."
            ) from exc
        raise RuntimeError(f"Could not reach Groq: {reason}") from exc

    try:
        body = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        preview = raw[:400].decode("utf-8", errors="replace")
        raise RuntimeError(
            "Groq returned an empty or non-JSON response (HTTP "
            f"{status}). Body preview: {preview!r}. If that looks like an "
            "HTML page (Cloudflare challenge / corporate proxy block page), "
            "the request is being intercepted — check GROQ_API_URL, any "
            "corporate proxy, and the SSL setup."
        ) from exc

    if status is not None and status >= 400:
        raise RuntimeError(f"Groq API error {status}: {str(body)[:400]}")

    try:
        content = body["choices"][0]["message"]["content"]
        result = json.loads(content)
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:  # noqa: BLE001
        raise RuntimeError(f"Unexpected Groq response: {str(body)[:400]}") from exc

    return {
        "root_cause": (result.get("root_cause") or "").strip(),
        "fix": (result.get("fix") or "").strip(),
    }
