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
import urllib.error
import urllib.request

GROQ_API_URL = os.environ.get(
    "GROQ_API_URL", "https://api.groq.com/openai/v1/chat/completions"
)
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")

CALL_COUNT = {"n": 0}


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
    api_key = os.environ.get("GROQ_API_KEY")
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
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Groq API error {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not reach Groq: {exc.reason}") from exc

    try:
        content = body["choices"][0]["message"]["content"]
        result = json.loads(content)
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:  # noqa: BLE001
        raise RuntimeError(f"Unexpected Groq response: {str(body)[:400]}") from exc

    return {
        "root_cause": (result.get("root_cause") or "").strip(),
        "fix": (result.get("fix") or "").strip(),
    }
