CALL_COUNT = {"n": 0}

def suggest_fix(issue_description, group):
    """Stub standing in for the real llm_suggest.py (not provided) so the
    app.py flow can be smoke-tested end to end without a real API key."""
    CALL_COUNT["n"] += 1
    return {
        "root_cause": f"Likely cause of {group.exception_class}: stub reasoning based on '{issue_description}'.",
        "fix": "Stub fix suggestion — replace with real llm_suggest.py output.",
    }
