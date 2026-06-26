"""Built-in policy presets for common tool ecosystems."""

from __future__ import annotations

from copy import deepcopy
from typing import Any


_PRESETS: dict[str, dict[str, Any]] = {
    "openai_tools_baseline": {
        "enabled": True,
        "enforcement_mode": "enforce",
        "unknown_tool_action": "deny",
        "confirmation_header": "X-Guardian-Tool-Confirm",
        "confirmation_value": "true",
        "allowed_tools": [
            "file_search",
            "web_search",
            "code_interpreter",
            "function_router",
        ],
        "denied_tools": [
            "shell_exec",
            "powershell_exec",
        ],
        "sensitive_tools": [
            "code_interpreter",
        ],
    },
    "langchain_tools_baseline": {
        "enabled": True,
        "enforcement_mode": "enforce",
        "unknown_tool_action": "deny",
        "confirmation_header": "X-Guardian-Tool-Confirm",
        "confirmation_value": "true",
        "allowed_tools": [
            "retriever",
            "calculator",
            "python_repl",
            "vector_lookup",
        ],
        "denied_tools": [
            "shell_tool",
            "bash_tool",
        ],
        "sensitive_tools": [
            "python_repl",
        ],
    },
    "internal_actions_baseline": {
        "enabled": True,
        "enforcement_mode": "enforce",
        "unknown_tool_action": "deny",
        "confirmation_header": "X-Guardian-Tool-Confirm",
        "confirmation_value": "true",
        "allowed_tools": [
            "ticket_read",
            "ticket_comment",
            "kb_search",
            "incident_lookup",
        ],
        "denied_tools": [
            "db_drop",
            "infra_terminate",
        ],
        "sensitive_tools": [
            "ticket_comment",
        ],
    },
}


def list_tool_policy_presets() -> list[str]:
    return sorted(_PRESETS.keys())


def get_tool_policy_preset(name: str) -> dict[str, Any]:
    key = str(name or "").strip().lower()
    if key not in _PRESETS:
        return {}
    return deepcopy(_PRESETS[key])
