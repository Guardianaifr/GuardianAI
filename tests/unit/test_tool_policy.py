from guardrails.tool_policy import ToolPolicyEngine
from guardrails.tool_policy_presets import get_tool_policy_preset, list_tool_policy_presets


def test_tool_policy_allow_when_disabled():
    engine = ToolPolicyEngine({"enabled": False})
    result = engine.evaluate({"tools": [{"function": {"name": "x"}}]}, headers={})
    assert result.action == "allow"


def test_tool_policy_denies_unknown_when_allowlist_set():
    engine = ToolPolicyEngine({
        "enabled": True,
        "allowed_tools": ["safe_tool"],
        "unknown_tool_action": "deny",
    })
    result = engine.evaluate({"tools": [{"type": "function", "function": {"name": "unsafe_tool"}}]}, headers={})
    assert result.action == "block"


def test_tool_policy_requires_confirmation_header():
    engine = ToolPolicyEngine({
        "enabled": True,
        "sensitive_tools": ["transfer_funds"],
        "confirmation_header": "X-Guardian-Tool-Confirm",
        "confirmation_value": "true",
    })
    payload = {"tools": [{"type": "function", "function": {"name": "transfer_funds"}}]}
    assert engine.evaluate(payload, headers={}).action == "confirm"
    assert engine.evaluate(payload, headers={"X-Guardian-Tool-Confirm": "true"}).action == "allow"


def test_tool_policy_preset_catalog_contains_expected_profiles():
    presets = list_tool_policy_presets()
    assert "openai_tools_baseline" in presets
    assert "langchain_tools_baseline" in presets
    assert "internal_actions_baseline" in presets


def test_openai_preset_blocks_denied_tool():
    engine = ToolPolicyEngine({"preset": "openai_tools_baseline"})
    payload = {"tools": [{"type": "function", "function": {"name": "shell_exec"}}]}
    result = engine.evaluate(payload, headers={})
    assert result.action == "block"
    assert "tool_denied" in result.reason


def test_langchain_preset_requires_confirmation_for_sensitive_tool():
    engine = ToolPolicyEngine({"preset": "langchain_tools_baseline"})
    payload = {"tools": [{"type": "function", "function": {"name": "python_repl"}}]}
    assert engine.evaluate(payload, headers={}).action == "confirm"
    assert engine.evaluate(payload, headers={"X-Guardian-Tool-Confirm": "true"}).action == "allow"


def test_internal_actions_preset_supports_local_override():
    engine = ToolPolicyEngine(
        {
            "preset": "internal_actions_baseline",
            "allowed_tools": ["ticket_read", "ticket_comment", "custom_safe_tool"],
        }
    )
    payload = {"tools": [{"type": "function", "function": {"name": "custom_safe_tool"}}]}
    result = engine.evaluate(payload, headers={"X-Guardian-Tool-Confirm": "true"})
    assert result.action == "allow"


def test_get_unknown_preset_returns_empty_dict():
    assert get_tool_policy_preset("does_not_exist") == {}
