"""Tool-call policy engine for agent action containment."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from guardrails.tool_policy_presets import get_tool_policy_preset


@dataclass
class ToolPolicyResult:
    action: str
    reason: str
    tools: list[str]


class ToolPolicyEngine:
    def __init__(self, config: dict[str, Any] | None = None):
        raw_cfg = config or {}
        preset_name = str(raw_cfg.get("preset", "")).strip().lower()
        preset_cfg = get_tool_policy_preset(preset_name) if preset_name else {}
        cfg = {**preset_cfg, **raw_cfg}
        self.enabled = bool(cfg.get("enabled", False))
        self.enforcement_mode = str(cfg.get("enforcement_mode", "enforce")).lower()
        self.unknown_tool_action = str(cfg.get("unknown_tool_action", "deny")).lower()

        self.allowed_tools = {str(x).strip().lower() for x in cfg.get("allowed_tools", []) if str(x).strip()}
        self.denied_tools = {str(x).strip().lower() for x in cfg.get("denied_tools", []) if str(x).strip()}
        self.sensitive_tools = {str(x).strip().lower() for x in cfg.get("sensitive_tools", []) if str(x).strip()}

        self.confirm_header = str(cfg.get("confirmation_header", "X-Guardian-Tool-Confirm"))
        self.confirm_value = str(cfg.get("confirmation_value", "true")).lower()

    def _extract_tools(self, data: dict[str, Any] | None) -> list[str]:
        if not isinstance(data, dict):
            return []
        tools: set[str] = set()

        for t in data.get("tools", []) if isinstance(data.get("tools"), list) else []:
            if not isinstance(t, dict):
                continue
            if isinstance(t.get("function"), dict) and t["function"].get("name"):
                tools.add(str(t["function"]["name"]).strip().lower())
            elif t.get("name"):
                tools.add(str(t["name"]).strip().lower())

        tool_choice = data.get("tool_choice")
        if isinstance(tool_choice, dict):
            fn = tool_choice.get("function")
            if isinstance(fn, dict) and fn.get("name"):
                tools.add(str(fn["name"]).strip().lower())

        function_call = data.get("function_call")
        if isinstance(function_call, dict) and function_call.get("name"):
            tools.add(str(function_call["name"]).strip().lower())

        messages = data.get("messages", [])
        if isinstance(messages, list):
            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                calls = msg.get("tool_calls")
                if not isinstance(calls, list):
                    continue
                for call in calls:
                    if not isinstance(call, dict):
                        continue
                    fn = call.get("function")
                    if isinstance(fn, dict) and fn.get("name"):
                        tools.add(str(fn["name"]).strip().lower())

        return sorted(t for t in tools if t)

    def evaluate(self, data: dict[str, Any] | None, headers: dict[str, str] | None = None) -> ToolPolicyResult:
        if not self.enabled:
            return ToolPolicyResult(action="allow", reason="tool_policy_disabled", tools=[])

        headers = headers or {}
        requested_tools = self._extract_tools(data)
        if not requested_tools:
            return ToolPolicyResult(action="allow", reason="no_tool_invocation", tools=[])

        for tool in requested_tools:
            if tool in self.denied_tools:
                return ToolPolicyResult(action="block", reason=f"tool_denied:{tool}", tools=requested_tools)

        if self.allowed_tools:
            unknown = [t for t in requested_tools if t not in self.allowed_tools]
            if unknown and self.unknown_tool_action == "deny":
                return ToolPolicyResult(action="block", reason=f"tool_not_allowlisted:{','.join(unknown)}", tools=requested_tools)

        requires_confirm = any(t in self.sensitive_tools for t in requested_tools)
        if requires_confirm:
            raw = str(headers.get(self.confirm_header, "")).strip().lower()
            if raw != self.confirm_value:
                return ToolPolicyResult(action="confirm", reason="sensitive_tool_confirmation_required", tools=requested_tools)

        return ToolPolicyResult(action="allow", reason="tool_policy_pass", tools=requested_tools)
