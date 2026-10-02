"""Use the defense layer in your own agent, without the simulated scenarios.

    from agentshield import ToolGuard

    guard = ToolGuard(
        allowed_tools={"read_inbox", "send_email"},
        sensitive={"send_email": {"to": "email"}},
        trusted={"email": ["boss@mycorp.com"]},
    )
    system_prompt += guard.system_prompt_addendum()

    # before executing a tool call the model asked for:
    reason = guard.check_call("send_email", args, user_request)
    if reason:
        result = f"Blocked by security policy: {reason}"
    else:
        result = guard.wrap_output("send_email", run_tool(...))
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any

from .defense.detector import Detector
from .defense.policy import check_value
from .defense.shield import SPOTLIGHT_PROMPT, Shield


@dataclass
class ToolGuard:
    allowed_tools: set[str] | None = None  # None = no allowlist
    sensitive: dict[str, dict[str, str]] = field(default_factory=dict)  # tool -> {arg: kind}
    trusted: dict[str, list[str]] = field(default_factory=dict)  # kind -> trusted values
    detector: Detector | None = None
    spotlight: bool = True
    threshold: float = 0.5
    trusted_tools: set[str] = field(default_factory=set)  # tools whose output is not scanned/wrapped
    boundary: str = field(default_factory=lambda: secrets.token_hex(4))
    detections: list[dict[str, Any]] = field(default_factory=list)

    def system_prompt_addendum(self) -> str:
        return SPOTLIGHT_PROMPT if self.spotlight else ""

    def check_call(self, tool: str, args: dict[str, Any], user_request: str) -> str | None:
        """Return a reason to block the call, or None to allow it."""
        if self.allowed_tools is not None and tool not in self.allowed_tools:
            return f"tool {tool!r} is not permitted for this task"
        for arg, kind in self.sensitive.get(tool, {}).items():
            if arg in args:
                reason = check_value(kind, args[arg], user_request, self.trusted)
                if reason:
                    return reason
        return None

    def wrap_output(self, tool: str, output: str) -> str:
        """Scan (if a detector is set) and delimit a tool result before it goes back to the model."""
        if tool in self.trusted_tools:
            return output
        shown = output
        if self.detector is not None:
            shown, found = Shield(detector=self.detector, threshold=self.threshold).sanitize(output)
            self.detections += [{"tool": tool, **d} for d in found]
        if self.spotlight:
            body = shown.replace("untrusted_data", "untrusted-data")
            shown = (f'<untrusted_data source="{tool}" boundary="{self.boundary}">\n{body}\n'
                     f'</untrusted_data boundary="{self.boundary}">')
        return shown
