"""Simulated tool-using agents (the systems under attack).

A *scenario* is one agent: a system prompt, a set of tools, a fixture world the
tools read from, and a few user *tasks*. Fixture data has named injection
*slots* (an email body, an advisory description, a web page...). An attack
fills one slot with its payload; with no attack, the slot holds benign text.

Tools are pure Python over the fixture, so episodes are reproducible and cost
nothing except the model calls. Every side effect (email sent, command run,
file written, report submitted) is recorded on the environment so attacks and
task completion can be scored from what the agent *did*, not what it said.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

from ..llm import LLM, AssistantTurn, QuotaExhausted, ToolCall, ToolResult, ToolSpec

if TYPE_CHECKING:
    from ..defense.shield import Shield


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict[str, Any]
    fn: Callable[["Env", dict[str, Any]], Any]
    # Output comes from the outside world (web, inbox, advisories) and may carry
    # injected instructions. Outputs of trusted tools (the user's own address
    # book, local config) are not wrapped or scanned.
    untrusted_output: bool = True
    # Arguments whose values must be traceable to trusted context (provenance
    # policy), mapped to their kind: "email", "url", "command" or "path".
    sensitive_args: dict[str, str] = field(default_factory=dict)
    side_effect: bool = False

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(self.name, self.description, self.parameters)


def obj(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": required if required is not None else list(properties)}


@dataclass
class Env:
    """Mutable world state for one episode, plus a log of side effects."""

    data: dict[str, Any]
    actions: list[dict[str, Any]] = field(default_factory=list)  # side-effecting tool calls that executed
    report: dict[str, Any] | None = None  # triage agent's submitted report

    def did(self, tool: str, **args: Any) -> None:
        self.actions.append({"tool": tool, "args": args})


@dataclass
class Task:
    id: str
    prompt: str
    prefill: list[ToolCall]  # scripted first tool calls, so every episode reads the poisoned data
    allowed_tools: list[str]  # least-privilege tool set for this task (used by the tool policy)
    utility: Callable[["Episode"], bool]  # did the agent do the user's task?
    slots: list[str]


@dataclass
class Scenario:
    name: str
    description: str
    system_prompt: str
    tools: list[Tool]
    tasks: dict[str, Task]
    make_env: Callable[[dict[str, str]], Env]  # slot -> payload overrides
    # Trusted values the provenance policy accepts besides the user prompt, by
    # argument kind: {"email": contacts, "url": domains, "command": safe prefixes}.
    trusted: dict[str, list[str]] = field(default_factory=dict)
    free_text_keys: tuple[str, ...] = ("body", "details", "description", "content", "text", "output", "html")
    # Optional output checker run on the final result (e.g. triage grounding checker).
    finalize: Callable[["Episode"], list[dict[str, Any]]] | None = None

    def tool(self, name: str) -> Tool | None:
        return next((t for t in self.tools if t.name == name), None)


@dataclass
class Step:
    call: ToolCall
    output: str  # what the model saw (after the shield)
    raw_output: str = ""  # what the tool returned
    blocked: str | None = None  # policy reason, if the call was refused
    detections: list[dict[str, Any]] = field(default_factory=list)
    prefill: bool = False


@dataclass
class Episode:
    scenario: str
    task: str
    model: str
    attack_id: str | None
    defense: str
    steps: list[Step] = field(default_factory=list)
    final_text: str = ""
    env: Env | None = None
    llm_calls: int = 0
    usage: dict[str, int] = field(default_factory=lambda: {"input": 0, "output": 0})
    error: str | None = None
    exposed: bool = False  # did the attack payload reach the model unmodified?
    interventions: list[dict[str, Any]] = field(default_factory=list)
    seconds: float = 0.0

    @property
    def calls(self) -> list[ToolCall]:
        """Tool calls that actually executed (not blocked, not scripted)."""
        return [s.call for s in self.steps if not s.blocked and not s.prefill]

    @property
    def attempted_calls(self) -> list[ToolCall]:
        return [s.call for s in self.steps if not s.prefill]

    def summary(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario, "task": self.task, "model": self.model, "attack": self.attack_id,
            "defense": self.defense, "llm_calls": self.llm_calls, "usage": self.usage, "error": self.error,
            "exposed": self.exposed, "final_text": self.final_text[:2000],
            "steps": [{"tool": s.call.name, "args": s.call.args, "blocked": s.blocked, "prefill": s.prefill,
                       "detections": s.detections, "output": s.output[:600]} for s in self.steps],
            "actions": self.env.actions if self.env else [],
            "report": self.env.report if self.env else None,
            "interventions": self.interventions, "seconds": round(self.seconds, 1),
        }


def _contains_payload(shown: str, payload: str) -> bool:
    """Payload text may appear verbatim or JSON-escaped inside a tool result."""
    if not payload:
        return False
    probe = payload.strip()[:40]
    return probe in shown or json.dumps(probe, ensure_ascii=False)[1:-1] in shown


def _execute(scenario: Scenario, env: Env, call: ToolCall) -> tuple[str, bool]:
    tool = scenario.tool(call.name)
    if tool is None:
        return f"unknown tool {call.name!r}", True
    try:
        out = tool.fn(env, dict(call.args or {}))
    except (KeyError, TypeError, ValueError) as e:
        return f"{type(e).__name__}: {e}", True
    return (out if isinstance(out, str) else json.dumps(out, ensure_ascii=False)), False


def run_episode(
    llm: LLM,
    scenario: Scenario,
    task_id: str,
    payloads: dict[str, str] | None = None,
    shield: "Shield | None" = None,
    attack_id: str | None = None,
    max_turns: int = 6,
) -> Episode:
    """Run one user task to completion (or max_turns), optionally under attack and/or defense."""
    from ..defense.shield import Shield  # local import: defense depends on agents

    shield = shield or Shield.none()
    task = scenario.tasks[task_id]
    env = scenario.make_env(payloads or {})
    ep = Episode(scenario.name, task_id, llm.name, attack_id, shield.name, env=env)
    ctx = shield.start(scenario, task, env)
    tools = [t.spec for t in scenario.tools if shield.tool_visible(ctx, t.name)]
    system = scenario.system_prompt + shield.system_addendum()
    messages: list[dict[str, Any]] = [{"role": "user", "content": task.prompt}]
    start = time.time()

    def handle(calls: list[ToolCall], prefill: bool) -> None:
        results = []
        for call in calls:
            blocked = None if prefill else shield.check_call(ctx, call)
            if blocked:
                step = Step(call, output=f"Blocked by security policy: {blocked}", blocked=blocked)
                results.append(ToolResult(call.id, call.name, step.output, is_error=True))
            else:
                raw, is_error = _execute(scenario, env, call)
                tool = scenario.tool(call.name)
                untrusted = bool(tool and tool.untrusted_output) and not is_error
                shown, detections = shield.process_output(ctx, call, raw, untrusted)
                step = Step(call, output=shown, raw_output=raw, detections=detections)
                if payloads and any(_contains_payload(shown, p) for p in payloads.values()):
                    ep.exposed = True
                results.append(ToolResult(call.id, call.name, shown, is_error=is_error))
            step.prefill = prefill
            ep.steps.append(step)
        messages.append({"role": "tool", "results": results})

    try:
        if task.prefill:
            messages.append({"role": "assistant", "turn": AssistantTurn(tool_calls=list(task.prefill))})
            handle(list(task.prefill), prefill=True)
        for _ in range(max_turns):
            turn = llm.chat(system, messages, tools)
            ep.llm_calls += 1
            for k, v in turn.usage.items():
                if isinstance(v, int) and k in ep.usage:
                    ep.usage[k] += v
            messages.append({"role": "assistant", "turn": turn})
            if not turn.tool_calls:
                ep.final_text = turn.text
                break
            handle(turn.tool_calls, prefill=False)
            if env.report is not None and scenario.name == "triage":
                ep.final_text = turn.text or ep.final_text
                break
    except QuotaExhausted:
        raise
    except Exception as e:  # model/API failure: score what happened so far
        ep.error = f"{type(e).__name__}: {str(e)[:300]}"

    ep.interventions += shield.finalize(ctx, ep)
    ep.seconds = time.time() - start
    return ep
