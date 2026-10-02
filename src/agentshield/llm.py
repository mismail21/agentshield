"""Provider-neutral chat interface with native tool calling.

One small transcript format is shared by every provider:

    {"role": "user", "content": str}
    {"role": "assistant", "turn": AssistantTurn}
    {"role": "tool", "results": [ToolResult, ...]}

Each client converts it to its own wire format. Supported: Google Gemini /
Gemma (REST, free tier), Ollama (local), Anthropic Claude (optional extra), and
a scripted client for offline tests.
"""

from __future__ import annotations

import json
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

import httpx


@dataclass
class ToolCall:
    name: str
    args: dict[str, Any]
    id: str = field(default_factory=lambda: "call_" + uuid.uuid4().hex[:10])


@dataclass
class ToolResult:
    call_id: str
    name: str
    content: str
    is_error: bool = False


@dataclass
class AssistantTurn:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    raw: Any = None  # provider-native content, replayed verbatim (e.g. Gemini thought signatures)
    usage: dict[str, int] = field(default_factory=dict)


@dataclass
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]  # JSON schema (object)


class QuotaExhausted(RuntimeError):
    """The provider's daily quota is used up; waiting a few seconds won't help."""


class LLM(Protocol):
    name: str

    def chat(self, system: str, messages: list[dict[str, Any]], tools: list[ToolSpec]) -> AssistantTurn: ...


def _retry_wait(attempt: int, text: str) -> float:
    m = re.search(r"retry in ([\d.]+)s", text) or re.search(r'"retryDelay":\s*"(\d+)s"', text)
    return float(m.group(1)) + 1 if m else min(10 * (attempt + 1), 60)


# --------------------------------------------------------------------------- Gemini / Gemma


class GeminiLLM:
    """Gemini API over REST. Also serves Google's open-weight Gemma models."""

    URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    # Gemini 3 requires a thought signature on replayed function calls. History we
    # construct ourselves (scripted calls) has none; this documented value opts out.
    DUMMY_SIGNATURE = "skip_thought_signature_validator"

    def __init__(self, model: str = "gemini-3.5-flash-lite", api_key: str | None = None,
                 temperature: float = 0.0, on_event: Callable[[dict], None] | None = None):
        self.model = model
        self.name = model
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if not self.api_key:
            raise RuntimeError("Set GEMINI_API_KEY (free key: https://aistudio.google.com/apikey)")
        self.temperature = temperature
        self.on_event = on_event or (lambda e: None)
        self.http = httpx.Client(timeout=180)

    def _contents(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for m in messages:
            if m["role"] == "user":
                out.append({"role": "user", "parts": [{"text": m["content"]}]})
            elif m["role"] == "assistant":
                turn: AssistantTurn = m["turn"]
                if turn.raw is not None:
                    out.append(turn.raw)
                    continue
                parts: list[dict[str, Any]] = [{"text": turn.text}] if turn.text else []
                for i, c in enumerate(turn.tool_calls):
                    p: dict[str, Any] = {"functionCall": {"name": c.name, "args": c.args, "id": c.id}}
                    if i == 0:
                        p["thoughtSignature"] = self.DUMMY_SIGNATURE
                    parts.append(p)
                out.append({"role": "model", "parts": parts})
            elif m["role"] == "tool":
                out.append({"role": "user", "parts": [
                    {"functionResponse": {"name": r.name, "id": r.call_id,
                                          "response": {"error" if r.is_error else "result": r.content}}}
                    for r in m["results"]]})
        return out

    def chat(self, system: str, messages: list[dict[str, Any]], tools: list[ToolSpec]) -> AssistantTurn:
        body: dict[str, Any] = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": self._contents(messages),
            "generationConfig": {"temperature": self.temperature},
        }
        if tools:
            body["tools"] = [{"functionDeclarations": [
                {"name": t.name, "description": t.description, "parameters": t.parameters} for t in tools]}]
        for _ in range(3):  # empty / MALFORMED_FUNCTION_CALL responses are transient; retry the turn
            data = self._post(body)
            cands = data.get("candidates") or []
            if cands and (cands[0].get("content") or {}).get("parts"):
                break
            self.on_event({"type": "empty_response",
                           "finish": cands[0].get("finishReason") if cands else data.get("promptFeedback")})
        else:
            raise RuntimeError(f"{self.model}: empty response 3 times")
        content = cands[0]["content"]
        content.setdefault("role", "model")
        text, calls = [], []
        for p in content["parts"]:
            if p.get("thought"):
                continue
            if "functionCall" in p:
                fc = p["functionCall"]
                calls.append(ToolCall(name=fc["name"], args=fc.get("args") or {}, id=fc.get("id") or ToolCall("", {}).id))
            elif p.get("text"):
                text.append(p["text"])
        # keep the native content (with thought signatures) but drop thought text to save tokens
        raw = {"role": "model", "parts": [p for p in content["parts"] if not p.get("thought")] or [{"text": ""}]}
        um = data.get("usageMetadata", {})
        return AssistantTurn(text="".join(text), tool_calls=calls, raw=raw, usage={
            "input": um.get("promptTokenCount", 0),
            "output": um.get("candidatesTokenCount", 0) + um.get("thoughtsTokenCount", 0)})

    def _post(self, body: dict[str, Any]) -> dict[str, Any]:
        url = self.URL.format(model=self.model)
        for attempt in range(8):
            try:
                r = self.http.post(url, json=body, headers={"x-goog-api-key": self.api_key})
            except httpx.TransportError as e:
                if attempt == 7:
                    raise
                self.on_event({"type": "network_retry", "error": type(e).__name__})
                time.sleep(5 * (attempt + 1))
                continue
            if r.status_code == 200:
                return r.json()
            text = r.text
            if r.status_code == 429 and ("PerDay" in text or "per day" in text.lower()):
                raise QuotaExhausted(f"{self.model}: daily quota exhausted")
            if r.status_code in (429, 500, 502, 503, 504) and attempt < 7:
                wait = _retry_wait(attempt, text)
                self.on_event({"type": "rate_limited", "status": r.status_code, "wait": round(wait)})
                time.sleep(min(wait, 90))
                continue
            raise RuntimeError(f"Gemini API {r.status_code}: {text[:400]}")
        raise RuntimeError("unreachable")


# --------------------------------------------------------------------------- Ollama


class OllamaLLM:
    """A local open-weight model served by Ollama (https://ollama.com)."""

    def __init__(self, model: str = "qwen3:1.7b", host: str | None = None, temperature: float = 0.0,
                 think: bool = False, num_ctx: int = 8192):
        self.model = model
        self.name = f"ollama/{model}"
        self.host = (host or os.environ.get("OLLAMA_HOST") or "http://127.0.0.1:11434").rstrip("/")
        if not self.host.startswith("http"):
            self.host = "http://" + self.host
        self.options = {"temperature": temperature, "num_ctx": num_ctx}
        self.think = think
        self.http = httpx.Client(timeout=900)

    def _messages(self, system: str, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = [{"role": "system", "content": system}]
        for m in messages:
            if m["role"] == "user":
                out.append({"role": "user", "content": m["content"]})
            elif m["role"] == "assistant":
                t: AssistantTurn = m["turn"]
                out.append({"role": "assistant", "content": t.text, "tool_calls": [
                    {"function": {"name": c.name, "arguments": c.args}} for c in t.tool_calls]})
            elif m["role"] == "tool":
                for r in m["results"]:
                    out.append({"role": "tool", "tool_name": r.name,
                                "content": ("ERROR: " if r.is_error else "") + r.content})
        return out

    def chat(self, system: str, messages: list[dict[str, Any]], tools: list[ToolSpec]) -> AssistantTurn:
        body = {
            "model": self.model, "stream": False, "think": self.think, "options": self.options,
            "messages": self._messages(system, messages),
            "tools": [{"type": "function", "function": {"name": t.name, "description": t.description,
                                                         "parameters": t.parameters}} for t in tools],
        }
        r = self.http.post(f"{self.host}/api/chat", json=body)
        r.raise_for_status()
        data = r.json()
        msg = data.get("message", {})
        calls = []
        for c in msg.get("tool_calls") or []:
            fn = c.get("function", {})
            args = fn.get("arguments") or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {"_raw": args}
            calls.append(ToolCall(name=fn.get("name", ""), args=args))
        return AssistantTurn(text=msg.get("content") or "", tool_calls=calls,
                             usage={"input": data.get("prompt_eval_count", 0), "output": data.get("eval_count", 0)})


# --------------------------------------------------------------------------- Anthropic


class AnthropicLLM:
    """Claude via the Anthropic API (paid). Install with `pip install agent-shield[anthropic]`."""

    def __init__(self, model: str = "claude-haiku-4-5", max_tokens: int = 2048):
        import anthropic

        self.client = anthropic.Anthropic()
        self.model = model
        self.name = model
        self.max_tokens = max_tokens

    def _messages(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for m in messages:
            if m["role"] == "user":
                out.append({"role": "user", "content": m["content"]})
            elif m["role"] == "assistant":
                t: AssistantTurn = m["turn"]
                blocks: list[dict[str, Any]] = [{"type": "text", "text": t.text}] if t.text else []
                blocks += [{"type": "tool_use", "id": c.id, "name": c.name, "input": c.args} for c in t.tool_calls]
                out.append({"role": "assistant", "content": blocks or [{"type": "text", "text": "(no output)"}]})
            elif m["role"] == "tool":
                out.append({"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": r.call_id, "content": r.content, "is_error": r.is_error}
                    for r in m["results"]]})
        return out

    def chat(self, system: str, messages: list[dict[str, Any]], tools: list[ToolSpec]) -> AssistantTurn:
        resp = self.client.messages.create(
            model=self.model, max_tokens=self.max_tokens, system=system, temperature=0,
            messages=self._messages(messages),
            tools=[{"name": t.name, "description": t.description, "input_schema": t.parameters} for t in tools],
        )
        text = "".join(b.text for b in resp.content if b.type == "text")
        calls = [ToolCall(name=b.name, args=dict(b.input), id=b.id) for b in resp.content if b.type == "tool_use"]
        return AssistantTurn(text=text, tool_calls=calls,
                             usage={"input": resp.usage.input_tokens, "output": resp.usage.output_tokens})


# --------------------------------------------------------------------------- scripted (tests)


class ScriptedLLM:
    """Replays canned turns. ``script`` items are AssistantTurns or callables(messages) -> AssistantTurn."""

    def __init__(self, script: list[Any], name: str = "scripted"):
        self.script = list(script)
        self.name = name
        self.seen: list[list[dict[str, Any]]] = []
        self.systems: list[str] = []

    def chat(self, system: str, messages: list[dict[str, Any]], tools: list[ToolSpec]) -> AssistantTurn:
        self.seen.append(list(messages))
        self.systems.append(system)
        if not self.script:
            return AssistantTurn(text="done")
        nxt = self.script.pop(0)
        return nxt(messages) if callable(nxt) else nxt


def make_llm(spec: str, **kw: Any) -> LLM:
    """Build a client from a spec: ``gemini:<model>``, ``ollama:<model>``, ``anthropic:<model>``.

    A bare Gemini/Gemma model name also works.
    """
    provider, _, model = spec.partition(":")
    if not model:
        provider, model = "gemini", spec
    if provider in ("gemini", "google", "gemma"):
        return GeminiLLM(model=model, **kw)
    if provider == "ollama":
        return OllamaLLM(model=model, **kw)
    if provider in ("anthropic", "claude"):
        return AnthropicLLM(model=model, **kw)
    raise ValueError(f"unknown provider in {spec!r}")
