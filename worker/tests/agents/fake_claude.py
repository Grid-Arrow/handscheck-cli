"""A scripted stand-in for `client.beta.messages` (no network, no cost)."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any


def text(
    payload: Any, *, usage: tuple[int, int] = (1000, 200), model: str = "claude-opus-5-5"
) -> SimpleNamespace:
    body = payload if isinstance(payload, str) else json.dumps(payload)
    return SimpleNamespace(
        stop_reason="end_turn",
        content=[SimpleNamespace(type="text", text=body)],
        usage=SimpleNamespace(
            input_tokens=usage[0],
            output_tokens=usage[1],
            cache_read_input_tokens=0,
            cache_creation_input_tokens=0,
        ),
        model=model,
        stop_details=None,
    )


def tool(command: str, sudo: bool = False, *, call_id: str = "toolu_1") -> SimpleNamespace:
    return SimpleNamespace(
        stop_reason="tool_use",
        content=[
            SimpleNamespace(type="thinking", thinking="", signature="sig"),
            SimpleNamespace(
                type="tool_use",
                id=call_id,
                name="run_readonly",
                input={"command": command, "sudo": sudo, "reason": "check"},
            ),
        ],
        usage=SimpleNamespace(
            input_tokens=1500, output_tokens=100, cache_read_input_tokens=500, cache_creation_input_tokens=0
        ),
        model="claude-opus-5-5",
        stop_details=None,
    )


def refusal(category: str = "cyber") -> SimpleNamespace:
    return SimpleNamespace(
        stop_reason="refusal",
        content=[],
        usage=SimpleNamespace(
            input_tokens=100, output_tokens=0, cache_read_input_tokens=0, cache_creation_input_tokens=0
        ),
        model="claude-opus-5-5",
        stop_details=SimpleNamespace(category=category, explanation="declined"),
    )


def finding(kind: str, subject: str, severity: str = "high", **extra: Any) -> dict[str, Any]:
    return {
        "kind": kind,
        "subject": subject,
        "severity": severity,
        "confidence": "high",
        "title": extra.get("title", f"{kind} {subject}"),
        "summary": "summary",
        "evidence": extra.get("evidence", [subject]),
        "rule_ids": [],
        "recommended_action": "look",
    }


class ScriptedAPI:
    """Calls `handler(request kwargs, call index)` for every request and records the requests."""

    def __init__(self, handler: Callable[[dict[str, Any], int], Any]) -> None:
        self.handler = handler
        self.requests: list[dict[str, Any]] = []

    async def create(self, **kwargs: Any) -> Any:
        self.requests.append(kwargs)
        return self.handler(kwargs, len(self.requests) - 1)


def section(request: dict[str, Any], name: str) -> str:
    """The text of a <name>…</name> section of the first user message."""
    content = request["messages"][0]["content"]
    m = re.search(rf"<{name}>\n(.*?)\n</{name}>", content, re.S)
    return m.group(1) if m else ""


def context(request: dict[str, Any]) -> dict[str, Any]:
    raw = section(request, "context")
    return json.loads(raw) if raw else {}


def is_verifier(request: dict[str, Any]) -> bool:
    return "You are the verifier" in request["system"][0]["text"]
