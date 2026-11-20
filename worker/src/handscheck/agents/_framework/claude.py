"""Run one Claude agent turn-by-turn: the agent's instructions, the facts and diff, one read-only tool, and a
structured answer. Plain Claude API (the `anthropic` SDK) with a loop we own, not the Claude Agent SDK:
the agent must have exactly one tool, `run_readonly`, gated by the SSH command policy. The Agent SDK ships
Claude Code's built-in Bash/file tools, which we would have to strip and audit.

- Every command the model asks for goes through `CheckContext.run` (policy, timeouts, caps) and is logged.
- Facts, diffs and tool output are redacted before they are sent (`redact.py`), and they are wrapped as data:
  files on a compromised host are attacker-controlled, so the system prompt says to never follow instructions
  found in them.
- The answer must validate against the requested schema (structured outputs); free text is an error.
- Tokens and cost are counted per call; a per-agent tool-call cap and a per-run dollar budget stop runaways.
- Refusals: server-side fallback (`fallbacks: "default"`) re-runs a declined request on a fallback model; a
  refusal that survives is reported as an error, never as "no findings".
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any, Protocol

import anthropic
from pydantic import BaseModel, ValidationError

from handscheck.agents._framework.check import CheckContext
from handscheck.agents._framework.redact import redact, redact_text
from handscheck.agents._framework.stripped import STRIPPED_MARKER
from handscheck.ssh.policy import PolicyViolation

FALLBACK_BETA = "server-side-fallback-2026-07-01"
MAX_TOKENS = 16000
TOOL_OUTPUT_CHARS = 20_000

# $ per million tokens: input, output, cache read. Cache writes (5-minute TTL) cost 1.25x input.
PRICES: dict[str, tuple[float, float, float]] = {
    "claude-opus-5-5": (4.00, 20.00, 0.20),
    "claude-sonnet-5-5": (2.00, 10.00, 0.10),
    "claude-haiku-5-5": (0.10, 0.50, 0.01),
    "claude-opus-4-8": (5.00, 25.00, 0.50),
}

RUN_READONLY: dict[str, Any] = {
    "name": "run_readonly",
    "description": (
        "Run one read-only command on the host being checked and get its output. The command is checked by "
        "handscheck's command policy before it is sent: single commands only (no pipes, redirection, ;, &&, "
        "subshells, globs or variable expansion), from a read-only allowlist (cat, head, tail, grep, find "
        "without -exec/-delete, stat, ls, md5sum, sha256sum, dpkg -L/-S/-s/-V, systemctl status/cat/show, "
        "journalctl, crontab -l, last, ss, ps, …). Anything that writes, deletes, installs, restarts, runs a "
        "shell or interpreter, or reaches the network is refused. Use sudo=true for root-only files. "
        "Output is "
        "capped; prefer grep/head over cat for large files."
    ),
    "strict": True,
    "input_schema": {
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": "The command line, e.g. grep -n eval /var/www/x.php",
            },
            "sudo": {"type": "boolean", "description": "Run with read-only sudo (as root)."},
            "reason": {"type": "string", "description": "One line: what you want to learn."},
        },
        "required": ["command", "sudo", "reason"],
        "additionalProperties": False,
    },
}

PREAMBLE_PATH = Path(__file__).with_name("PREAMBLE.md")
"""The shared start of every agent's system prompt. Like the AGENT.md bodies, it is not in public builds."""


@cache
def preamble() -> str:
    """The preamble text, or "" in a public build (the file holds only the stripped-build marker there)."""
    try:
        text = PREAMBLE_PATH.read_text(encoding="utf-8").strip()
    except OSError:
        return ""
    return "" if text == STRIPPED_MARKER else text


class MessagesAPI(Protocol):
    async def create(self, **kwargs: Any) -> Any: ...


class SDKMessages:
    """`client.beta.messages` behind the minimal protocol the runner uses (tests pass a fake instead)."""

    def __init__(self, client: anthropic.AsyncAnthropic) -> None:
        self.client = client

    async def create(self, **kwargs: Any) -> Any:
        return await self.client.beta.messages.create(**kwargs)


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    cost_usd: float = 0.0
    calls: int = 0

    def add_response(self, model: str, usage: Any) -> None:
        inp = getattr(usage, "input_tokens", 0) or 0
        out = getattr(usage, "output_tokens", 0) or 0
        read = getattr(usage, "cache_read_input_tokens", 0) or 0
        write = getattr(usage, "cache_creation_input_tokens", 0) or 0
        price_in, price_out, price_read = PRICES.get(model, PRICES["claude-opus-5-5"])
        self.input_tokens += inp
        self.output_tokens += out
        self.cache_read_tokens += read
        self.cache_write_tokens += write
        self.calls += 1
        self.cost_usd += (
            inp * price_in + out * price_out + read * price_read + write * price_in * 1.25
        ) / 1e6

    def add(self, other: Usage) -> None:
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens
        self.cache_read_tokens += other.cache_read_tokens
        self.cache_write_tokens += other.cache_write_tokens
        self.cost_usd += other.cost_usd
        self.calls += other.calls

    def dump(self) -> dict[str, Any]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_read_tokens": self.cache_read_tokens,
            "cache_write_tokens": self.cache_write_tokens,
            "cost_usd": round(self.cost_usd, 4),
            "calls": self.calls,
        }


class ClaudeError(Exception):
    """The agent run did not produce a valid answer (refusal, truncation, invalid output, budget)."""


class NoInstructions(ClaudeError):
    """A public build: the prompts (AGENT.md bodies, the preamble) aren't in it, so no Claude call is made."""


@dataclass
class Budget:
    """A dollar ceiling shared by every Claude call of a run."""

    limit_usd: float
    spent: Usage = field(default_factory=Usage)

    @property
    def exhausted(self) -> bool:
        return self.spent.cost_usd >= self.limit_usd


@dataclass
class AgentCall:
    model: str
    effort: str
    instructions: str
    max_tool_calls: int


@dataclass
class AgentOutcome[R: BaseModel]:
    answer: R
    usage: Usage
    tool_calls: list[dict[str, Any]]
    model: str
    served_by: str | None = None


async def run_agent[T: BaseModel](
    api: MessagesAPI,
    call: AgentCall,
    user_payload: dict[str, Any],
    output: type[T],
    *,
    ctx: CheckContext | None,
    budget: Budget,
    schema: dict[str, Any],
) -> AgentOutcome[T]:
    """One agent conversation. `ctx` None = no tool (e.g. the correlator works only on the payload)."""
    if not call.instructions:  # a stripped AGENT.md (public build)
        raise NoInstructions(
            "this build has no agent instructions (public build): Claude analysis runs on handscheck's side"
        )
    usage = Usage()
    tool_log: list[dict[str, Any]] = []
    system = [
        {
            "type": "text",
            "text": preamble() + "\n\n" + call.instructions,
            "cache_control": {"type": "ephemeral"},
        }
    ]
    messages: list[dict[str, Any]] = [{"role": "user", "content": render_payload(user_payload)}]
    tools = [RUN_READONLY] if ctx is not None else []
    served_by: str | None = None
    for _turn in range(call.max_tool_calls + 3):
        if budget.exhausted:
            raise ClaudeError(f"run budget of ${budget.limit_usd:.2f} reached")
        response = await api.create(
            model=call.model,
            max_tokens=MAX_TOKENS,
            system=system,
            messages=messages,
            tools=tools,
            output_config={"effort": call.effort, "format": {"type": "json_schema", "schema": schema}},
            cache_control={"type": "ephemeral"},  # caches the growing history between tool turns
            betas=[FALLBACK_BETA],
            fallbacks="default",
        )
        served_by = getattr(response, "model", None) or call.model
        usage.add_response(served_by, response.usage)
        budget.spent.add_response(served_by, response.usage)
        stop = response.stop_reason
        if stop == "refusal":
            details = getattr(response, "stop_details", None)
            category = getattr(details, "category", None) if details else None
            raise ClaudeError(f"Claude declined (category {category or 'unknown'}) even after fallback")
        if stop == "max_tokens":
            raise ClaudeError("answer truncated at max_tokens")
        uses = [b for b in response.content if getattr(b, "type", None) == "tool_use"]
        if stop == "tool_use" and uses:
            messages.append({"role": "assistant", "content": response.content})
            results = []
            for block in uses:
                results.append(await _tool_result(block, ctx, tool_log, call.max_tool_calls))
            messages.append({"role": "user", "content": results})
            continue
        text = "".join(getattr(b, "text", "") for b in response.content if getattr(b, "type", None) == "text")
        try:
            answer = output.model_validate_json(text)
        except ValidationError as exc:
            raise ClaudeError(f"answer did not match the schema: {exc.errors()[:3]}") from exc
        return AgentOutcome(
            answer=answer, usage=usage, tool_calls=tool_log, model=call.model, served_by=served_by
        )
    raise ClaudeError("too many turns without a final answer")


async def _tool_result(
    block: Any, ctx: CheckContext | None, log: list[dict[str, Any]], cap: int
) -> dict[str, Any]:
    args = block.input if isinstance(block.input, dict) else {}
    command, sudo = str(args.get("command", "")), bool(args.get("sudo", False))
    entry: dict[str, Any] = {"command": command, "sudo": sudo, "reason": str(args.get("reason", ""))[:200]}
    log.append(entry)

    def result(text: str, error: bool = False) -> dict[str, Any]:
        entry["result"] = "error" if error else "ok"
        body = "<tool_output>\n" + redact_text(text)[:TOOL_OUTPUT_CHARS] + "\n</tool_output>"
        return {"type": "tool_result", "tool_use_id": block.id, "content": body, "is_error": error}

    if ctx is None:
        return result("no tool is available for this task", error=True)
    if len(log) > cap:
        return result(f"tool-call limit ({cap}) reached: give your answer from what you have", error=True)
    try:
        out = await ctx.run(_split(command), sudo=sudo, timeout=60, max_output=TOOL_OUTPUT_CHARS * 2)
    except PolicyViolation as exc:
        entry["refused"] = exc.reason
        return result(f"refused by the command policy: {exc.reason}", error=True)
    except ValueError as exc:
        return result(f"could not parse the command: {exc}", error=True)
    entry["exit_status"] = out.exit_status
    text = f"exit status: {out.exit_status}{' (timed out)' if out.timed_out else ''}"
    text += f"{' (output truncated)' if out.truncated else ''}\n{out.stdout}"
    if out.stderr.strip():
        text += f"\n--- stderr ---\n{out.stderr[:2000]}"
    return result(text)


def _split(command: str) -> list[str]:
    """Split like the policy does (it re-checks the words and refuses operators)."""
    from handscheck.ssh.policy import split_words

    words = split_words(command)
    if any(is_op for _, is_op in words):
        raise PolicyViolation(command, "shell operators (|, ;, &&, >, …) are not allowed")
    return [w for w, _ in words]


def render_payload(payload: dict[str, Any]) -> str:
    """The user message: sections as JSON inside tags, redacted."""
    parts = []
    for key, value in payload.items():
        body = (
            value
            if isinstance(value, str)
            else json.dumps(redact(value), indent=1, sort_keys=True, default=str)
        )
        parts.append(f"<{key}>\n{redact_text(body) if isinstance(value, str) else body}\n</{key}>")
    return "\n\n".join(parts)


def compact(value: Any, *, max_list: int = 150, max_str: int = 2000) -> Any:
    """Shrink large facts for the prompt: long lists keep their first items and say how many were cut."""
    if isinstance(value, dict):
        return {k: compact(v, max_list=max_list, max_str=max_str) for k, v in value.items()}
    if isinstance(value, list):
        items = [compact(v, max_list=max_list, max_str=max_str) for v in value[:max_list]]
        if len(value) > max_list:
            items.append(f"… {len(value) - max_list} more not shown")
        return items
    if isinstance(value, str) and len(value) > max_str:
        return value[:max_str] + f"… ({len(value) - max_str} more characters)"
    return value
