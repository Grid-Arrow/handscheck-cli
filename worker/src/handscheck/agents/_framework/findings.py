"""What Claude must return (`FindingOut`, enforced with structured outputs) and how a returned item becomes a
finding with a stable dedupe key. Free text is rejected: an answer that doesn't validate is an error."""

from __future__ import annotations

import re
from copy import deepcopy
from typing import Any, Literal

from pydantic import BaseModel, Field

from handscheck.contracts import Finding, Severity

SeverityName = Literal["info", "low", "medium", "high", "critical"]
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
VERIFY_FROM = "medium"
"""Findings at or above this severity get an independent verifier opinion before anyone is alerted."""


class FindingItem(BaseModel):
    kind: str = Field(description="Short snake_case type, e.g. php_in_uploads, rogue_admin, fake_service.")
    subject: str = Field(
        description="The one thing this is about: a path, login, unit, IP or plugin slug. Stable across runs."
    )
    severity: SeverityName
    confidence: Literal["low", "medium", "high"]
    title: str = Field(description="One line, specific (what and where).")
    summary: str = Field(description="What it is, why it matters, how sure you are, in 2-5 sentences.")
    evidence: list[str] = Field(description="Exact fact values or command output lines that support it.")
    rule_ids: list[str] = Field(description="IDs of matching rules from the context (may be empty).")
    recommended_action: str = Field(
        description="What a human should do next (read-only advice; nothing is run)."
    )


class FindingOut(BaseModel):
    assessment: str = Field(description="One short paragraph: overall state of this agent's area.")
    findings: list[FindingItem]


class InvestigationOut(BaseModel):
    answer: str = Field(description="What you found, how sure you are, and what you could not check.")
    findings: list[FindingItem]


class Verdict(BaseModel):
    verdict: Literal["confirmed", "rejected", "needs_more"]
    reason: str = Field(description="Why, citing what you checked. For needs_more: what is missing.")
    checked: list[str] = Field(description="The facts or commands you used to decide.")


class Verification(BaseModel):
    status: Literal["pending", "confirmed", "rejected", "needs_more", "not_required", "error"]
    reason: str | None = None
    verifier_version: int | None = None


class ReportedFinding(BaseModel):
    """A finding as the worker reports it: the contract fields plus verification and confidence."""

    finding: Finding
    confidence: str
    host: str
    verification: Verification


def strict_schema(model: type[BaseModel]) -> dict[str, Any]:
    """A JSON Schema for structured outputs: every object closed and every property required, no $refs."""
    schema = model.model_json_schema()
    defs = schema.pop("$defs", {})

    def walk(node: Any) -> Any:
        if isinstance(node, dict):
            if "$ref" in node:
                return walk(deepcopy(defs[node["$ref"].rsplit("/", 1)[-1]]))
            # Drop pydantic's "title"/"default" annotations, but never a property that happens to be named so.
            node = {
                k: ({name: walk(sub) for name, sub in v.items()} if k == "properties" else walk(v))
                for k, v in node.items()
                if k not in ("title", "default")
            }
            if node.get("type") == "object":
                node["additionalProperties"] = False
                node["required"] = list(node.get("properties", {}))
            return node
        if isinstance(node, list):
            return [walk(v) for v in node]
        return node

    result: dict[str, Any] = walk(schema)
    return result


def _slug(text: str, limit: int = 60) -> str:
    return re.sub(r"[^a-z0-9_]+", "_", text.lower()).strip("_")[:limit] or "finding"


def dedupe_key(agent: str, kind: str, host: str, site: str | None, subject: str) -> str:
    """e.g. malware:php_in_uploads:lab-wp2:gamma.lab.test:/var/www/…/cache.php"""
    return f"{agent}:{_slug(kind)}:{host}:{site or '-'}:{subject.strip()[:300]}"


def to_finding(item: FindingItem, *, agent: str, version: int, host: str, site: str | None) -> Finding:
    return Finding(
        dedupe_key=dedupe_key(agent, item.kind, host, site, item.subject),
        agent=agent,
        agent_version=version,
        site=site,
        severity=Severity(item.severity),
        title=item.title.strip()[:300],
        summary=item.summary.strip()[:4000],
        evidence=[e[:1000] for e in item.evidence[:30]],
        rule_ids=item.rule_ids[:20],
        recommended_action=item.recommended_action.strip()[:2000] or None,
    )


def needs_verification(severity: str) -> bool:
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER[VERIFY_FROM]


Mode = Literal["baseline", "deep", "changes", "skipped"]
"""`deep`: the planner asked for a review of all facts on a host that already has a baseline (M7c)."""


class ClaudeRunInfo(BaseModel):
    agent: str
    site: str | None = None
    mode: Mode
    reason: str | None = None
    """Why it was skipped, or the error that stopped it."""
    model: str | None = None
    served_by: str | None = None
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    usage: dict[str, Any] = Field(default_factory=dict)
    assessment: str | None = None
    findings: int = 0
    error: str | None = None
