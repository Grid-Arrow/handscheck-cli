"""The Claude stage of a host run (M4): specialists on what changed, then the verifier on medium+ findings.

- A specialist runs only when its facts are new (baseline review) or changed since the last run; otherwise it
  is skipped and its open findings simply stay open ("agents only run on changed facts").
- Each specialist gets its AGENT.md instructions, redacted facts and diff, change events, its rules and its
  settings, and may call `run_readonly`. Its answer is validated (`FindingOut`).
- Every finding of severity medium or higher is `pending` until the verifier, which sees the claim and
  evidence but not the specialist's reasoning, returns confirmed / rejected / needs_more. Lower ones are
  `not_required`. Standalone `hc check` verifies here (`verify`); control-plane scans leave it to a separate
  `verify` job (`run_verifier` is shared with it, see worker/roles.py).
- One dollar budget covers the whole run; when it runs out, the remaining agents are skipped and say so.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any

import anthropic
import yaml

from handscheck.agents._framework.check import CheckContext
from handscheck.agents._framework.claude import (
    AgentCall,
    Budget,
    ClaudeError,
    MessagesAPI,
    Usage,
    compact,
    run_agent,
)
from handscheck.agents._framework.definition import AgentDefinition, load_agent
from handscheck.agents._framework.findings import (
    ClaudeRunInfo,
    FindingOut,
    Mode,
    ReportedFinding,
    Verdict,
    Verification,
    needs_verification,
    strict_schema,
    to_finding,
)
from handscheck.agents._framework.registry import Agent
from handscheck.contracts import Finding
from handscheck.pipeline.guaranteed import add_guaranteed_findings
from handscheck.pipeline.run import AgentResult, HostRun
from handscheck.remediation.propose import propose_fix

log = logging.getLogger(__name__)
ROLES = Path(__file__).resolve().parents[1] / "roles"


@dataclass
class ClaudeOptions:
    api: MessagesAPI
    budget_usd: float = 5.0
    baseline_review: bool = True
    """Run specialists on a first (baseline) snapshot. Off = only on changes."""
    verify: bool = True
    concurrency: int = 3
    open_findings: list[dict[str, Any]] = field(default_factory=list)
    """Open findings for this host (dedupe_key, agent, site, title, severity): context for the specialists."""
    overrides: dict[str, dict[str, Any]] = field(default_factory=dict)
    deep: dict[str, frozenset[str]] = field(default_factory=dict)
    """The planner's deep reviews (M7c): agent → the sites to review in full (empty = every site)."""
    deep_reasons: dict[str, str] = field(default_factory=dict)

    def is_deep(self, agent: str, site: str | None) -> bool:
        sites = self.deep.get(agent)
        return sites is not None and (not sites or site is None or site in sites)


@cache
def verifier() -> AgentDefinition:
    return load_agent(ROLES / "verifier")


def plan(result: AgentResult, baseline_review: bool, deep: bool = False) -> tuple[Mode, str | None]:
    if result.status == "failed" or result.facts is None:
        return "skipped", "the deterministic check failed"
    if result.baseline:
        return ("baseline", None) if baseline_review else ("skipped", "baseline (baseline review is off)")
    if deep:
        return "deep", None
    if result.changes:
        return "changes", None
    return "skipped", "no changes since the last run"


async def run_claude_stage(
    ctx: CheckContext, run: HostRun, agents: dict[str, Agent], options: ClaudeOptions
) -> None:
    budget = Budget(limit_usd=options.budget_usd)
    gate = asyncio.Semaphore(options.concurrency)
    inventory = run.site_inventory()
    sites = {s.name: s for s in (inventory.sites if inventory else [])}

    async def specialist(result: AgentResult) -> tuple[ClaudeRunInfo, list[ReportedFinding]]:
        agent = agents.get(result.agent)
        mode, reason = plan(result, options.baseline_review, options.is_deep(result.agent, result.site))
        info = ClaudeRunInfo(agent=result.agent, site=result.site, mode=mode, reason=reason)
        if agent is None or agent.definition.model is None or mode == "skipped":
            info.mode = "skipped"
            info.reason = info.reason or "no Claude model for this agent"
            return info, []
        if budget.exhausted:
            info.mode, info.reason = "skipped", f"run budget of ${budget.limit_usd:.2f} reached"
            return info, []
        d = agent.definition
        call = AgentCall(
            model=d.model or "", effort=d.effort, instructions=d.instructions, max_tool_calls=d.max_tool_calls
        )
        payload = specialist_payload(run, result, d, options, mode)
        agent_ctx = ctx.for_site(sites[result.site]) if result.site in sites else ctx
        async with gate:
            try:
                outcome = await run_agent(
                    options.api,
                    call,
                    payload,
                    FindingOut,
                    ctx=agent_ctx,
                    budget=budget,
                    schema=FINDING_SCHEMA,
                )
            except (ClaudeError, anthropic.APIError) as exc:
                info.error = f"{type(exc).__name__}: {exc}"[:500]
                return info, []
        info.model, info.served_by = outcome.model, outcome.served_by
        info.tool_calls, info.usage = outcome.tool_calls, outcome.usage.dump()
        info.assessment = outcome.answer.assessment
        reported = []
        for item in outcome.answer.findings:
            finding = to_finding(item, agent=d.name, version=d.version, host=run.host, site=result.site)
            finding.fix = propose_fix(finding, result.facts)
            # Medium+ stays `pending` until a verifier decides: here (options.verify) or in its own job.
            status = "pending" if needs_verification(item.severity) else "not_required"
            reported.append(
                ReportedFinding(
                    finding=finding,
                    confidence=item.confidence,
                    host=run.host,
                    verification=Verification(status=status),
                )
            )
        info.findings = len(reported)
        return info, reported

    outcomes = await asyncio.gather(*(specialist(r) for r in run.agents))
    run.claude = True
    run.claude_runs = [info for info, _ in outcomes]
    run.findings = [f for _, found in outcomes for f in found]
    # What a check guarantees, unless Claude reported it (verified below). One that is already open while its
    # agent's review was skipped (unchanged facts) isn't reported, and so not verified, again.
    add_guaranteed_findings(
        run,
        agents,
        still_open={str(f.get("dedupe_key")) for f in options.open_findings},
        reviewed={(i.agent, i.site) for i in run.claude_runs if i.mode != "skipped"},
    )

    if options.verify:
        pending = [f for f in run.findings if f.verification.status == "pending"]

        async def verify(rf: ReportedFinding) -> None:
            f = rf.finding
            result = next((r for r in run.agents if r.agent == f.agent and r.site == f.site), None)
            verdict = await run_verifier(
                options.api,
                Claim.of(f),
                result.facts if result else None,
                host=run.host,
                ctx=ctx,
                budget=budget,
                gate=gate,
            )
            rf.verification = verdict.verification
            run.claude_runs.append(verdict.info)

        await asyncio.gather(*(verify(f) for f in pending))

    total = Usage()
    for info in run.claude_runs:
        if info.usage:
            u = info.usage
            total.input_tokens += u["input_tokens"]
            total.output_tokens += u["output_tokens"]
            total.cache_read_tokens += u["cache_read_tokens"]
            total.cache_write_tokens += u["cache_write_tokens"]
            total.cost_usd += u["cost_usd"]
            total.calls += u["calls"]
    run.claude_usage = total.dump()


FINDING_SCHEMA = strict_schema(FindingOut)
VERDICT_SCHEMA = strict_schema(Verdict)


def specialist_payload(
    run: HostRun, result: AgentResult, d: AgentDefinition, options: ClaudeOptions, mode: Mode
) -> dict[str, Any]:
    tasks = {
        "baseline": "Baseline review: this is the first snapshot of your area on this host (or your agent "
        "version changed). Review all the facts and report what matters.",
        "deep": "Deep review (the planner asked for one, see <plan_reason>): review all the facts again, not "
        "only what changed (in <changes>, if anything did). Something may have been planted before the last "
        "run or missed by it. Report every problem you find, and open findings that are still present.",
    }
    task = tasks.get(
        mode,
        "Change review: review what changed since the last run (in <changes>), using the current facts for "
        "context. Report new problems, and open findings that are still present.",
    )
    settings = d.effective_settings(options.overrides.get(d.name))
    payload: dict[str, Any] = {
        "task": task,
        "context": {
            "host": run.host,
            "site": result.site,
            "agent": d.name,
            "agent_version": d.version,
            "scan_user": run.scan_user,
            "read_only_sudo": run.sudo_ok,
            "collection_warnings": result.warnings,
        },
        "settings": settings,
        "rules": rules_summary(d),
        "change_events": [e.model_dump(mode="json") for e in run.change_events],
        "open_findings": [
            f for f in options.open_findings if f.get("agent") == d.name and f.get("site") == result.site
        ],
    }
    if mode == "deep":
        payload["plan_reason"] = options.deep_reasons.get(d.name, "")
    if mode in ("changes", "deep") and result.changes:
        payload["changes"] = compact([c.model_dump(mode="json") for c in result.changes], max_list=300)
    payload["facts"] = compact(result.facts or {})
    return payload


@dataclass(frozen=True)
class Claim:
    """What the verifier sees of a finding: the claim and its evidence, never the specialist's reasoning."""

    dedupe_key: str
    agent: str
    site: str | None
    severity: str
    title: str
    evidence: list[str]

    @classmethod
    def of(cls, f: Finding) -> Claim:
        return cls(f.dedupe_key, f.agent, f.site, f.severity.value, f.title, list(f.evidence))

    @property
    def subject(self) -> str:
        return self.dedupe_key.split(":", 4)[-1]


@dataclass
class VerifierOutcome:
    verification: Verification
    info: ClaudeRunInfo
    checked: list[str] = field(default_factory=list)


async def run_verifier(
    api: MessagesAPI,
    claim: Claim,
    facts: dict[str, Any] | None,
    *,
    host: str,
    ctx: CheckContext | None,
    budget: Budget,
    gate: asyncio.Semaphore | None = None,
) -> VerifierOutcome:
    """One verifier opinion. `ctx` None = no read-only tool (it judges the claim and observed facts only).
    Never raises: a failure is an `error` verification with the reason."""
    v = verifier()
    info = ClaudeRunInfo(agent=v.name, site=claim.site, mode="changes")
    if budget.exhausted:
        reason = "run budget reached before verification"
        info.mode, info.reason = "skipped", reason
        return VerifierOutcome(Verification(status="error", reason=reason), info)
    call = AgentCall(
        model=v.model or "", effort=v.effort, instructions=v.instructions, max_tool_calls=v.max_tool_calls
    )
    try:
        async with gate or asyncio.Semaphore(1):
            outcome = await run_agent(
                api,
                call,
                claim_payload(host, claim, facts),
                Verdict,
                ctx=ctx,
                budget=budget,
                schema=VERDICT_SCHEMA,
            )
    except (ClaudeError, anthropic.APIError) as exc:
        reason = f"{type(exc).__name__}: {exc}"[:500]
        info.error = reason
        return VerifierOutcome(Verification(status="error", reason=reason, verifier_version=v.version), info)
    verdict = outcome.answer
    info.model, info.served_by = outcome.model, outcome.served_by
    info.tool_calls, info.usage = outcome.tool_calls, outcome.usage.dump()
    info.assessment = f"{verdict.verdict}: {claim.dedupe_key}"
    verification = Verification(status=verdict.verdict, reason=verdict.reason, verifier_version=v.version)
    return VerifierOutcome(verification, info, list(verdict.checked))


def claim_payload(host: str, claim: Claim, facts: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "task": "Verify this finding independently and return your verdict.",
        "context": {"host": host, "site": claim.site, "reported_by_agent": claim.agent},
        "claim": {"title": claim.title, "subject": claim.subject, "severity": claim.severity},
        "evidence": claim.evidence,
        "observed_facts": observed_facts(facts, claim.subject),
    }


def verifier_payload(run: HostRun, rf: ReportedFinding) -> dict[str, Any]:
    f = rf.finding
    result = next((r for r in run.agents if r.agent == f.agent and r.site == f.site), None)
    return claim_payload(run.host, Claim.of(f), result.facts if result else None)


def observed_facts(facts: dict[str, Any] | None, subject: str, limit: int = 8) -> list[dict[str, Any]]:
    """The entries of the reporting agent's collected facts that mention the claim's subject: what
    handscheck's checks observed (some of it, like WordPress database rows, the verifier can't re-read)."""
    needle = subject.strip()
    if not facts or len(needle) < 3:
        return []
    found: list[dict[str, Any]] = []

    def walk(node: Any, path: str) -> None:
        if len(found) >= limit:
            return
        if isinstance(node, dict):
            leaves = [v for v in node.values() if not isinstance(v, dict | list)]
            if any(needle == str(v) or (len(needle) > 8 and needle in str(v)) for v in leaves):
                found.append({"path": path or "$", "value": compact(node, max_list=10)})
                return
            for k, v in node.items():
                walk(v, f"{path}.{k}" if path else str(k))
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")
        elif isinstance(node, str) and (needle == node or (len(needle) > 8 and needle in node)):
            found.append({"path": path, "value": node})

    walk(facts, "")
    return found


def rules_summary(d: AgentDefinition) -> list[dict[str, Any]]:
    out = []
    for path in d.rule_paths():
        try:
            data = yaml.safe_load(path.read_text())
        except (OSError, yaml.YAMLError):
            continue
        for rule in (data or {}).get("rules", []):
            out.append({k: rule.get(k) for k in ("id", "description", "severity") if k in rule})
    return out
