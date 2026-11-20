"""Role-agent jobs (M5c): verify, investigate, triage and compose; recon and plan (M7c). Each runs one
role agent on the data the control plane put in the job and returns its output section of the Result.
Claude decides; nothing here changes a host (verify, investigate and recon get only `run_readonly`, through
the command policy).

A handler never raises for Claude or host problems: they become errors in the Result (and `error` verdicts),
so the control plane can apply its fallbacks (e.g. the unverified-critical alert, SPEC §9).
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import cache
from typing import Any

import anthropic
from pydantic import BaseModel

from handscheck import __version__
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
    InvestigationOut,
    needs_verification,
    strict_schema,
    to_finding,
)
from handscheck.agents._framework.host_settings import check_overrides, decode_values, validate_change
from handscheck.agents._framework.registry import all_agents
from handscheck.contracts import (
    ComposedMessage,
    Finding,
    FindingVerification,
    FollowUp,
    Investigation,
    Job,
    JobKind,
    PlanItem,
    ReconOutput,
    Result,
    ResultStatus,
    RunPlan,
    SettingChange,
    Severity,
    TriageDecision,
    VerifyVerdict,
)
from handscheck.pipeline.claude_stage import ROLES, Claim, run_verifier, verifier
from handscheck.roles.notifier import ComposeOut
from handscheck.roles.planner import PlanOut
from handscheck.roles.recon import ReconOut
from handscheck.roles.recon.inventory import CHECK as RECON
from handscheck.roles.recon.inventory import ReconInventory, build_inventory, code_changes
from handscheck.roles.triage import TriageOut
from handscheck.sites.discovery import DISCOVERY
from handscheck.ssh.probe import SUDO_PROBE
from handscheck.ssh.runner import SSHError, SSHRunner, SSHTarget
from handscheck.worker.session import SessionRunner

MAX_FOLLOW_UPS = 2


@cache
def role(name: str) -> AgentDefinition:
    return load_agent(ROLES / name)


@dataclass
class RoleRun:
    """What a role handler collects; `finish` turns it into the Result."""

    job: Job
    started: datetime = field(default_factory=lambda: datetime.now(UTC))
    usage: Usage = field(default_factory=Usage)
    errors: list[str] = field(default_factory=list)
    failed: bool = False

    def finish(self, **sections: Any) -> Result:
        status = (
            ResultStatus.failed if self.failed else ResultStatus.partial if self.errors else ResultStatus.ok
        )
        return Result(
            job_id=self.job.job_id,
            worker_version=__version__,
            status=status,
            started_at=self.started,
            finished_at=datetime.now(UTC),
            errors=self.errors,
            claude_input_tokens=self.usage.input_tokens,
            claude_output_tokens=self.usage.output_tokens,
            claude_cost_usd=round(self.usage.cost_usd, 4),
            **sections,
        )


def _no_claude(job: Job, api: MessagesAPI | None) -> str | None:
    if not job.options.use_claude:
        return "the control plane did not allow Claude for this job (budget)"
    if api is None:
        return "this worker has no Anthropic credentials"
    return None


def _call(d: AgentDefinition) -> AgentCall:
    return AgentCall(
        model=d.model or "", effort=d.effort, instructions=d.instructions, max_tool_calls=d.max_tool_calls
    )


async def _connect(
    job: Job, timeout: float, runner: SessionRunner | None
) -> tuple[SessionRunner, CheckContext]:
    assert job.host is not None  # noqa: S101 - checked by the caller
    ssh: SessionRunner = runner or SSHRunner(
        SSHTarget.from_host_target(job.host), connect_timeout=timeout, default_timeout=timeout
    )
    ctx = CheckContext(runner=ssh, host=job.host.name, address=job.host.address, timeout=timeout)
    try:
        sudo = await ctx.run(SUDO_PROBE, sudo=True)
    except BaseException:
        await ssh.close()
        raise
    ctx.sudo_ok = sudo.ok
    return ssh, ctx


# ── verify ─────────────────────────────────────────────────────────────────────────────────────────────


async def run_verify(
    job: Job, *, api: MessagesAPI | None, timeout: float, runner: SessionRunner | None
) -> Result:
    assert job.verify is not None  # noqa: S101 - the Job validator ties the section to the kind
    out = RoleRun(job)
    version = verifier().version

    def all_error(reason: str) -> list[VerifyVerdict]:
        return [
            VerifyVerdict(finding_id=i.finding_id, status="error", reason=reason, verifier_version=version)
            for i in job.verify.findings  # type: ignore[union-attr]
        ]

    problem = _no_claude(job, api)
    if problem is not None:
        out.errors.append(problem)
        out.failed = True
        return out.finish(verdicts=all_error(problem))
    assert api is not None  # noqa: S101

    ssh: SessionRunner | None = None
    ctx: CheckContext | None = None
    host_name = job.host.name if job.host else "(self-hosted)"
    if job.host is not None:
        try:
            ssh, ctx = await _connect(job, timeout, runner)
        except SSHError as exc:
            out.errors.append(str(exc))
            out.failed = True
            return out.finish(verdicts=all_error(f"host unreachable: {exc}"[:500]))

    budget = Budget(limit_usd=job.options.claude_budget_usd)
    gate = asyncio.Semaphore(3)
    try:
        outcomes = await asyncio.gather(
            *(
                run_verifier(
                    api,
                    Claim(i.dedupe_key, i.agent, i.site, i.severity.value, i.title, list(i.evidence)),
                    job.verify.facts.get(i.agent if i.site is None else f"{i.agent}@{i.site}"),
                    host=host_name,
                    ctx=ctx,
                    budget=budget,
                    gate=gate,
                )
                for i in job.verify.findings
            )
        )
    finally:
        if ssh is not None:
            await ssh.close()
    verdicts = []
    for item, outcome in zip(job.verify.findings, outcomes, strict=True):
        if outcome.info.usage:
            out.usage.add(_usage(outcome.info.usage))
        v = outcome.verification
        if v.status == "error":
            out.errors.append(f"{item.dedupe_key}: {v.reason}")
        verdicts.append(
            VerifyVerdict(
                finding_id=item.finding_id,
                status=v.status,
                reason=v.reason or "",
                checked=outcome.checked[:20],
                verifier_version=v.verifier_version or version,
            )
        )
    return out.finish(verdicts=verdicts)


def _usage(d: dict[str, Any]) -> Usage:
    return Usage(
        input_tokens=d["input_tokens"],
        output_tokens=d["output_tokens"],
        cache_read_tokens=d["cache_read_tokens"],
        cache_write_tokens=d["cache_write_tokens"],
        cost_usd=d["cost_usd"],
        calls=d["calls"],
    )


# ── investigate ────────────────────────────────────────────────────────────────────────────────────────


async def run_investigate(
    job: Job, *, api: MessagesAPI | None, timeout: float, runner: SessionRunner | None
) -> Result:
    assert job.investigate is not None and job.host is not None  # noqa: S101
    out = RoleRun(job)
    problem = _no_claude(job, api)
    if problem is not None:
        out.errors.append(problem)
        out.failed = True
        return out.finish()
    assert api is not None  # noqa: S101
    d = role("investigator")
    inv = job.investigate
    payload: dict[str, Any] = {
        "question": inv.question,
        "context": {"host": job.host.name, "why_asked": inv.reason},
        "followed_up_finding": inv.finding.model_dump(mode="json") if inv.finding else None,
        "open_findings": [f.model_dump(mode="json") for f in job.open_findings],
        "facts": compact(inv.facts, max_list=60),
    }
    ssh: SessionRunner | None = None
    try:
        ssh, ctx = await _connect(job, timeout, runner)
        outcome = await run_agent(
            api,
            _call(d),
            payload,
            InvestigationOut,
            ctx=ctx,
            budget=Budget(limit_usd=job.options.claude_budget_usd),
            schema=strict_schema(InvestigationOut),
        )
    except SSHError as exc:
        out.errors.append(str(exc))
        out.failed = True
        return out.finish()
    except (ClaudeError, anthropic.APIError) as exc:
        out.errors.append(f"investigator: {type(exc).__name__}: {exc}"[:500])
        out.failed = True
        return out.finish()
    finally:
        if ssh is not None:
            await ssh.close()
    out.usage.add(outcome.usage)
    findings = []
    for item in outcome.answer.findings:
        f = to_finding(item, agent=d.name, version=d.version, host=job.host.name, site=None)
        status = "pending" if needs_verification(item.severity) else "not_required"
        findings.append(
            Finding.model_validate(
                f.model_dump()
                | {"confidence": item.confidence, "verification": FindingVerification(status=status)}
            )
        )
    return out.finish(findings=findings, investigation=Investigation(answer=outcome.answer.answer))


# ── triage and compose (no host access) ────────────────────────────────────────────────────────────────


async def _structured[T: BaseModel](
    out: RoleRun, api: MessagesAPI, d: AgentDefinition, payload: dict[str, Any], model: type[T]
) -> T | None:
    try:
        outcome = await run_agent(
            api,
            _call(d),
            payload,
            model,
            ctx=None,
            budget=Budget(limit_usd=out.job.options.claude_budget_usd),
            schema=strict_schema(model),
        )
    except (ClaudeError, anthropic.APIError) as exc:
        out.errors.append(f"{d.name}: {type(exc).__name__}: {exc}"[:500])
        out.failed = True
        return None
    out.usage.add(outcome.usage)
    return outcome.answer


async def run_triage(
    job: Job, *, api: MessagesAPI | None, timeout: float, runner: SessionRunner | None
) -> Result:
    assert job.triage is not None  # noqa: S101
    out = RoleRun(job)
    problem = _no_claude(job, api)
    if problem is not None:
        out.errors.append(problem)
        out.failed = True
        return out.finish()
    assert api is not None  # noqa: S101
    t = job.triage
    payload = {
        "task": "Triage these verified findings and return one decision per finding.",
        "findings": [f.model_dump(mode="json") for f in t.findings],
        "related": [f.model_dump(mode="json") for f in t.related],
        "change_events": [e.model_dump(mode="json") for e in t.change_events],
        "chain": t.chain.model_dump(mode="json"),
    }
    answer = await _structured(out, api, role("triage"), payload, TriageOut)
    if answer is None:
        return out.finish()
    wanted = {f.finding_id for f in t.findings}
    related = {r.dedupe_key for r in t.related}
    allow_follow_ups = t.chain.depth < t.chain.max_depth
    decisions: dict[str, TriageDecision] = {}
    for item in answer.decisions:
        if item.finding_id not in wanted or item.finding_id in decisions:
            out.errors.append(
                f"triage: ignored a decision for unknown or repeated finding {item.finding_id!r}"
            )
            continue
        decisions[item.finding_id] = TriageDecision(
            finding_id=item.finding_id,
            severity=Severity(item.severity),
            action=item.action,
            reason=item.reason[:1000],
            related=[k for k in item.related if k in related][:20],
            follow_ups=[
                FollowUp(kind="investigate", question=f.question[:2000], reason=f.reason[:500])
                for f in item.follow_ups[:MAX_FOLLOW_UPS]
            ]
            if allow_follow_ups
            else [],
        )
    missing = wanted - decisions.keys()
    if missing:
        out.errors.append(f"triage: no decision for finding(s) {', '.join(sorted(missing))}")
    return out.finish(triage=list(decisions.values()))


async def run_compose(
    job: Job, *, api: MessagesAPI | None, timeout: float, runner: SessionRunner | None
) -> Result:
    assert job.compose is not None  # noqa: S101
    out = RoleRun(job)
    problem = _no_claude(job, api)
    if problem is not None:
        out.errors.append(problem)
        out.failed = True
        return out.finish()
    assert api is not None  # noqa: S101
    payload = {
        "task": "Write one message per request.",
        "messages": [m.model_dump(mode="json") for m in job.compose.messages],
    }
    answer = await _structured(out, api, role("notifier"), payload, ComposeOut)
    if answer is None:
        return out.finish()
    wanted = {m.alert_id for m in job.compose.messages}
    messages: dict[str, ComposedMessage] = {}
    for item in answer.messages:
        if item.alert_id in wanted and item.alert_id not in messages and item.subject.strip():
            messages[item.alert_id] = ComposedMessage(
                alert_id=item.alert_id, subject=item.subject.strip()[:200], body=item.body.strip()[:8000]
            )
    missing = wanted - messages.keys()
    if missing:
        out.errors.append(f"notifier: no message for alert(s) {', '.join(sorted(missing))}")
    return out.finish(messages=list(messages.values()))


async def run_explain(
    job: Job, *, api: MessagesAPI | None, timeout: float, runner: SessionRunner | None
) -> Result:
    """The watchdog's team alert: one message about the issues in the job."""
    assert job.explain is not None  # noqa: S101
    out = RoleRun(job)
    problem = _no_claude(job, api)
    if problem is not None:
        out.errors.append(problem)
        out.failed = True
        return out.finish()
    assert api is not None  # noqa: S101
    e = job.explain
    payload = {
        "task": "Write one message, with this message_id, about these watchdog issues.",
        "message_id": e.message_id,
        "heading": e.heading,
        "issues": [i.model_dump(mode="json") for i in e.issues],
    }
    answer = await _structured(out, api, role("watchdog"), payload, ComposeOut)
    if answer is None:
        return out.finish()
    item = next((m for m in answer.messages if m.alert_id == e.message_id and m.subject.strip()), None)
    if item is None:
        out.errors.append(f"watchdog: no message for {e.message_id}")
        return out.finish()
    message = ComposedMessage(
        alert_id=e.message_id, subject=item.subject.strip()[:200], body=item.body.strip()[:8000]
    )
    return out.finish(messages=[message])


# ── recon and plan (M7c) ───────────────────────────────────────────────────────────────────────────────


def _definitions() -> dict[str, AgentDefinition]:
    return {name: a.definition for name, a in all_agents().items() if a.definition.scope != "org"}


def describe(inv: ReconInventory) -> str:
    """The profile code writes when Claude doesn't (no budget or no key)."""
    services = ", ".join(f"{s.name}{'' if s.active else ' (inactive)'}" for s in inv.services) or "none found"
    pools = "; ".join(f"{p} as {', '.join(u)}" for p, u in inv.pool_users.items()) or "none found"
    wp = sum(1 for s in inv.sites if s.type == "wordpress")
    return (
        f"{inv.os or 'Unknown OS'}. Web services: {services}. PHP pools: {pools}. "
        f"{len(inv.sites)} site(s), {wp} WordPress."
    )[:2000]


def _changes_from(items: list[Any]) -> tuple[list[SettingChange], list[str]]:
    changes, errors = [], []
    for item in items:
        settings, bad = decode_values([(v.field, v.value_json) for v in item.settings])
        if bad:
            errors.append(f"{item.agent}: setting(s) {', '.join(bad)} weren't valid JSON")
        changes.append(
            SettingChange(agent=item.agent, enabled=item.enabled, settings=settings, reason=item.reason[:500])
        )
    return changes, errors


_WORD = re.compile(r"[a-z0-9][a-z0-9.\-]*[a-z0-9]")


def _words(text: str) -> set[str]:
    return {w for w in _WORD.findall(text.lower()) if len(w) > 3}


def repeats(note: str, earlier: list[str], threshold: float = 0.5) -> bool:
    """Whether `note` mostly restates one of `earlier` (shared words / the shorter note's words): Claude
    sometimes rewords a note code already wrote."""
    words = _words(note)
    for other in earlier:
        theirs = _words(other)
        if words and theirs and len(words & theirs) / min(len(words), len(theirs)) >= threshold:
            return True
    return False


def merge_changes(base: list[SettingChange], extra: list[SettingChange]) -> list[SettingChange]:
    """Code's changes, with Claude's added on top (one change per agent; Claude's values and reason win for
    the fields it names)."""
    merged = {c.agent: c for c in base}
    for c in extra:
        old = merged.get(c.agent)
        if old is None:
            merged[c.agent] = c
            continue
        reason = c.reason if c.reason == old.reason else f"{old.reason} {c.reason}"
        merged[c.agent] = SettingChange(
            agent=c.agent,
            enabled=c.enabled if c.enabled is not None else old.enabled,
            settings={**old.settings, **c.settings},
            reason=reason[:500],
        )
    return list(merged.values())


async def run_recon(
    job: Job, *, api: MessagesAPI | None, timeout: float, runner: SessionRunner | None
) -> Result:
    """Map the host read-only and propose agent settings. Works without Claude (code's proposals only)."""
    assert job.recon is not None and job.host is not None  # noqa: S101
    out = RoleRun(job)
    definitions = _definitions()
    try:
        ssh, ctx = await _connect(job, timeout, runner)
    except SSHError as exc:
        out.errors.append(str(exc))
        out.failed = True
        return out.finish()
    model: str | None = None
    try:
        sites = DISCOVERY.parse(await DISCOVERY.collect(ctx, {}), {}).sites
        ctx.sites = sites
        inv = build_inventory(await RECON.collect(ctx, {}), sites)
        changes, notes = code_changes(inv, definitions, job.recon.current, job.recon.facts)
        profile = describe(inv)
        problem = _no_claude(job, api)
        if problem is not None:
            notes.append(f"Proposed by code only: {problem}.")
        else:
            assert api is not None  # noqa: S101
            d = role("recon")
            payload: dict[str, Any] = {
                "task": "Describe this server and propose the agent settings that fit it.",
                "host": job.host.name,
                "inventory": inv.model_dump(mode="json"),
                "proposed_by_code": [c.model_dump(mode="json") for c in changes],
                "notes_by_code": notes,
                "agents": [
                    {
                        "name": n,
                        "scope": a.scope,
                        "description": a.description,
                        "settings": {k: spec.model_dump(mode="json") for k, spec in a.settings.items()},
                    }
                    for n, a in sorted(definitions.items())
                ],
                "current": [c.model_dump(mode="json") for c in job.recon.current],
                "facts": compact(job.recon.facts, max_list=40),
            }
            try:
                outcome = await run_agent(
                    api,
                    _call(d),
                    payload,
                    ReconOut,
                    ctx=ctx,
                    budget=Budget(limit_usd=job.options.claude_budget_usd),
                    schema=strict_schema(ReconOut),
                )
            except (ClaudeError, anthropic.APIError) as exc:
                out.errors.append(f"recon: {type(exc).__name__}: {exc}"[:500])
            else:
                out.usage.add(outcome.usage)
                extra, problems = _changes_from(outcome.answer.changes)
                out.errors.extend(problems)
                changes = merge_changes(changes, extra)
                profile = outcome.answer.profile.strip()[:2000] or profile
                for note in outcome.answer.notes:
                    note = note.strip()[:500]
                    if note and not repeats(note, notes):
                        notes.append(note)
                model = d.model
    except SSHError as exc:
        out.errors.append(str(exc))
        out.failed = True
        return out.finish()
    finally:
        await ssh.close()
    valid: list[SettingChange] = []
    for change in changes:
        kept, why = validate_change(change, definitions)
        if kept is None:
            out.errors.append(f"recon: dropped a change: {why}")
        else:
            valid.append(kept)
    return out.finish(
        recon=ReconOutput(
            profile=profile,
            inventory=inv.model_dump(mode="json"),
            changes=valid,
            notes=notes[:20],
            model=model,
        ),
        host_key_fingerprint=getattr(ssh, "host_key_fingerprint", None),
    )


async def run_plan(
    job: Job, *, api: MessagesAPI | None, timeout: float, runner: SessionRunner | None
) -> Result:
    """The planner: which agents look deeper in the next scan. No host access; the control plane validates
    the plan again before it queues the scan."""
    assert job.plan is not None  # noqa: S101
    out = RoleRun(job)
    problem = _no_claude(job, api)
    if problem is not None:
        out.errors.append(problem)
        out.failed = True
        return out.finish()
    assert api is not None  # noqa: S101
    p = job.plan
    definitions = _definitions()
    agents = {a.name: a for a in p.agents if a.name in definitions}
    payload = {
        "task": "Plan the next daily scan of this server.",
        "host": p.host,
        "signals": p.signals,
        "agents": [
            {
                "name": a.name,
                "scope": a.scope,
                "description": definitions[a.name].description,
                "current_settings": definitions[a.name].effective_settings(a.settings),
                "settings": {
                    k: spec.model_dump(mode="json") for k, spec in definitions[a.name].settings.items()
                },
            }
            for a in agents.values()
        ],
        "sites": p.sites,
        "open_findings": [f.model_dump(mode="json") for f in p.open_findings],
        "change_events": [e.model_dump(mode="json") for e in p.change_events],
        "profile": p.profile,
        "max_deep": p.max_deep,
    }
    answer = await _structured(out, api, role("planner"), payload, PlanOut)
    if answer is None:
        return out.finish()
    items: list[PlanItem] = []
    deep = 0
    for item in answer.items:
        agent = agents.get(item.agent)
        if agent is None:
            out.errors.append(f"planner: ignored unknown agent {item.agent!r}")
            continue
        if item.site is not None and (agent.scope != "site" or item.site not in p.sites):
            out.errors.append(f"planner: ignored {item.agent} on {item.site!r} (not one of its sites)")
            continue
        settings, bad = decode_values([(v.field, v.value_json) for v in item.settings])
        why = check_overrides(definitions[item.agent], {**agent.settings, **settings})
        if bad or why is not None:
            out.errors.append(f"planner: ignored {item.agent}: {why or 'invalid JSON in ' + ', '.join(bad)}")
            continue
        if item.depth == "deep":
            if deep >= p.max_deep:
                out.errors.append(f"planner: ignored a deep review of {item.agent} (at most {p.max_deep})")
                continue
            deep += 1
        elif not settings:
            continue  # a normal run with nothing changed is what happens anyway
        items.append(
            PlanItem(
                agent=item.agent,
                site=item.site,
                depth=item.depth,
                settings=settings,
                reason=item.reason.strip()[:500],
            )
        )
    return out.finish(plan=RunPlan(summary=answer.summary.strip()[:1000], items=items))


Handler = Callable[..., Any]

ROLE_HANDLERS: dict[JobKind, Handler] = {
    JobKind.verify: run_verify,
    JobKind.investigate: run_investigate,
    JobKind.triage: run_triage,
    JobKind.compose: run_compose,
    JobKind.explain: run_explain,
    JobKind.recon: run_recon,
    JobKind.plan: run_plan,
}
