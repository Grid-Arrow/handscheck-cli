"""Run one control-plane job. `scan` is the `hc check` pipeline with the inputs from the job and no local
state; the role kinds (verify, investigate, triage, compose) are in `roles.py`. `HANDLERS` maps each kind
this worker runs to its handler, and the worker tells the control plane these kinds when it leases, so a new
kind (Track S `analyze`) is a new handler here and a new payload section on the control plane.

The SSH private key from the job stays in memory; nothing about the job is written to disk."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from handscheck import __version__
from handscheck.agents._framework.check import CheckContext
from handscheck.agents._framework.claude import MessagesAPI
from handscheck.agents._framework.registry import Agent, all_agents
from handscheck.agents._framework.services import Services
from handscheck.contracts import (
    ROLE_KINDS,
    AgentReview,
    Finding,
    FindingVerification,
    Job,
    JobKind,
    Result,
    ResultStatus,
)
from handscheck.pipeline.claude_stage import ClaudeOptions, run_claude_stage
from handscheck.pipeline.guaranteed import add_guaranteed_findings
from handscheck.pipeline.run import HostRun, PreviousSnapshot, run_host
from handscheck.remediation.handler import run_remediate
from handscheck.ssh.runner import SSHError, SSHRunner, SSHTarget
from handscheck.worker.roles import ROLE_HANDLERS
from handscheck.worker.session import SessionRunner


class JobError(Exception):
    """The job can't run on this worker (unknown kind, no agents)."""


def agents_for(job: Job) -> tuple[list[Agent], list[str]]:
    """The job's agents that this worker has and that run on a host, plus errors for the rest."""
    known = all_agents()
    agents, errors = [], []
    for run in job.agents:
        agent = known.get(run.name)
        if agent is None:
            errors.append(f"agent {run.name} is not in this worker's catalog")
        elif agent.definition.version != run.version:
            have = agent.definition.version
            errors.append(f"agent {run.name}: the job asks for v{run.version}, this worker has v{have}")
        elif agent.definition.scope == "org":
            errors.append(f"agent {run.name} is org-scoped and doesn't run in a host scan")
        else:
            agents.append(agent)
    return agents, errors


def supported_kinds(*, claude: bool) -> list[str]:
    """The job kinds this worker leases: role kinds only with Anthropic credentials."""
    return [k.value for k in HANDLERS if claude or k not in ROLE_KINDS]


async def execute(
    job: Job,
    *,
    services: Services,
    api: MessagesAPI | None,
    timeout: float = 60.0,
    runner: SessionRunner | None = None,
) -> Result:
    """Run a job and build its Result. Never raises for host or Claude problems: they become errors."""
    if job.kind in (JobKind.scan, JobKind.watch):
        return await execute_scan(job, services=services, api=api, timeout=timeout, runner=runner)
    if job.kind == JobKind.remediate:
        return await run_remediate(job, http=services.http, timeout=timeout, runner=runner)  # type: ignore[arg-type]
    handler = ROLE_HANDLERS.get(job.kind)
    if handler is None:
        raise JobError(f"job kind {job.kind} is not supported by this worker")
    result: Result = await handler(job, api=api, timeout=timeout, runner=runner)
    return result


async def execute_scan(
    job: Job,
    *,
    services: Services,
    api: MessagesAPI | None,
    timeout: float = 60.0,
    runner: SessionRunner | None = None,
) -> Result:
    """Run a scan (or watch) job and build its Result. Never raises for host problems: they become a failed
    result. A watch job runs only its (watch) agents, rules only: its guaranteed findings that are already
    open aren't reported again every 15-60 minutes."""
    if job.host is None:
        raise JobError(f"a {job.kind} job needs a host")
    started = datetime.now(UTC)
    agents, errors = agents_for(job)
    previous = {
        key: PreviousSnapshot(version=snap.agent_version, facts=snap.facts, taken_at=snap.taken_at)
        for key, snap in job.previous_snapshots.items()
    }
    overrides = {r.name: r.settings for r in job.agents}
    ssh: SessionRunner = runner or SSHRunner(
        SSHTarget.from_host_target(job.host), connect_timeout=timeout, default_timeout=timeout
    )

    post = None
    if job.kind == JobKind.watch:
        still_open = {f.dedupe_key for f in job.open_findings}
        by_agent = {a.name: a for a in agents}

        async def post(ctx: CheckContext, run: HostRun) -> None:
            add_guaranteed_findings(run, by_agent, still_open=still_open, reviewed=set())

    elif job.options.use_claude and api is not None:
        options = ClaudeOptions(
            api=api,
            budget_usd=job.options.claude_budget_usd,
            baseline_review=job.options.baseline_review,
            verify=job.options.verify,
            open_findings=[f.model_dump(mode="json") for f in job.open_findings],
            overrides=overrides,
            deep={r.name: frozenset(r.review_sites) for r in job.agents if r.review_all},
            deep_reasons={r.name: r.review_reason or "" for r in job.agents if r.review_all},
        )
        by_name = {a.name: a for a in agents}

        async def post(ctx: CheckContext, run: HostRun) -> None:
            await run_claude_stage(ctx, run, by_name, options)

    elif job.options.use_claude:
        errors.append("the job asked for Claude, but this worker has no Anthropic credentials")

    try:
        run = await run_host(
            ssh,
            job.host.name,
            agents,
            address=job.host.address,
            previous=previous,
            overrides=overrides,
            services=services,
            site_exclude=job.disabled_sites,
            timeout=timeout,
            post=post,
        )
    except SSHError as exc:
        run = HostRun(
            host=job.host.name,
            started_at=started,
            finished_at=datetime.now(UTC),
            status="failed",
            errors=[str(exc)],
        )
    finally:
        await ssh.close()
    run.errors = errors + run.errors
    return to_result(job, run, host_key_fingerprint=ssh.host_key_fingerprint)


def to_result(job: Job, run: HostRun, *, host_key_fingerprint: str | None) -> Result:
    findings = [
        Finding.model_validate(
            rf.finding.model_dump()
            | {
                "confidence": rf.confidence,
                "verification": FindingVerification.model_validate(rf.verification.model_dump()),
            }
        )
        for rf in run.findings
    ]
    usage = run.claude_usage
    return Result(
        job_id=job.job_id,
        worker_version=__version__,
        status=ResultStatus(run.status if run.status in ("ok", "partial", "failed") else "partial"),
        started_at=run.started_at,
        finished_at=run.finished_at,
        snapshots=run.snapshots(),
        change_events=run.change_events,
        findings=findings,
        metrics=run.metrics,
        reviews=[
            AgentReview(agent=i.agent, site=i.site, mode=i.mode, error=i.error)
            for i in run.claude_runs
            if i.agent != "verifier"
        ],
        errors=run.errors,
        host_key_fingerprint=host_key_fingerprint,
        claude_input_tokens=int(usage.get("input_tokens", 0)),
        claude_output_tokens=int(usage.get("output_tokens", 0)),
        claude_cost_usd=float(usage.get("cost_usd", 0.0)),
    )


HANDLERS: dict[JobKind, Any] = {
    JobKind.scan: execute_scan,
    JobKind.watch: execute_scan,
    JobKind.remediate: run_remediate,
    **ROLE_HANDLERS,
}
