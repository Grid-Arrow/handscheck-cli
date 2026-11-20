"""The `remediate` job: apply (or roll back) one approved fix on one host.

Order: refuse without an approval or when the plan hash doesn't match → connect with the job's key (the
remediate key, the fix user) and `PlanPolicy` → HTTP baseline of the host's sites, from the worker →
precheck (stale: stop, nothing changed) → apply → verify + baseline again → roll back on any problem. Every
command is in the outcome with its exit status and an output hash, for the audit log. A remediate job is
never retried by the control plane: if this worker dies halfway, people check the host."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from handscheck import __version__
from handscheck.agents._framework.services import HttpProber
from handscheck.contracts import Job, RemediationOutcome, Result, ResultStatus, SiteStatus
from handscheck.remediation.actions import ACTIONS
from handscheck.remediation.base import Action, Executor, FixContext, FixFailed, FixRunner, Stale, plan_sha256
from handscheck.remediation.policy import PlanPolicy
from handscheck.ssh.policy import PolicyViolation
from handscheck.ssh.runner import SSHError, SSHRunner, SSHTarget

MAX_BASELINE_SITES = 30


async def run_remediate(
    job: Job, *, http: HttpProber | None, timeout: float = 60.0, runner: FixRunner | None = None
) -> Result:
    started = datetime.now(UTC)
    outcome, fingerprint = await _remediate(job, http=http, timeout=timeout, runner=runner)
    failed = outcome.status in ("failed", "refused")
    return Result(
        job_id=job.job_id,
        worker_version=__version__,
        status=ResultStatus.failed if failed else ResultStatus.ok,
        started_at=started,
        finished_at=datetime.now(UTC),
        remediation=outcome,
        errors=[outcome.message] if failed else [],
        host_key_fingerprint=fingerprint,
    )


def _refusal(job: Job) -> tuple[Action[Any], Any] | str:
    r = job.remediate
    if r is None or job.host is None:
        return "not a remediate job"
    if not r.approval.user.strip():
        return "refused: the fix has no approval"
    action = ACTIONS.get(r.fix.action)
    if action is None:
        return f"refused: this worker has no action {r.fix.action!r}"
    if action.version != r.fix.action_version:
        return (
            f"refused: {action.name} is v{action.version} here, the approval is for v{r.fix.action_version}"
        )
    try:
        params = action.params(r.fix.params)
    except ValueError as exc:
        return f"refused: invalid parameters: {exc}"[:500]
    if plan_sha256(action.name, action.version, params.model_dump(mode="json")) != r.fix.plan_sha256:
        return "refused: the plan doesn't match what was approved"
    if r.mode not in ("apply", "rollback"):
        return f"refused: unknown mode {r.mode!r}"
    if r.mode == "rollback" and r.rollback_data is None:
        return "refused: nothing saved to roll back"
    return action, params


async def _remediate(
    job: Job, *, http: HttpProber | None, timeout: float, runner: FixRunner | None
) -> tuple[RemediationOutcome, str | None]:
    checked = _refusal(job)
    if isinstance(checked, str):
        return RemediationOutcome(status="refused", message=checked), None
    action, params = checked
    assert job.remediate is not None and job.host is not None  # noqa: S101 - checked in _refusal
    r = job.remediate
    ctx = FixContext(proposal_id=r.proposal_id)
    policy = PlanPolicy(allowed=frozenset(c.line() for c in action.commands(params, ctx)))
    ssh = runner or SSHRunner(
        SSHTarget.from_host_target(job.host), policy=policy, connect_timeout=timeout, default_timeout=timeout
    )
    ex = Executor(ssh, policy, http, job.host.address)
    sites = r.sites[:MAX_BASELINE_SITES]
    outcome = RemediationOutcome(status="failed", message="")
    try:
        outcome.baseline_before = await _baseline(ex, sites)
        if r.mode == "rollback":
            ex.phase = "rollback"
            await action.rollback(ex, params, ctx, r.rollback_data or {})
            outcome.status, outcome.message = "succeeded", "Rolled back."
        else:
            await action.precheck(ex, params, ctx)
            ex.phase = "apply"
            data = await action.apply(ex, params, ctx)
            outcome.rollback_data = data
            ex.phase = "verify"
            problems = await action.verify(ex, params, ctx)
            outcome.baseline_after = await _baseline(ex, sites)
            problems += _regressions(outcome.baseline_before, outcome.baseline_after)
            if problems:
                outcome.problems = problems
                ex.phase = "rollback"
                await action.rollback(ex, params, ctx, data)
                outcome.status = "rolled_back"
                outcome.message = "Verification failed, so the change was rolled back: " + "; ".join(problems)
            else:
                outcome.status, outcome.message = "succeeded", "Applied and verified."
    except Stale as exc:
        outcome.status, outcome.message = "stale", f"Nothing changed: {exc}"
    except (FixFailed, PolicyViolation, SSHError, OSError) as exc:
        outcome.status, outcome.message = (
            "failed",
            await _after_failure(ex, action, params, ctx, outcome, exc),
        )
    finally:
        fingerprint = getattr(ssh, "host_key_fingerprint", None)
        close = getattr(ssh, "close", None)
        if close is not None:
            await close()
    if not outcome.baseline_after and outcome.status in ("succeeded", "rolled_back"):
        outcome.baseline_after = outcome.baseline_before
    outcome.steps = ex.steps
    outcome.message = outcome.message[:2000]
    return outcome, fingerprint


async def _after_failure(
    ex: Executor,
    action: Action[Any],
    params: Any,
    ctx: FixContext,
    outcome: RemediationOutcome,
    exc: Exception,
) -> str:
    """A step failed after the change may have started: roll back what was saved, and say what happened."""
    message = f"{type(exc).__name__}: {exc}"
    if ex.phase in ("apply", "verify") and outcome.rollback_data:
        ex.phase = "rollback"
        try:
            await action.rollback(ex, params, ctx, outcome.rollback_data)
            return f"{message}. The change was rolled back."
        except Exception as again:  # reported to people, who check the host
            return f"{message}. Rolling back also failed ({again}): check the host."
    if ex.phase == "apply":
        return f"{message}. The fix stopped partway: check the host."
    return message


async def _baseline(ex: Executor, sites: list[str]) -> list[SiteStatus]:
    out = []
    for site in sites:
        response = await ex.get(site, "/")
        out.append(SiteStatus(site=site, status=response.status, error=response.error))
    return out


def _regressions(before: list[SiteStatus], after: list[SiteStatus]) -> list[str]:
    """A site that answered (below 500) before the fix and errors or fails after it."""
    was = {s.site: s for s in before}
    problems = []
    for now in after:
        old = was.get(now.site)
        if old is None or old.status is None or old.status >= 500:
            continue
        if now.status is None or now.status >= 500:
            problems.append(f"{now.site} answered {old.status} before and {now.status or now.error} after")
    return problems
