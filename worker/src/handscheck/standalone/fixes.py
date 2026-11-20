"""`hc fix`: apply a finding's fix from this terminal (standalone, later Track S), never from a control plane.

The person at the terminal is the approval: they see the plan and type the host's name (or pass it with
`--confirm`). The fix then runs exactly as a production `remediate` job does (`remediation.handler`): the
plan hash is checked, it connects as the fix user with the local remediate key through `PlanPolicy`, takes an
HTTP baseline, verifies and rolls back on a problem. Every approval and outcome is appended to the local
`fix_log` (SQLite triggers refuse updates and deletes)."""

from __future__ import annotations

import getpass
import socket
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import BaseModel, SecretStr

from handscheck.agents._framework.services import HttpxProber
from handscheck.config import Settings
from handscheck.contracts import Approval, FixProposal, Job, JobKind, RemediateInput, RemediationOutcome
from handscheck.contracts.models import HostTarget
from handscheck.remediation.handler import run_remediate
from handscheck.standalone.keys import AUTHORIZED_KEYS_OPTIONS, FROM_PLACEHOLDER, ensure_key
from handscheck.standalone.service import (
    StandaloneError,
    get_finding,
    get_host,
    open_state,
)
from handscheck.standalone.state import FixEvent, StoredFinding

REMEDIATE_KEY_NAME = "id_ed25519_handscheck_remediate"
DEFAULT_FIX_USER = "handscheck-fix"
VERIFIED = ("confirmed", "not_required")


class FixSetup(BaseModel):
    key_path: str
    created: bool
    fingerprint: str
    authorized_keys_line: str
    fix_user: str


class FixSummary(BaseModel):
    host: str
    dedupe_key: str
    severity: str
    title: str
    verification: str | None
    fix: FixProposal
    applied: FixEvent | None = None
    """The last successful apply that hasn't been undone."""


class FixResult(BaseModel):
    fix_id: str
    host: str
    dedupe_key: str
    mode: str
    outcome: RemediationOutcome


def remediate_key_path(settings: Settings) -> Path:
    return settings.resolved_key_dir() / REMEDIATE_KEY_NAME


def setup(settings: Settings, *, from_addrs: list[str] | None = None) -> FixSetup:
    """The local remediate key (separate from the scan key) and the line for ~handscheck-fix's
    authorized_keys."""
    key = ensure_key(settings.resolved_key_dir(), REMEDIATE_KEY_NAME)
    sources = ",".join(from_addrs) if from_addrs else FROM_PLACEHOLDER
    return FixSetup(
        key_path=str(key.path),
        created=key.created,
        fingerprint=key.fingerprint,
        authorized_keys_line=f'from="{sources}",{AUTHORIZED_KEYS_OPTIONS} {key.public_line}',
        fix_user=DEFAULT_FIX_USER,
    )


def _fix_of(finding: StoredFinding) -> FixProposal | None:
    raw = (finding.data.get("finding") or {}).get("fix")
    return FixProposal.model_validate(raw) if raw else None


def _verification(finding: StoredFinding) -> str | None:
    status = (finding.data.get("verification") or {}).get("status")
    return str(status) if status else None


def applied(events: list[FixEvent], fix: FixProposal) -> FixEvent | None:
    """The last successful apply of this plan, unless a later undo of it succeeded."""
    current: FixEvent | None = None
    for e in events:
        if e.event != "finished" or e.status != "succeeded" or e.plan_sha256 != fix.plan_sha256:
            continue
        current = e if e.mode == "apply" else (None if current and current.fix_id == e.fix_id else current)
    return current


def list_fixes(settings: Settings, host: str | None = None) -> list[FixSummary]:
    state = open_state(settings)
    out = []
    for f in state.list_findings(host=host):
        fix = _fix_of(f)
        if fix is None:
            continue
        out.append(
            FixSummary(
                host=f.host,
                dedupe_key=f.dedupe_key,
                severity=f.severity,
                title=f.title,
                verification=_verification(f),
                fix=fix,
                applied=applied(state.fix_events(f.host, f.dedupe_key), fix),
            )
        )
    return out


def show(settings: Settings, key: str) -> FixSummary:
    finding = get_finding(settings, key)
    fix = _fix_of(finding)
    if fix is None:
        raise StandaloneError(f"{finding.dedupe_key} has no fix to offer")
    events = open_state(settings).fix_events(finding.host, finding.dedupe_key)
    return FixSummary(
        host=finding.host,
        dedupe_key=finding.dedupe_key,
        severity=finding.severity,
        title=finding.title,
        verification=_verification(finding),
        fix=fix,
        applied=applied(events, fix),
    )


def _approver() -> str:
    try:
        user = getpass.getuser()
    except (KeyError, OSError):
        user = "unknown"
    return f"local:{user}@{socket.gethostname()}"


def _sites(settings: Settings, host: str, finding: StoredFinding) -> list[str]:
    """The host's sites from its latest inventory, for the HTTP baseline (at least the finding's own)."""
    sites: list[str] = []
    for snap in open_state(settings).latest_snapshots(host):
        if snap.agent == "sites":
            sites = [str(s.get("name")) for s in snap.facts.get("sites") or [] if s.get("name")]
    if finding.site and finding.site not in sites:
        sites.insert(0, finding.site)
    return sites


async def run_fix(
    settings: Settings,
    key: str,
    *,
    confirm: str,
    mode: str = "apply",
    fix_user: str = DEFAULT_FIX_USER,
    key_path: Path | None = None,
    allow_unverified: bool = False,
    http: Any = None,
    runner: Any = None,
) -> FixResult:
    """Apply (or undo) the finding's fix. `confirm` must be the host's name: what the person typed."""
    finding = get_finding(settings, key)
    fix = _fix_of(finding)
    if fix is None:
        raise StandaloneError(f"{finding.dedupe_key} has no fix to offer")
    if confirm != finding.host:
        raise StandaloneError(f"not confirmed: type the host name {finding.host!r} to go ahead")
    host = get_host(settings, finding.host)
    if host.local:
        raise StandaloneError(
            f"{host.name} is checked locally (`hc check --local`): fixes there come as runbooks in a later "
            "release (Track S3), not from this command yet"
        )
    if not host.host_key_fingerprint:
        raise StandaloneError(
            f"{host.name}'s host key isn't pinned yet: run `hc host test {host.name}` first"
        )
    state = open_state(settings)
    events = state.fix_events(finding.host, finding.dedupe_key)
    previous = applied(events, fix)
    rollback_data: dict[str, Any] | None = None
    if mode == "apply":
        if previous is not None:
            raise StandaloneError(f"this fix is already applied ({previous.fix_id}); `hc fix undo` first")
        if _verification(finding) not in VERIFIED and not allow_unverified:
            raise StandaloneError(
                f"the finding isn't verified ({_verification(finding) or 'no verification'}); run `hc check` "
                "with agents, or pass --unverified if you have checked it yourself"
            )
    elif mode == "rollback":
        if previous is None:
            raise StandaloneError("nothing to undo: this fix hasn't been applied from here")
        rollback_data = previous.data.get("rollback_data")
        if rollback_data is None:
            raise StandaloneError("nothing saved to undo this fix with")
    else:
        raise StandaloneError(f"unknown mode {mode!r}")

    path = key_path or remediate_key_path(settings)
    if not path.is_file():
        raise StandaloneError(f"no remediate key at {path}; run `hc fix setup` first")
    user = _approver()
    approval = state.log_fix(
        fix_id=previous.fix_id if previous is not None else None,
        host=finding.host,
        dedupe_key=finding.dedupe_key,
        event="approved",
        mode=mode,
        action=fix.action,
        plan_sha256=fix.plan_sha256,
        user=user,
        data=fix.model_dump(mode="json"),
    )
    job = Job(
        job_id=f"standalone-{approval.fix_id}-{approval.id}",
        task_id=str(approval.id),
        kind=JobKind.remediate,
        host=HostTarget(
            host_id=host.name,
            name=host.name,
            address=host.address,
            port=host.port,
            user=fix_user,
            private_key=SecretStr(path.read_text()),
            host_key_fingerprint=host.host_key_fingerprint,
        ),
        remediate=RemediateInput(
            proposal_id=approval.fix_id,
            mode=mode,
            fix=fix,
            approval=Approval(user=user, approved_at=datetime.now(UTC)),
            sites=_sites(settings, host.name, finding),
            rollback_data=rollback_data,
        ),
        deadline=datetime.now(UTC) + timedelta(hours=1),
    )
    prober = http or HttpxProber()
    try:
        result = await run_remediate(job, http=prober, runner=runner)
    finally:
        if http is None:
            await prober.close()
    outcome = result.remediation or RemediationOutcome(status="failed", message="no outcome")
    state.log_fix(
        fix_id=approval.fix_id,
        host=finding.host,
        dedupe_key=finding.dedupe_key,
        event="finished",
        mode=mode,
        action=fix.action,
        plan_sha256=fix.plan_sha256,
        user=user,
        status=outcome.status,
        message=outcome.message,
        data=outcome.model_dump(mode="json"),
    )
    return FixResult(
        fix_id=approval.fix_id, host=finding.host, dedupe_key=finding.dedupe_key, mode=mode, outcome=outcome
    )
