"""Standalone commands (`hc setup`, `hc host …`). The CLI only parses arguments and prints these results."""

from __future__ import annotations

import asyncio
import getpass
import os
import re
import socket
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import anthropic
from pydantic import BaseModel, Field

from handscheck.agents._framework.check import CheckContext
from handscheck.agents._framework.claude import (
    AgentCall,
    Budget,
    ClaudeError,
    MessagesAPI,
    SDKMessages,
    compact,
    run_agent,
)
from handscheck.agents._framework.definition import load_agent
from handscheck.agents._framework.findings import (
    FindingOut,
    InvestigationOut,
    ReportedFinding,
    Verification,
    strict_schema,
    to_finding,
)
from handscheck.agents._framework.host_settings import CORE_AGENTS
from handscheck.agents._framework.registry import Agent, UnknownAgent, all_agents, get_agents
from handscheck.agents._framework.services import HttpxProber, Services, WordPressOrgChecksums
from handscheck.config import Settings
from handscheck.contracts import (
    ChangeEvent,
    HostAgentState,
    HostTarget,
    Job,
    JobKind,
    ReconInput,
    ReconOutput,
    RunOptions,
)
from handscheck.pipeline.claude_stage import ROLES, ClaudeOptions, run_claude_stage
from handscheck.pipeline.diff import Change
from handscheck.pipeline.run import HostRun, PreviousSnapshot, run_host, snapshot_key
from handscheck.sites.discovery import SiteInventory
from handscheck.ssh.local import LocalRunner
from handscheck.ssh.probe import SUDO_PROBE, ProbeReport, probe_host
from handscheck.ssh.runner import SSHError, SSHRunner, SSHTarget
from handscheck.standalone import report as report_mod
from handscheck.standalone.keys import DEFAULT_KEY_NAME, authorized_keys_line, ensure_key
from handscheck.standalone.report import Report
from handscheck.standalone.state import (
    ACTIVE,
    FindingStatus,
    HostExists,
    StandaloneState,
    StoredFinding,
    StoredHost,
    StoredRun,
)

_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
_USER = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


class StandaloneError(Exception):
    """A user-facing error (bad input, unknown host, missing key)."""


class SetupResult(BaseModel):
    key_path: str
    public_key_path: str
    created: bool
    fingerprint: str
    public_key: str
    authorized_keys_line: str
    state_path: str


def open_state(settings: Settings) -> StandaloneState:
    return StandaloneState.open(settings.state_dir)


def default_key_path(settings: Settings) -> Path:
    return settings.resolved_key_dir() / DEFAULT_KEY_NAME


def setup(settings: Settings, *, from_addrs: list[str] | None = None) -> SetupResult:
    key = ensure_key(settings.resolved_key_dir())
    state = open_state(settings)
    return SetupResult(
        key_path=str(key.path),
        public_key_path=str(key.public_path),
        created=key.created,
        fingerprint=key.fingerprint,
        public_key=key.public_line,
        authorized_keys_line=authorized_keys_line(key.public_line, from_addrs),
        state_path=str(state.path),
    )


def add_host(
    settings: Settings,
    name: str,
    *,
    address: str,
    user: str = "handscheck",
    port: int = 22,
    key_path: Path | None = None,
) -> StoredHost:
    if not _NAME.match(name):
        raise StandaloneError(f"invalid host name {name!r} (lowercase letters, digits, . _ -)")
    if not _USER.match(user):
        raise StandaloneError(f"invalid SSH user {user!r}")
    if not 1 <= port <= 65535:
        raise StandaloneError(f"invalid port {port}")
    if not address or address.startswith("-") or any(c.isspace() for c in address):
        raise StandaloneError(f"invalid address {address!r}")
    key = key_path or default_key_path(settings)
    if not key.is_file():
        raise StandaloneError(f"no SSH key at {key}; run `hc setup` first or pass --key")
    host = StoredHost(
        name=name, address=address, port=port, user=user, key_path=str(key), added_at=datetime.now(UTC)
    )
    try:
        open_state(settings).add_host(host)
    except HostExists as exc:
        raise StandaloneError(f"host {name!r} already exists; remove it first") from exc
    return host


def list_hosts(settings: Settings) -> list[StoredHost]:
    return open_state(settings).list_hosts()


def remove_host(settings: Settings, name: str) -> None:
    if not open_state(settings).remove_host(name):
        raise StandaloneError(f"unknown host {name!r}")


def get_host(settings: Settings, name: str) -> StoredHost:
    host = open_state(settings).get_host(name)
    if host is None:
        raise StandaloneError(f"unknown host {name!r}; see `hc host list`")
    return host


def target_for(host: StoredHost) -> SSHTarget:
    if host.local:
        raise StandaloneError(
            f"{host.name} is this machine, checked with `hc check --local`; it has no SSH connection"
        )
    return SSHTarget(
        name=host.name,
        address=host.address,
        port=host.port,
        user=host.user,
        key_path=Path(host.key_path) if host.key_path else None,
        host_key_fingerprint=host.host_key_fingerprint,
    )


def runner_for(host: StoredHost, *, timeout: float) -> SSHRunner | LocalRunner:
    """A local host runs its commands here (same policy); any other host over SSH."""
    if host.local:
        return LocalRunner(host.name, default_timeout=timeout)
    return SSHRunner(target_for(host), connect_timeout=timeout, default_timeout=timeout)


async def run_host_test_async(settings: Settings, name: str, *, timeout: float = 20.0) -> ProbeReport:
    state = open_state(settings)
    host = get_host(settings, name)
    runner = SSHRunner(target_for(host), connect_timeout=timeout)
    try:
        report = await probe_host(runner, timeout=timeout)  # reports connection errors itself
    finally:
        await runner.close()
    # Trust on first use: pin the key the first time we authenticate successfully.
    if report.ssh_ok and report.host_key_fingerprint and host.host_key_fingerprint is None:
        state.pin_host_key(name, report.host_key_fingerprint)
    state.record_test(name, report.ok)
    return report


def run_host_test(settings: Settings, name: str, *, timeout: float = 20.0) -> ProbeReport:
    return asyncio.run(run_host_test_async(settings, name, timeout=timeout))


# ── checks, diffs and sites (M2) ─────────────────────────────────────────────


class CheckOutcome(BaseModel):
    run_id: int | None = None
    run: HostRun
    finding_status: dict[str, str] = Field(default_factory=dict)
    """dedupe_key → status after this run (new, open, acknowledged, false_positive)."""
    resolved: list[str] = Field(default_factory=list)


class DiffReport(BaseModel):
    host: str
    run_id: int | None = None
    finished_at: datetime | None = None
    status: str | None = None
    baseline: list[str] = Field(default_factory=list)
    """Agents with no comparable previous snapshot in that run (first run or new agent version)."""
    changes: list[Change] = Field(default_factory=list)
    change_events: list[ChangeEvent] = Field(default_factory=list)


def resolve_agents(names: list[str] | None) -> list[Agent]:
    try:
        return get_agents(names)
    except UnknownAgent as exc:
        raise StandaloneError(str(exc)) from exc


def run_checks(
    settings: Settings,
    agent_names: list[str] | None,
    *,
    host_names: list[str],
    sites: list[str] | None = None,
    timeout: float = 60.0,
    claude: bool = False,
    budget_usd: float | None = None,
    baseline_review: bool = True,
    api: MessagesAPI | None = None,
) -> list[CheckOutcome]:
    """`hc check`: run the agents' deterministic checks on each host, diff, and store the run (read-only).
    `sites` limits site-scoped agents to those sites."""
    agents = resolve_agents(agent_names)
    hosts = [get_host(settings, name) for name in host_names]
    if not hosts:
        raise StandaloneError("no hosts: pass --host NAME or --all (and see `hc host list`)")
    if local := [h.name for h in hosts if h.local]:
        raise StandaloneError(f"{', '.join(local)}: this machine; check it with `hc check --local`")
    if claude and api is None:
        require_claude_credentials()
    budget = settings.claude_budget_usd if budget_usd is None else budget_usd
    return [
        asyncio.run(
            _check_host(
                settings,
                host,
                agents,
                timeout=timeout,
                site_filter=sites or None,
                claude=ClaudeSetup(api=api, budget_usd=budget, baseline_review=baseline_review)
                if claude
                else None,
            )
        )
        for host in hosts
    ]


async def _check_host(
    settings: Settings,
    host: StoredHost,
    agents: list[Agent],
    *,
    timeout: float,
    site_filter: list[str] | None = None,
    claude: ClaudeSetup | None = None,
    fetch_checksums: bool = False,
) -> CheckOutcome:
    state = open_state(settings)
    stored = {s.agent: s for s in state.host_settings(host.name)}
    agents = [a for a in agents if a.name in CORE_AGENTS or stored.get(a.name, _ON).enabled]
    overrides = {name: s.settings for name, s in stored.items() if s.settings}
    previous = {
        snapshot_key(snap.agent, snap.site): PreviousSnapshot(
            version=snap.agent_version, facts=snap.facts, taken_at=snap.taken_at
        )
        for snap in state.latest_snapshots(host.name)
    }
    runner = runner_for(host, timeout=timeout)
    http = HttpxProber()
    # Self-hosted free mode makes no outbound requests unless asked (`--checksums`): the CLI runs on the
    # target itself there (CLAUDE.md safety rule 1). HTTP probes go to the host's own address (127.0.0.1).
    checksums = (
        WordPressOrgChecksums(cache_dir=settings.state_dir / "cache" / "checksums")
        if fetch_checksums or not host.local
        else None
    )
    started = datetime.now(UTC)
    post = None
    client = None
    if claude is not None:
        api: MessagesAPI
        if claude.api is None:
            client = new_client()
            api = SDKMessages(client)
        else:
            api = claude.api
        options = ClaudeOptions(
            api=api,
            budget_usd=claude.budget_usd,
            baseline_review=claude.baseline_review,
            open_findings=[_finding_context(f) for f in state.list_findings(host=host.name)],
            overrides=overrides,
        )
        by_name = {a.name: a for a in agents}

        async def post(ctx: CheckContext, run: HostRun) -> None:
            await run_claude_stage(ctx, run, by_name, options)

    try:
        run = await run_host(
            runner,
            host.name,
            agents,
            address=host.address,
            previous=previous,
            overrides=overrides,
            services=Services(http=http, checksums=checksums),
            site_filter=site_filter,
            timeout=timeout,
            post=post,
        )
    except (SSHError, OSError) as exc:  # OSError: the local runner could not start a command
        run = HostRun(
            host=host.name,
            started_at=started,
            finished_at=datetime.now(UTC),
            status="failed",
            errors=[str(exc)],
        )
    finally:
        await runner.close()
        await http.close()
        if checksums is not None:
            await checksums.close()
        if client is not None:
            await client.close()
    if run.status != "failed" and runner.host_key_fingerprint and host.host_key_fingerprint is None:
        state.pin_host_key(host.name, runner.host_key_fingerprint)  # trust on first use, as in `host test`
    run_id = state.save_run(
        host.name,
        started_at=run.started_at,
        finished_at=run.finished_at,
        status=run.status,
        data=run.model_dump(mode="json"),
        snapshots=[(s.agent, s.site, s.agent_version, s.facts) for s in run.snapshots()],
    )
    outcome = CheckOutcome(run_id=run_id, run=run)
    record_findings(state, host.name, run, run_id, outcome)
    return outcome


# ── self-hosted, free (Track S1) ─────────────────────────────────────────────

LOCAL_ADDRESS = "127.0.0.1"
"""Where a local check's HTTP probes go: the server's own web server, addressed by site name."""


def local_name(name: str | None = None) -> str:
    """The name this machine is stored under: `--name`, else the hostname made into a valid host name."""
    raw = name if name is not None else socket.gethostname().split(".")[0]
    candidate = re.sub(r"[^a-z0-9._-]+", "-", raw.lower()).strip("-._")[:63] or "localhost"
    if not _NAME.match(candidate):
        raise StandaloneError(f"invalid host name {raw!r} (lowercase letters, digits, . _ -); pass --name")
    return candidate


def ensure_local_host(settings: Settings, name: str | None = None) -> StoredHost:
    """Register this machine in the local state (once). A name already used by an SSH host is refused."""
    state = open_state(settings)
    host_name = local_name(name)
    existing = state.get_host(host_name)
    if existing is not None:
        if not existing.local:
            raise StandaloneError(
                f"{host_name!r} is already an SSH host in the local inventory; pass --name to pick another"
            )
        return existing
    host = StoredHost(
        name=host_name,
        address=LOCAL_ADDRESS,
        port=0,
        user=getpass.getuser(),
        added_at=datetime.now(UTC),
        local=True,
    )
    state.add_host(host)
    return host


def refuse_root(allow_root: bool) -> None:
    if os.geteuid() == 0 and not allow_root:
        raise StandaloneError(
            "refusing to run checks as root: run them as the read-only `handscheck` user "
            "(`sudo -u handscheck hc check --local`; install.sh creates it), or pass --allow-root if you "
            "accept running every check with full privileges"
        )


def run_local_check(
    settings: Settings,
    agent_names: list[str] | None,
    *,
    name: str | None = None,
    allow_root: bool = False,
    fetch_checksums: bool = False,
    sites: list[str] | None = None,
    timeout: float = 60.0,
) -> CheckOutcome:
    """`hc check --local`: the deterministic checks on this machine, through the same command policy, stored
    in the local state like any `hc check` (free mode: no Claude, nothing sent anywhere)."""
    refuse_root(allow_root)
    agents = resolve_agents(agent_names)
    host = ensure_local_host(settings, name)
    return asyncio.run(
        _check_host(
            settings,
            host,
            agents,
            timeout=timeout,
            site_filter=sites or None,
            fetch_checksums=fetch_checksums,
        )
    )


def discover_local_sites(
    settings: Settings, *, name: str | None = None, allow_root: bool = False, timeout: float = 60.0
) -> tuple[SiteInventory, HostRun]:
    """`hc sites --local`."""
    refuse_root(allow_root)
    host = ensure_local_host(settings, name)
    return asyncio.run(_discover(host, timeout=timeout))


def record_findings(
    state: StandaloneState, host: str, run: HostRun, run_id: int | None, outcome: CheckOutcome
) -> None:
    """Upsert the run's findings; after a full (baseline) review, resolve what it didn't report again."""
    at = run.finished_at
    for rf in run.findings:
        f = rf.finding
        outcome.finding_status[f.dedupe_key] = state.upsert_finding(
            host,
            key=f.dedupe_key,
            agent=f.agent,
            site=f.site,
            severity=f.severity.value,
            title=f.title,
            data=rf.model_dump(mode="json"),
            run_id=run_id,
            at=at,
        )
    for info in run.claude_runs:
        if info.mode == "baseline" and info.error is None and info.agent != "verifier":
            seen = {
                rf.finding.dedupe_key
                for rf in run.findings
                if rf.finding.agent == info.agent and rf.finding.site == info.site
            }
            outcome.resolved += state.resolve_absent(host, info.agent, info.site, seen, at)


def _finding_context(f: StoredFinding) -> dict[str, Any]:
    return {
        "dedupe_key": f.dedupe_key,
        "agent": f.agent,
        "site": f.site,
        "title": f.title,
        "severity": f.severity,
        "status": f.status,
    }


# ── Claude (M4) ──────────────────────────────────────────────────────────────


@dataclass
class ClaudeSetup:
    api: MessagesAPI | None
    budget_usd: float
    baseline_review: bool = True


def require_claude_credentials() -> None:
    if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
        raise StandaloneError(
            "Claude agents need ANTHROPIC_API_KEY (use your own spend-limited key, in .env); "
            "or run deterministic checks only with --no-agents"
        )


def new_client() -> anthropic.AsyncAnthropic:
    return anthropic.AsyncAnthropic(max_retries=4)


class FindingsView(BaseModel):
    findings: list[StoredFinding]


def list_findings(
    settings: Settings, *, host: str | None = None, include_closed: bool = False
) -> list[StoredFinding]:
    statuses = ("new", "open", "acknowledged", "resolved", "false_positive") if include_closed else ACTIVE
    return open_state(settings).list_findings(host=host, statuses=statuses)


def get_finding(settings: Settings, key: str) -> StoredFinding:
    matches = open_state(settings).get_finding(key)
    if not matches:
        raise StandaloneError(f"no finding {key!r}; see `hc findings list`")
    if len(matches) > 1:
        keys = ", ".join(m.dedupe_key for m in matches[:5])
        raise StandaloneError(f"{key!r} matches {len(matches)} findings ({keys}…); give more of the key")
    return matches[0]


def set_finding_status(
    settings: Settings, key: str, status: FindingStatus, note: str | None = None
) -> StoredFinding:
    finding = get_finding(settings, key)
    open_state(settings).set_finding_status(finding.host, finding.dedupe_key, status, note)
    return get_finding(settings, finding.dedupe_key)


_ON = HostAgentState(agent="-")


class ReconOutcome(BaseModel):
    host: str
    recon: ReconOutput | None
    errors: list[str]
    cost_usd: float
    applied: bool = False


def recon(
    settings: Settings,
    name: str,
    *,
    use_claude: bool = True,
    budget_usd: float | None = None,
    apply: bool = False,
    api: MessagesAPI | None = None,
    timeout: float = 60.0,
) -> ReconOutcome:
    """`hc recon`: map a host read-only and propose agent settings (the worker's recon job, run locally).
    With `apply`, the proposal is stored and later `hc check` runs use it."""
    if use_claude and api is None:
        require_claude_credentials()
    host = get_host(settings, name)
    return asyncio.run(_recon(settings, host, use_claude, budget_usd or 0.5, apply, api, timeout))


async def _recon(
    settings: Settings,
    host: StoredHost,
    use_claude: bool,
    budget_usd: float,
    apply: bool,
    api: MessagesAPI | None,
    timeout: float,
) -> ReconOutcome:
    from handscheck.worker.roles import run_recon  # the worker's handler, unchanged

    state = open_state(settings)
    latest = state.latest_snapshots(host.name)
    sites = next((SiteInventory.model_validate(s.facts) for s in latest if s.agent == "sites"), None)
    job = Job(
        job_id="local-recon",
        task_id="0",
        kind=JobKind.recon,
        host=HostTarget(
            host_id="0",
            name=host.name,
            address=host.address,
            port=host.port,
            user=host.user,
            private_key="(local key file)",  # unused: the runner below uses the stored key path
            host_key_fingerprint=host.host_key_fingerprint,
        ),
        options=RunOptions(use_claude=use_claude, claude_budget_usd=budget_usd),
        recon=ReconInput(
            sites=[s.name for s in sites.sites] if sites else [],
            facts={snapshot_key(s.agent, s.site): s.facts for s in latest if s.agent != "sites"},
            current=state.host_settings(host.name),
        ),
        deadline=datetime.now(UTC),
    )
    client = new_client() if use_claude and api is None else None
    messages_api = api if api is not None else (SDKMessages(client) if client is not None else None)
    runner = SSHRunner(target_for(host), connect_timeout=timeout, default_timeout=timeout)
    try:
        result = await run_recon(job, api=messages_api, timeout=timeout, runner=runner)
    finally:
        await runner.close()
        if client is not None:
            await client.close()
    applied = False
    if apply and result.recon is not None and result.recon.changes:
        state.apply_setting_changes(host.name, result.recon.changes, source="recon")
        applied = True
    return ReconOutcome(
        host=host.name,
        recon=result.recon,
        errors=result.errors,
        cost_usd=result.claude_cost_usd,
        applied=applied,
    )


class Investigation(BaseModel):
    host: str
    question: str
    answer: str
    findings: list[ReportedFinding]
    finding_status: dict[str, str]
    tool_calls: list[dict[str, Any]]
    usage: dict[str, Any]


def investigate(
    settings: Settings,
    name: str,
    question: str,
    *,
    budget_usd: float | None = None,
    api: MessagesAPI | None = None,
    timeout: float = 60.0,
) -> Investigation:
    """`hc investigate`: one read-only Claude investigation of a host; findings it reports are tracked."""
    if api is None:
        require_claude_credentials()
    host = get_host(settings, name)
    return asyncio.run(
        _investigate(settings, host, question, budget_usd or settings.claude_budget_usd, api, timeout)
    )


async def _investigate(
    settings: Settings,
    host: StoredHost,
    question: str,
    budget_usd: float,
    api: MessagesAPI | None,
    timeout: float,
) -> Investigation:
    state = open_state(settings)
    d = load_agent(ROLES / "investigator")
    latest = state.latest_snapshots(host.name)
    payload: dict[str, Any] = {
        "question": question,
        "context": {"host": host.name},
        "open_findings": [_finding_context(f) for f in state.list_findings(host=host.name)],
        "facts": compact({snapshot_key(s.agent, s.site): s.facts for s in latest}, max_list=60),
    }
    client = new_client() if api is None else None
    messages_api: MessagesAPI = (
        api if api is not None else SDKMessages(new_client() if client is None else client)
    )
    runner = SSHRunner(target_for(host), connect_timeout=timeout, default_timeout=timeout)
    try:
        ctx = CheckContext(runner=runner, host=host.name, address=host.address, timeout=timeout)
        sudo = await ctx.run(SUDO_PROBE, sudo=True)
        ctx.sudo_ok = sudo.ok
        outcome = await run_agent(
            messages_api,
            AgentCall(
                model=d.model or "",
                effort=d.effort,
                instructions=d.instructions,
                max_tool_calls=d.max_tool_calls,
            ),
            payload,
            InvestigationOut,
            ctx=ctx,
            budget=Budget(limit_usd=budget_usd),
            schema=strict_schema(InvestigationOut),
        )
    except (ClaudeError, anthropic.APIError) as exc:
        raise StandaloneError(f"investigation failed: {exc}") from exc
    except SSHError as exc:
        raise StandaloneError(str(exc)) from exc
    finally:
        await runner.close()
        if client is not None:
            await client.close()
    reported = [
        ReportedFinding(
            finding=to_finding(item, agent="investigator", version=d.version, host=host.name, site=None),
            confidence=item.confidence,
            host=host.name,
            verification=Verification(status="not_required", reason="from an interactive investigation"),
        )
        for item in outcome.answer.findings
    ]
    now = datetime.now(UTC)
    status = {
        rf.finding.dedupe_key: state.upsert_finding(
            host.name,
            key=rf.finding.dedupe_key,
            agent="investigator",
            site=None,
            severity=rf.finding.severity.value,
            title=rf.finding.title,
            data=rf.model_dump(mode="json"),
            run_id=None,
            at=now,
        )
        for rf in reported
    }
    return Investigation(
        host=host.name,
        question=question,
        answer=outcome.answer.answer,
        findings=reported,
        finding_status=status,
        tool_calls=outcome.tool_calls,
        usage=outcome.usage.dump(),
    )


ORG = "*"
"""Host name under which org-wide (correlator) findings are stored."""


class Correlation(BaseModel):
    assessment: str
    findings: list[ReportedFinding]
    finding_status: dict[str, str]
    usage: dict[str, Any]
    hosts: list[str]


def correlate(
    settings: Settings, *, budget_usd: float | None = None, api: MessagesAPI | None = None
) -> Correlation:
    """`hc correlate`: the correlator over every host's latest login/account facts and open findings."""
    if api is None:
        require_claude_credentials()
    return asyncio.run(_correlate(settings, budget_usd or settings.claude_budget_usd, api))


async def _correlate(settings: Settings, budget_usd: float, api: MessagesAPI | None) -> Correlation:
    state = open_state(settings)
    d = all_agents()["correlator"].definition
    hosts = [h.name for h in state.list_hosts()]
    data: dict[str, Any] = {}
    for name in hosts:
        latest = {snapshot_key(s.agent, s.site): s.facts for s in state.latest_snapshots(name)}
        users = latest.get("users") or {}
        data[name] = {
            "ssh_logins": (users.get("auth") or {}).get("ssh_logins", []),
            "auth_events": (users.get("auth") or {}).get("events", []),
            "wordpress_admins": {
                key.split("@", 1)[1]: facts.get("admins")
                for key, facts in latest.items()
                if key.startswith("wordpress@")
            },
        }
    payload = {
        "task": "Correlate across hosts and sites. Report only cross-host or cross-site patterns.",
        "hosts": compact(data, max_list=200),
        "open_findings": [_finding_context(f) | {"host": f.host} for f in state.list_findings()],
    }
    client = new_client() if api is None else None
    messages_api: MessagesAPI = (
        api if api is not None else SDKMessages(new_client() if client is None else client)
    )
    try:
        outcome = await run_agent(
            messages_api,
            AgentCall(model=d.model or "", effort=d.effort, instructions=d.instructions, max_tool_calls=0),
            payload,
            FindingOut,
            ctx=None,
            budget=Budget(limit_usd=budget_usd),
            schema=strict_schema(FindingOut),
        )
    except (ClaudeError, anthropic.APIError) as exc:
        raise StandaloneError(f"correlation failed: {exc}") from exc
    finally:
        if client is not None:
            await client.close()
    now = datetime.now(UTC)
    reported = [
        ReportedFinding(
            finding=to_finding(item, agent=d.name, version=d.version, host=ORG, site=None),
            confidence=item.confidence,
            host=ORG,
            verification=Verification(status="not_required", reason="cross-host pattern over host findings"),
        )
        for item in outcome.answer.findings
    ]
    status = {
        rf.finding.dedupe_key: state.upsert_finding(
            ORG,
            key=rf.finding.dedupe_key,
            agent=d.name,
            site=None,
            severity=rf.finding.severity.value,
            title=rf.finding.title,
            data=rf.model_dump(mode="json"),
            run_id=None,
            at=now,
        )
        for rf in reported
    }
    return Correlation(
        assessment=outcome.answer.assessment,
        findings=reported,
        finding_status=status,
        usage=outcome.usage.dump(),
        hosts=hosts,
    )


def latest_diff(settings: Settings, name: str) -> DiffReport:
    """`hc diff`: what the most recent run found changed since the previous snapshots."""
    get_host(settings, name)
    runs = open_state(settings).recent_runs(name, limit=1)
    if not runs:
        raise StandaloneError(f"no runs for {name!r} yet: hc check --host {name}")
    return _diff_report(runs[0])


def _diff_report(stored: StoredRun) -> DiffReport:
    run = HostRun.model_validate(stored.data)
    return DiffReport(
        host=stored.host,
        run_id=stored.id,
        finished_at=run.finished_at,
        status=run.status,
        baseline=[r.agent for r in run.results() if r.baseline],
        changes=run.changes,
        change_events=run.change_events,
    )


def discover_sites(settings: Settings, name: str, *, timeout: float = 60.0) -> tuple[SiteInventory, HostRun]:
    """`hc sites`: discover the sites on a host now (read-only; nothing is stored)."""
    host = get_host(settings, name)
    return asyncio.run(_discover(host, timeout=timeout))


async def _discover(host: StoredHost, *, timeout: float) -> tuple[SiteInventory, HostRun]:
    runner = runner_for(host, timeout=timeout)
    try:
        run = await run_host(runner, host.name, [], address=host.address, timeout=timeout)
    except (SSHError, OSError) as exc:
        raise StandaloneError(str(exc)) from exc
    finally:
        await runner.close()
    inventory = run.site_inventory()
    if inventory is None:
        raise StandaloneError(f"site discovery failed on {host.name}: {run.sites.error if run.sites else ''}")
    return inventory, run


def build_report(settings: Settings, *, host: str | None = None) -> Report:
    state = open_state(settings)
    names = [get_host(settings, host).name] if host else [h.name for h in state.list_hosts()]
    return report_mod.build_report(state, hosts=names, now=datetime.now(UTC))
