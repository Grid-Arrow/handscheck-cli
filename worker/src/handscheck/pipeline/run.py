"""Run agents for one host: sudo probe → site discovery → host agents → site agents (once per site) → diff →
change events → metrics.

The same code runs standalone (`hc check`, previous snapshots from SQLite) and, from M5, in `hc worker`
(previous snapshots from the job). M2 and M3 run the deterministic checks only; Claude runs on the diff in M4.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError

from handscheck import __version__
from handscheck.agents._framework.check import Check, CheckContext, CommandRunner, Facts
from handscheck.agents._framework.definition import AgentDefinitionError
from handscheck.agents._framework.findings import ClaudeRunInfo, ReportedFinding
from handscheck.agents._framework.registry import Agent
from handscheck.agents._framework.services import Services
from handscheck.contracts import ChangeEvent, Metric, Snapshot
from handscheck.pipeline.diff import Change, diff_views
from handscheck.pipeline.events import change_events
from handscheck.pipeline.guaranteed import add_guaranteed_findings
from handscheck.sites.discovery import DISCOVERY, DISCOVERY_VERSION, Site, SiteInventory
from handscheck.ssh.policy import PolicyViolation
from handscheck.ssh.probe import SUDO_PROBE
from handscheck.ssh.runner import SSHError

log = logging.getLogger(__name__)

SITES = "sites"
AgentStatus = Literal["ok", "partial", "failed"]


def snapshot_key(agent: str, site: str | None = None) -> str:
    """How previous snapshots are keyed: `system`, or `malware@alpha.example.com` for site agents."""
    return agent if site is None else f"{agent}@{site}"


class PreviousSnapshot(BaseModel):
    version: int
    facts: dict[str, Any]
    taken_at: datetime | None = None


class AgentResult(BaseModel):
    agent: str
    version: int
    site: str | None = None
    status: AgentStatus
    duration_s: float
    baseline: bool = False
    """No comparable previous snapshot (first run, or the agent version changed): no diff."""
    facts: dict[str, Any] | None = None
    changes: list[Change] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    error: str | None = None
    metrics: dict[str, float] = Field(default_factory=dict)

    @property
    def key(self) -> str:
        return snapshot_key(self.agent, self.site)

    @property
    def label(self) -> str:
        return self.agent if self.site is None else f"{self.agent} @ {self.site}"


class HostRun(BaseModel):
    host: str
    worker_version: str = __version__
    started_at: datetime
    finished_at: datetime
    status: AgentStatus
    scan_user: str | None = None
    sudo_ok: bool = False
    claude: bool = False
    """Whether Claude agents ran (M4). Always False before M4."""
    sites: AgentResult | None = None
    agents: list[AgentResult] = Field(default_factory=list)
    change_events: list[ChangeEvent] = Field(default_factory=list)
    metrics: list[Metric] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    commands: int = 0
    findings: list[ReportedFinding] = Field(default_factory=list)
    """Claude findings of this run (M4), with their verification."""
    claude_runs: list[ClaudeRunInfo] = Field(default_factory=list)
    claude_usage: dict[str, Any] = Field(default_factory=dict)

    def results(self) -> list[AgentResult]:
        return [*([self.sites] if self.sites else []), *self.agents]

    @property
    def changes(self) -> list[Change]:
        return [c for r in self.results() for c in r.changes]

    def snapshots(self) -> list[Snapshot]:
        """Contract snapshots (one per agent, and per site for site agents, that produced facts)."""
        return [
            Snapshot(agent=r.agent, agent_version=r.version, site=r.site, facts=r.facts)
            for r in self.results()
            if r.facts is not None
        ]

    def site_inventory(self) -> SiteInventory | None:
        if self.sites is None or self.sites.facts is None:
            return None
        return SiteInventory.model_validate(self.sites.facts)


async def run_host(
    runner: CommandRunner,
    host: str,
    agents: list[Agent],
    *,
    address: str | None = None,
    previous: dict[str, PreviousSnapshot] | None = None,
    overrides: dict[str, dict[str, Any]] | None = None,
    services: Services | None = None,
    site_filter: list[str] | None = None,
    site_exclude: list[str] | None = None,
    timeout: float = 60.0,
    post: Callable[[CheckContext, HostRun], Awaitable[None]] | None = None,
) -> HostRun:
    """Run the deterministic checks of `agents` on one host. Raises SSHError if the host can't be reached.

    `previous` is keyed by `snapshot_key(agent, site)`. `site_filter` limits site agents to those sites;
    `site_exclude` skips sites (switched off in the control plane).
    `post` runs after the checks while the connection is still open (the Claude stage, M4).
    """
    previous = previous or {}
    overrides = overrides or {}
    started = datetime.now(UTC)
    t0 = time.monotonic()
    ctx = CheckContext(
        runner=runner, host=host, address=address or host, timeout=timeout, services=services or Services()
    )
    run = HostRun(host=host, started_at=started, finished_at=started, status="ok")

    whoami = await ctx.run(["id", "-un"])
    run.scan_user = ctx.scan_user = whoami.stdout.strip() or None
    sudo = await ctx.run(SUDO_PROBE, sudo=True)
    run.sudo_ok = ctx.sudo_ok = sudo.ok
    if not sudo.ok:
        reason = sudo.sudo_failure or (sudo.stderr.strip()[:200] or f"exit status {sudo.exit_status}")
        run.errors.append(
            f"read-only sudo is not working ({reason}); privileged facts (crontabs, sudoers, keys, auth.log, "
            "some web files) are missing or partial"
        )

    run.sites = await _run_check(ctx, DISCOVERY, SITES, DISCOVERY_VERSION, {}, previous.get(SITES))
    inventory = run.site_inventory()
    sites: list[Site] = inventory.sites if inventory else []
    if site_filter:
        unknown = sorted(set(site_filter) - {s.name for s in sites})
        if unknown:
            run.errors.append(f"site(s) not found on {host}: {', '.join(unknown)}")
        sites = [s for s in sites if s.name in site_filter]
    if site_exclude:
        sites = [s for s in sites if s.name not in set(site_exclude)]
    ctx.sites = sites

    for agent in agents:
        if agent.check is None:
            continue
        d = agent.definition
        try:
            settings = d.effective_settings(overrides.get(agent.name))
        except AgentDefinitionError as exc:
            run.agents.append(
                AgentResult(
                    agent=agent.name, version=d.version, status="failed", duration_s=0, error=str(exc)
                )
            )
            continue
        if d.scope == "host":
            run.agents.append(
                await _run_check(ctx, agent.check, agent.name, d.version, settings, previous.get(agent.name))
            )
        elif d.scope == "site":
            for site in sites:
                result = await _run_check(
                    ctx.for_site(site),
                    agent.check,
                    agent.name,
                    d.version,
                    settings,
                    previous.get(snapshot_key(agent.name, site.name)),
                    site=site.name,
                )
                run.agents.append(result)

    run.change_events = change_events(run.changes, datetime.now(UTC))
    if post is not None:
        await post(ctx, run)  # the Claude stage adds guaranteed findings itself, before verification
    else:
        add_guaranteed_findings(run, {a.name: a for a in agents})
    run.finished_at = datetime.now(UTC)
    run.commands = len(ctx.commands)
    run.metrics = _metrics(run, time.monotonic() - t0)
    statuses = [r.status for r in run.results()]
    if statuses and all(s == "failed" for s in statuses):
        run.status = "failed"
    elif any(s != "ok" for s in statuses) or not run.sudo_ok or run.errors:
        run.status = "partial"
    return run


async def _run_check(
    ctx: CheckContext,
    check: Check[Any],
    name: str,
    version: int,
    settings: dict[str, Any],
    previous: PreviousSnapshot | None,
    *,
    site: str | None = None,
) -> AgentResult:
    t0 = time.monotonic()
    try:
        facts: Facts = await check.run(ctx, settings)
    except SSHError:
        raise
    except PolicyViolation as exc:  # a check bug: never sent to the host
        log.exception("check %s issued a refused command", name)
        return AgentResult(
            agent=name,
            version=version,
            site=site,
            status="failed",
            duration_s=_since(t0),
            error=f"policy: {exc}",
        )
    except Exception as exc:  # a parser bug must not take down the whole host run
        log.exception("check %s failed", name)
        return AgentResult(
            agent=name,
            version=version,
            site=site,
            status="failed",
            duration_s=_since(t0),
            error=f"{type(exc).__name__}: {exc}",
        )

    if previous is not None and previous.version == version:
        try:
            facts = check.carry(previous.facts, facts)
        except Exception as exc:  # carried state is a convenience: a bad old snapshot starts it afresh
            log.exception("check %s could not carry state from its previous snapshot", name)
            facts.warnings.append(f"state from the previous snapshot not carried ({type(exc).__name__})")
    result = AgentResult(
        agent=name,
        version=version,
        site=site,
        status="partial" if facts.warnings else "ok",
        duration_s=_since(t0),
        facts=facts.model_dump(mode="json"),
        warnings=list(facts.warnings),
        metrics=facts.metrics(),
    )
    if previous is None:
        result.baseline = True
    elif previous.version != version:
        result.baseline = True
        result.warnings.append(f"agent version changed (v{previous.version} → v{version}): new baseline")
    else:
        try:
            before = type(facts).model_validate(previous.facts)
        except ValidationError:
            result.baseline = True
            result.warnings.append("previous snapshot doesn't match this version's facts: new baseline")
        else:
            result.changes = diff_views(
                name, before.diff_view(), facts.diff_view(), append_only=type(facts).append_only, site=site
            )
    return result


def _metrics(run: HostRun, duration: float) -> list[Metric]:
    metrics = [
        Metric(name="run.duration_s", value=round(duration, 3), unit="s"),
        Metric(name="run.commands", value=run.commands),
        Metric(name="run.changes", value=len(run.changes)),
        Metric(name="run.change_events", value=len(run.change_events)),
        Metric(name="run.sudo_ok", value=int(run.sudo_ok)),
    ]
    if run.claude_usage:
        metrics.append(
            Metric(name="claude.cost_usd", value=run.claude_usage.get("cost_usd", 0.0), unit="usd")
        )
        metrics.append(Metric(name="claude.calls", value=run.claude_usage.get("calls", 0)))
        metrics.append(Metric(name="claude.input_tokens", value=run.claude_usage.get("input_tokens", 0)))
        metrics.append(Metric(name="claude.output_tokens", value=run.claude_usage.get("output_tokens", 0)))
        metrics.append(Metric(name="findings.reported", value=len(run.findings)))
        for status in ("confirmed", "rejected", "needs_more", "not_required", "error"):
            n = sum(1 for f in run.findings if f.verification.status == status)
            metrics.append(Metric(name=f"findings.{status}", value=n))
    for result in run.results():
        site = result.site
        metrics.append(
            Metric(name=f"{result.agent}.duration_s", value=result.duration_s, unit="s", site=site)
        )
        metrics.append(Metric(name=f"{result.agent}.changes", value=len(result.changes), site=site))
        metrics.extend(
            Metric(name=f"{result.agent}.{k}", value=v, site=site) for k, v in result.metrics.items()
        )
    return metrics


def _since(t0: float) -> float:
    return round(time.monotonic() - t0, 3)
