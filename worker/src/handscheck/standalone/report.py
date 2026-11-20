"""`hc report`: open findings, recent runs (with trends) and change events, from the standalone state, as data
and as Markdown (the terminal renders the same Markdown)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from handscheck.agents._framework.findings import SEVERITY_ORDER
from handscheck.standalone.state import StandaloneState, StoredFinding

RUNS_SHOWN = 10


class RunRow(BaseModel):
    id: int
    finished_at: datetime
    status: str
    duration_s: float
    changes: int
    change_events: int
    findings: int
    confirmed: int
    rejected: int
    cost_usd: float


class HostSection(BaseModel):
    host: str
    last_run: RunRow | None = None
    runs: list[RunRow] = Field(default_factory=list)
    change_events: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[StoredFinding] = Field(default_factory=list)


class Report(BaseModel):
    generated_at: datetime
    hosts: list[HostSection]
    org_findings: list[StoredFinding] = Field(default_factory=list)
    totals: dict[str, int] = Field(default_factory=dict)


def build_report(state: StandaloneState, *, hosts: list[str], now: datetime) -> Report:
    sections = []
    for name in hosts:
        section = HostSection(host=name)
        for stored in state.recent_runs(name, limit=RUNS_SHOWN):
            data = stored.data
            metrics = {m["name"]: m["value"] for m in data.get("metrics", []) if m.get("site") is None}
            row = RunRow(
                id=stored.id,
                finished_at=stored.finished_at,
                status=stored.status,
                duration_s=float(metrics.get("run.duration_s", 0.0)),
                changes=int(metrics.get("run.changes", 0)),
                change_events=len(data.get("change_events", [])),
                findings=len(data.get("findings", [])),
                confirmed=int(metrics.get("findings.confirmed", 0)),
                rejected=int(metrics.get("findings.rejected", 0)),
                cost_usd=float(metrics.get("claude.cost_usd", 0.0)),
            )
            section.runs.append(row)
            section.change_events += data.get("change_events", [])
        section.last_run = section.runs[0] if section.runs else None
        section.change_events = section.change_events[:20]
        section.findings = sorted(
            state.list_findings(host=name), key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.dedupe_key)
        )
        sections.append(section)
    org = state.list_findings(host="*")
    every = [f for s in sections for f in s.findings] + org
    totals = {sev: sum(1 for f in every if f.severity == sev) for sev in SEVERITY_ORDER}
    totals["unverified_medium_plus"] = sum(
        1
        for f in every
        if SEVERITY_ORDER.get(f.severity, 0) >= 2 and _verification(f) not in ("confirmed", "rejected")
    )
    return Report(generated_at=now, hosts=sections, org_findings=org, totals=totals)


def _verification(f: StoredFinding) -> str:
    return str((f.data.get("verification") or {}).get("status", "pending"))


def render_markdown(report: Report) -> str:
    lines = [f"# handscheck report — {report.generated_at:%Y-%m-%d %H:%M} UTC", ""]
    t = report.totals
    lines.append(
        f"Open findings: **{t.get('critical', 0)} critical**, **{t.get('high', 0)} high**, "
        f"{t.get('medium', 0)} medium, {t.get('low', 0)} low, {t.get('info', 0)} info "
        f"({t.get('unverified_medium_plus', 0)} medium+ not verified)."
    )
    lines.append("")
    if report.org_findings:
        lines += ["## Across hosts", ""] + _findings_table(report.org_findings) + [""]
    for section in report.hosts:
        lines.append(f"## {section.host}")
        lines.append("")
        if section.last_run is None:
            lines += ["No runs yet.", ""]
            continue
        r = section.last_run
        lines.append(
            f"Last run {r.id}: {r.status}, {r.finished_at:%Y-%m-%d %H:%M} UTC, {r.duration_s:.0f}s, "
            f"${r.cost_usd:.2f}."
        )
        lines.append("")
        lines += (
            ["### Open findings", ""]
            + (_findings_table(section.findings) if section.findings else ["None."])
            + [""]
        )
        if section.change_events:
            lines += ["### Recent changes", ""]
            lines += [
                f"- {e.get('observed_at', '')[:16]} {e.get('kind')}: {e.get('summary')}"
                for e in section.change_events
            ]
            lines.append("")
        lines += [
            "### Trend (recent runs)",
            "",
            "| run | finished | status | changes | findings | confirmed | rejected | cost |",
        ]
        lines.append("|---|---|---|---|---|---|---|---|")
        for run in section.runs:
            lines.append(
                f"| {run.id} | {run.finished_at:%m-%d %H:%M} | {run.status} | {run.changes} | "
                f"{run.findings} | "
                f"{run.confirmed} | {run.rejected} | ${run.cost_usd:.2f} |"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _findings_table(findings: list[StoredFinding]) -> list[str]:
    rows = ["| severity | finding | status | verified | first seen |", "|---|---|---|---|---|"]
    for f in findings:
        title = f.title.replace("|", "\\|")
        rows.append(
            f"| {f.severity} | {title} (`{f.agent}`{', ' + f.site if f.site else ''}) | {f.status} | "
            f"{_verification(f)} | {f.first_seen:%Y-%m-%d} |"
        )
    return rows
