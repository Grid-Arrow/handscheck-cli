"""The `hc` command line. Thin: parse arguments, call into the package, print."""

import asyncio
import json
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.markup import escape
from rich.table import Table

from handscheck import __version__
from handscheck.agents._framework.definition import AgentDefinitionError
from handscheck.agents._framework.findings import SEVERITY_ORDER
from handscheck.agents._framework.registry import all_agents, catalog
from handscheck.config import get_settings
from handscheck.contracts.export import default_contracts_dir, export_schemas
from handscheck.pipeline.run import HostRun
from handscheck.ssh.probe import ProbeReport
from handscheck.standalone import fixes, service
from handscheck.standalone.report import render_markdown
from handscheck.standalone.service import DiffReport, StandaloneError

app = typer.Typer(
    name="hc",
    help="handscheck.ai: read-only security checks for Linux hosts.",
    no_args_is_help=True,
    add_completion=False,
)
contracts_app = typer.Typer(help="Worker ↔ control plane contract (JSON Schemas).", no_args_is_help=True)
app.add_typer(contracts_app, name="contracts")
host_app = typer.Typer(help="Manage the local (standalone) host inventory.", no_args_is_help=True)
app.add_typer(host_app, name="host")
agents_app = typer.Typer(help="The agents shipped with this worker.", no_args_is_help=True)
app.add_typer(agents_app, name="agents")
findings_app = typer.Typer(help="Findings from Claude agents (standalone).", no_args_is_help=True)
app.add_typer(findings_app, name="findings")
fix_app = typer.Typer(
    help="Apply a finding's fix from this terminal (standalone): you see the plan and confirm it here.",
    no_args_is_help=True,
)
app.add_typer(fix_app, name="fix")

console = Console()
err_console = Console(stderr=True)
JsonOpt = Annotated[bool, typer.Option("--json", help="Print machine-readable JSON.")]


def _fail(exc: Exception, as_json: bool, code: int = 1) -> typer.Exit:
    if as_json:
        print(json.dumps({"error": str(exc)}))
    else:
        err_console.print(f"[red]error:[/red] {exc}")
    return typer.Exit(code=code)


@app.command()
def version(as_json: JsonOpt = False) -> None:
    """Print the worker version."""
    if as_json:
        print(json.dumps({"version": __version__}))
    else:
        console.print(f"handscheck {__version__}")


@contracts_app.command("export")
def contracts_export(
    out: Annotated[
        Path | None, typer.Option(help="Output directory (default: the repo's contracts/).")
    ] = None,
    check: Annotated[bool, typer.Option("--check", help="Fail if the committed schemas are stale.")] = False,
    as_json: JsonOpt = False,
) -> None:
    """Regenerate contracts/*.schema.json from the pydantic models."""
    out_dir = out or default_contracts_dir()
    result = export_schemas(out_dir, check=check)
    if as_json:
        print(
            json.dumps({"written": [str(p) for p in result.written], "stale": [str(p) for p in result.stale]})
        )
    elif check and result.stale:
        for path in result.stale:
            console.print(f"[red]stale:[/red] {path}")
        console.print("Run [bold]hc contracts export[/bold] and commit the result.")
    elif result.written:
        for path in result.written:
            console.print(f"wrote {path}")
    else:
        console.print("contracts are up to date")
    if check and result.stale:
        raise typer.Exit(code=1)


@app.command()
def setup(
    from_addr: Annotated[
        list[str] | None,
        typer.Option("--from", help="Source IP(s) for the authorized_keys from= restriction (repeatable)."),
    ] = None,
    as_json: JsonOpt = False,
) -> None:
    """Standalone first run: create the local SSH key and show the authorized_keys line."""
    result = service.setup(get_settings(), from_addrs=from_addr)
    if as_json:
        print(result.model_dump_json())
        return
    verb = "Created" if result.created else "Using existing"
    console.print(f"{verb} key [bold]{result.key_path}[/bold] ({result.fingerprint})")
    console.print(f"State: {result.state_path}\n")
    console.print("On a real host, add this line to [bold]~handscheck/.ssh/authorized_keys[/bold]:")
    console.print(result.authorized_keys_line, soft_wrap=True, highlight=False, markup=False)
    if not from_addr:
        console.print(
            "[dim]Replace the from= placeholder with the IP you connect from (or pass --from IP).[/dim]"
        )
    console.print(
        "\nLab hosts install every .local/keys/*.pub at start: "
        "[bold]docker compose restart lab-wp1 lab-wp2[/bold], then "
        "[bold]hc host add lab-wp1 --address lab-wp1[/bold] and [bold]hc host test lab-wp1[/bold]."
    )


@host_app.command("add")
def host_add(
    name: Annotated[str, typer.Argument(help="Short name, e.g. lab-wp1.")],
    address: Annotated[str, typer.Option(help="Hostname or IP address.")],
    user: Annotated[str, typer.Option(help="SSH user.")] = "handscheck",
    port: Annotated[int, typer.Option(help="SSH port.")] = 22,
    key: Annotated[Path | None, typer.Option(help="Private key file (default: the `hc setup` key).")] = None,
    as_json: JsonOpt = False,
) -> None:
    """Add a host to the local inventory."""
    try:
        host = service.add_host(get_settings(), name, address=address, user=user, port=port, key_path=key)
    except StandaloneError as exc:
        raise _fail(exc, as_json) from exc
    if as_json:
        print(host.model_dump_json())
    else:
        console.print(f"added [bold]{host.name}[/bold] ({host.user}@{host.address}:{host.port})")
        console.print(f"next: hc host test {host.name}")


@host_app.command("list")
def host_list(as_json: JsonOpt = False) -> None:
    """List hosts in the local inventory."""
    hosts = service.list_hosts(get_settings())
    if as_json:
        print(json.dumps([h.model_dump(mode="json") for h in hosts]))
        return
    if not hosts:
        console.print("no hosts yet: hc host add NAME --address ADDRESS")
        return
    table = Table("name", "address", "user", "host key", "last test")
    for h in hosts:
        if h.local:
            table.add_row(h.name, "this machine (--local)", h.user, "-", "-")
            continue
        tested = "never" if h.last_tested_at is None else ("ok" if h.last_test_ok else "failed")
        table.add_row(h.name, f"{h.address}:{h.port}", h.user, h.host_key_fingerprint or "not pinned", tested)
    console.print(table)


@host_app.command("remove")
def host_remove(name: str, as_json: JsonOpt = False) -> None:
    """Remove a host from the local inventory."""
    try:
        service.remove_host(get_settings(), name)
    except StandaloneError as exc:
        raise _fail(exc, as_json) from exc
    if as_json:
        print(json.dumps({"removed": name}))
    else:
        console.print(f"removed {name}")


@host_app.command("test")
def host_test(
    name: str,
    timeout: Annotated[float, typer.Option(help="Seconds per connection/command.")] = 20.0,
    as_json: JsonOpt = False,
) -> None:
    """Check SSH, read-only sudo, OS version, wp-cli and birth-time support (read-only)."""
    try:
        report = service.run_host_test(get_settings(), name, timeout=timeout)
    except StandaloneError as exc:
        raise _fail(exc, as_json) from exc
    if as_json:
        print(json.dumps({**report.model_dump(mode="json"), "ok": report.ok}))
    else:
        _print_probe(report)
    if not report.ok:
        raise typer.Exit(code=1)


def _print_probe(r: ProbeReport) -> None:
    ok, bad, warn = "[green]ok[/green]", "[red]fail[/red]", "[yellow]note[/yellow]"
    table = Table("check", "result", "detail", title=f"{r.host} ({r.address}:{r.port})")
    pin = "pinned, matches" if r.host_key_pinned else "first contact, now pinned"
    table.add_row(
        "ssh",
        ok if r.ssh_ok else bad,
        f"as {r.user}; host key {r.host_key_fingerprint} ({pin})" if r.ssh_ok else "",
    )
    if r.os:
        table.add_row("os", ok, r.os.pretty_name or f"{r.os.name} {r.os.version_id}")
    if r.sudo:
        table.add_row(
            "sudo", ok if r.sudo.ok else bad, "read-only sudo works" if r.sudo.ok else r.sudo.detail
        )
    if r.wp_cli:
        table.add_row(
            "wp-cli",
            ok if r.wp_cli.present else warn,
            f"{r.wp_cli.path} {r.wp_cli.version or ''}" if r.wp_cli.present else "not installed",
        )
    if r.birth_time:
        table.add_row(
            "birth time",
            ok if r.birth_time.supported else warn,
            "stat %W supported" if r.birth_time.supported else "stat %W is 0; using ctime",
        )
    console.print(table)
    for error in r.errors:
        console.print(f"[red]error:[/red] {error}", highlight=False)
    console.print("[green]host test passed[/green]" if r.ok else "[red]host test failed[/red]")


# ── agents, sites, check, diff (M2) ──────────────────────────────────────────

MAX_CHANGES_SHOWN = 60


@agents_app.command("list")
def agents_list(as_json: JsonOpt = False) -> None:
    """List agents (name, version, scope, cadence, model)."""
    try:
        agents = all_agents()
    except AgentDefinitionError as exc:
        raise _fail(exc, as_json) from exc
    if as_json:
        print(json.dumps([a.catalog_entry().model_dump(mode="json") for a in agents.values()]))
        return
    table = Table("agent", "version", "scope", "cadence", "model", "check", "title")
    for a in agents.values():
        d = a.definition
        cadence = d.cadence.full + (" + watch" if d.cadence.watch else "")
        table.add_row(
            d.name, str(d.version), d.scope, cadence, d.model or "", "yes" if a.check else "no", d.title
        )
    console.print(table)


@agents_app.command("export")
def agents_export(
    out: Annotated[
        Path | None, typer.Option(help="Write the catalog JSON to this file instead of stdout.")
    ] = None,
    as_json: JsonOpt = False,
) -> None:
    """Export the agent catalog (contract `catalog.schema.json`) for the control plane."""
    try:
        text = catalog().model_dump_json(indent=2) + "\n"
    except AgentDefinitionError as exc:
        raise _fail(exc, as_json) from exc
    if out is None:
        print(text, end="")
        return
    out.write_text(text)
    if as_json:
        print(json.dumps({"written": str(out)}))
    else:
        console.print(f"wrote {out}")


TimeoutOpt = Annotated[float, typer.Option(help="Seconds per connection/command.")]
BudgetOpt = Annotated[
    float | None,
    typer.Option(
        "--budget-usd", help="Dollar ceiling for Claude calls (default: HANDSCHECK_CLAUDE_BUDGET_USD or 5)."
    ),
]


LocalOpt = Annotated[
    bool,
    typer.Option("--local", help="This machine (self-hosted, free): no SSH, same read-only command policy."),
]
NameOpt = Annotated[
    str | None,
    typer.Option("--name", help="With --local: the name to store this machine under (default: hostname)."),
]
AllowRootOpt = Annotated[
    bool,
    typer.Option("--allow-root", help="With --local: run even as root (default: refused; use `handscheck`)."),
]


@app.command()
def sites(
    host: Annotated[str | None, typer.Option("--host", help="Host name from `hc host list`.")] = None,
    local: LocalOpt = False,
    name: NameOpt = None,
    allow_root: AllowRootOpt = False,
    timeout: TimeoutOpt = 60.0,
    as_json: JsonOpt = False,
) -> None:
    """Discover the sites on a host (Apache/Nginx vhosts, WordPress installs). Read-only; not stored."""
    try:
        if local == (host is not None):
            raise StandaloneError("pass either --host NAME or --local")
        if local:
            inventory, run = service.discover_local_sites(
                get_settings(), name=name, allow_root=allow_root, timeout=timeout
            )
            host = run.host
        else:
            assert host is not None  # noqa: S101 - checked above
            inventory, run = service.discover_sites(get_settings(), host, timeout=timeout)
    except StandaloneError as exc:
        raise _fail(exc, as_json) from exc
    if as_json:
        print(json.dumps({"host": host, **inventory.model_dump(mode="json"), "errors": run.errors}))
        return
    table = Table("site", "type", "server", "document root", "WordPress", "aliases", title=host)
    for site in inventory.sites:
        wp = site.wordpress.version or "?" if site.wordpress else ""
        table.add_row(site.name, site.type, site.server, site.docroot or "", wp, ", ".join(site.aliases))
    console.print(table if inventory.sites else f"no sites found on {host}")
    for line in [*run.errors, *inventory.warnings]:
        console.print(f"[yellow]note:[/yellow] {line}", highlight=False)


@app.command()
def check(
    agents: Annotated[
        list[str] | None, typer.Argument(help="Agents to run (default: all), e.g. system malware wordpress.")
    ] = None,
    host: Annotated[list[str] | None, typer.Option("--host", help="Host name (repeatable).")] = None,
    all_hosts: Annotated[bool, typer.Option("--all", help="Every host in the local inventory.")] = False,
    site: Annotated[
        list[str] | None, typer.Option("--site", help="Only this site for site agents (repeatable).")
    ] = None,
    no_agents: Annotated[
        bool, typer.Option("--no-agents", help="Deterministic checks only, no Claude calls.")
    ] = False,
    budget_usd: BudgetOpt = None,
    baseline_review: Annotated[
        bool,
        typer.Option(
            "--baseline-review/--no-baseline-review",
            help="Run Claude on first snapshots too (default), or only on changes.",
        ),
    ] = True,
    local: LocalOpt = False,
    name: NameOpt = None,
    allow_root: AllowRootOpt = False,
    checksums: Annotated[
        bool,
        typer.Option(
            "--checksums",
            help="With --local: fetch WordPress.org checksums to verify core and plugin files "
            "(outbound HTTPS; off by default, so a local check sends nothing anywhere).",
        ),
    ] = False,
    timeout: TimeoutOpt = 60.0,
    as_json: JsonOpt = False,
) -> None:
    """Run checks on a host (read-only), diff against the previous run, store the snapshot, and (unless
    --no-agents) have Claude agents review what changed, with a verifier on medium+ findings.

    With --local: check this machine (self-hosted, free): the deterministic checks only, no Claude, results
    kept in the local state."""
    settings = get_settings()
    try:
        if local:
            if host or all_hosts:
                raise StandaloneError("--local checks this machine; don't combine it with --host or --all")
            outcomes = [
                service.run_local_check(
                    settings,
                    agents,
                    name=name,
                    allow_root=allow_root,
                    fetch_checksums=checksums,
                    sites=site,
                    timeout=timeout,
                )
            ]
        else:
            if name or allow_root or checksums:
                raise StandaloneError("--name, --allow-root and --checksums only apply with --local")
            names = [h.name for h in service.list_hosts(settings)] if all_hosts else list(host or [])
            outcomes = service.run_checks(
                settings,
                agents,
                host_names=names,
                sites=site,
                timeout=timeout,
                claude=not no_agents,
                budget_usd=budget_usd,
                baseline_review=baseline_review,
            )
    except StandaloneError as exc:
        raise _fail(exc, as_json) from exc
    if as_json:
        print(json.dumps([o.model_dump(mode="json") for o in outcomes]))
    else:
        for outcome in outcomes:
            _print_run(outcome.run, outcome.run_id)
            _print_claude(outcome)
    if any(o.run.status == "failed" for o in outcomes):
        raise typer.Exit(code=1)


@app.command()
def diff(
    host: Annotated[str, typer.Option("--host", help="Host name from `hc host list`.")],
    as_json: JsonOpt = False,
) -> None:
    """What changed since the previous run (from the latest `hc check` of the host)."""
    try:
        report = service.latest_diff(get_settings(), host)
    except StandaloneError as exc:
        raise _fail(exc, as_json) from exc
    if as_json:
        print(report.model_dump_json())
        return
    _print_diff(report)


def _print_run(run: HostRun, run_id: int | None) -> None:
    style = {"ok": "green", "partial": "yellow", "failed": "red"}[run.status]
    duration = (run.finished_at - run.started_at).total_seconds()
    console.print(
        f"\n[bold]{run.host}[/bold] [{style}]{run.status}[/{style}] run {run_id or '-'} · {duration:.1f}s · "
        f"{run.commands} read-only commands · sudo {'ok' if run.sudo_ok else '[red]unavailable[/red]'}"
    )
    for error in run.errors:
        console.print(f"[red]error:[/red] {error}", highlight=False)
    if not run.results():
        return
    table = Table("agent", "v", "status", "time", "changes", "facts")
    for r in run.results():
        status = {
            "ok": "[green]ok[/green]",
            "partial": "[yellow]partial[/yellow]",
            "failed": "[red]failed[/red]",
        }
        changes = "baseline" if r.baseline else str(len(r.changes))
        facts = ", ".join(f"{k} {_num(v)}" for k, v in r.metrics.items()) or (r.error or "")
        table.add_row(r.label, str(r.version), status[r.status], f"{r.duration_s:.1f}s", changes, facts)
    console.print(table)
    for r in run.results():
        for warning in r.warnings:
            console.print(f"[yellow]note:[/yellow] {r.label}: {warning}", highlight=False)
    baseline = all(r.baseline for r in run.results() if r.facts is not None)
    _print_changes(run.changes, run.change_events, baseline=baseline)


def _print_diff(report: DiffReport) -> None:
    console.print(
        f"[bold]{report.host}[/bold] run {report.run_id} ({report.status}, "
        f"{report.finished_at:%Y-%m-%d %H:%M:%S %Z})"
        if report.finished_at
        else f"[bold]{report.host}[/bold]"
    )
    if report.baseline:
        console.print(f"[dim]baseline (nothing to compare yet): {', '.join(report.baseline)}[/dim]")
    _print_changes(report.changes, report.change_events)


def _print_changes(changes: list[Any], events: list[Any], *, baseline: bool = False) -> None:
    for event in events:
        console.print(f"[cyan]event[/cyan] {event.kind}: {event.summary}", highlight=False)
    if not changes:
        console.print("first run: baseline recorded" if baseline else "no changes since the previous run")
        return
    for change in changes[:MAX_CHANGES_SHOWN]:
        mark = {"added": "[green]+[/green]", "removed": "[red]-[/red]", "changed": "[yellow]~[/yellow]"}[
            change.op
        ]
        where = change.agent + (f" @ {change.site}" if change.site else "")
        console.print(f"{mark} {where}: {change.describe()}", highlight=False, soft_wrap=True)
    if len(changes) > MAX_CHANGES_SHOWN:
        console.print(f"… and {len(changes) - MAX_CHANGES_SHOWN} more (use --json)")


SEVERITY_STYLE = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}
VERDICT_STYLE = {"confirmed": "red", "rejected": "green", "needs_more": "yellow", "error": "magenta"}


def _print_claude(outcome: service.CheckOutcome) -> None:
    run = outcome.run
    if not run.claude:
        return
    usage = run.claude_usage
    ran = [i for i in run.claude_runs if i.mode != "skipped" and i.agent != "verifier"]
    skipped = [i for i in run.claude_runs if i.mode == "skipped"]
    console.print(
        f"Claude: {len(ran)} agent run(s), {len(skipped)} skipped, {usage.get('calls', 0)} calls, "
        f"{usage.get('input_tokens', 0) + usage.get('cache_read_tokens', 0):,} in / "
        f"{usage.get('output_tokens', 0):,} out tokens, ${usage.get('cost_usd', 0):.2f}"
    )
    for info in run.claude_runs:
        if info.error:
            where = info.agent + (f" @ {info.site}" if info.site else "")
            console.print(f"[red]error:[/red] {where}: {info.error}", highlight=False)
    if not run.findings:
        console.print("[green]no findings[/green]")
    for rf in sorted(run.findings, key=lambda r: -SEVERITY_ORDER.get(r.finding.severity.value, 0)):
        f = rf.finding
        sev = f.severity.value
        v = rf.verification.status
        state = outcome.finding_status.get(f.dedupe_key, "")
        verdict = (
            f"[{VERDICT_STYLE.get(v, 'dim')}]{v}[/]"
            if v != "not_required"
            else "[dim]not verified (low)[/dim]"
        )
        console.print(
            f"[{SEVERITY_STYLE[sev]}]{sev:>8}[/] {f.title} "
            f"[dim]({f.agent}{' @ ' + f.site if f.site else ''}, {state})[/dim]"
            f" — {verdict}",
            highlight=False,
        )
        if rf.verification.reason and v in ("rejected", "needs_more", "error"):
            console.print(f"           [dim]verifier: {rf.verification.reason[:300]}[/dim]", highlight=False)
    for key in outcome.resolved:
        console.print(f"[green]resolved[/green] {key}", highlight=False)


@findings_app.command("list")
def findings_list(
    host: Annotated[str | None, typer.Option("--host", help="Only this host.")] = None,
    include_closed: Annotated[
        bool, typer.Option("--all", help="Include resolved and false-positive findings.")
    ] = False,
    as_json: JsonOpt = False,
) -> None:
    """Open findings (new, open, acknowledged), most severe first."""
    found = service.list_findings(get_settings(), host=host, include_closed=include_closed)
    found.sort(key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.host, f.dedupe_key))
    if as_json:
        print(json.dumps([f.model_dump(mode="json") for f in found]))
        return
    if not found:
        console.print("no open findings")
        return
    table = Table("severity", "host", "finding", "status", "verified", "key")
    for f in found:
        verified = str((f.data.get("verification") or {}).get("status", ""))
        table.add_row(
            f"[{SEVERITY_STYLE.get(f.severity, '')}]{f.severity}[/]",
            f.host,
            f.title,
            f.status,
            verified,
            f.dedupe_key,
        )
    console.print(table)


@findings_app.command("show")
def findings_show(
    key: Annotated[str, typer.Argument(help="Dedupe key (or a unique prefix).")], as_json: JsonOpt = False
) -> None:
    """One finding with its evidence and verification."""
    try:
        f = service.get_finding(get_settings(), key)
    except StandaloneError as exc:
        raise _fail(exc, as_json) from exc
    if as_json:
        print(f.model_dump_json())
        return
    finding = f.data.get("finding", {})
    verification = f.data.get("verification", {})
    console.print(
        f"[{SEVERITY_STYLE.get(f.severity, '')}]{f.severity}[/] [bold]{f.title}[/bold]  ({f.status})"
    )
    console.print(
        f"{f.dedupe_key}\nhost {f.host}{', site ' + f.site if f.site else ''}; "
        f"first seen {f.first_seen:%Y-%m-%d %H:%M}, last seen {f.last_seen:%Y-%m-%d %H:%M}",
        highlight=False,
    )
    console.print(f"\n{finding.get('summary', '')}", highlight=False)
    for line in finding.get("evidence", []):
        console.print(f"  • {line}", highlight=False, markup=False)
    if finding.get("recommended_action"):
        console.print(f"\n[bold]Recommended:[/bold] {finding['recommended_action']}", highlight=False)
    console.print(
        f"\nverification: {verification.get('status')} {verification.get('reason') or ''}", highlight=False
    )
    if f.note:
        console.print(f"note: {f.note}", highlight=False)


def _set_status(key: str, status: str, note: str | None, as_json: bool) -> None:
    try:
        f = service.set_finding_status(get_settings(), key, status, note)  # type: ignore[arg-type]
    except StandaloneError as exc:
        raise _fail(exc, as_json) from exc
    if as_json:
        print(f.model_dump_json())
    else:
        console.print(f"{f.dedupe_key}: {f.status}", highlight=False)


NoteOpt = Annotated[str | None, typer.Option("--note", help="Why (kept with the finding).")]


@findings_app.command("ack")
def findings_ack(key: str, note: NoteOpt = None, as_json: JsonOpt = False) -> None:
    """Acknowledge a finding (seen; being handled)."""
    _set_status(key, "acknowledged", note, as_json)


@findings_app.command("false-positive")
def findings_false_positive(key: str, note: NoteOpt = None, as_json: JsonOpt = False) -> None:
    """Mark a finding as a false positive (kept for agent tuning)."""
    _set_status(key, "false_positive", note, as_json)


@findings_app.command("resolve")
def findings_resolve(key: str, note: NoteOpt = None, as_json: JsonOpt = False) -> None:
    """Mark a finding as fixed. It reopens if an agent reports it again."""
    _set_status(key, "resolved", note, as_json)


ConfirmOpt = Annotated[
    str | None,
    typer.Option("--confirm", help="The host's name, to confirm without the prompt (scripts, --json)."),
]


@fix_app.command("setup")
def fix_setup(
    from_addr: Annotated[
        list[str] | None, typer.Option("--from", help="Address the fixes connect from (repeatable).")
    ] = None,
    as_json: JsonOpt = False,
) -> None:
    """Create the local remediate key (separate from the scan key) and print the fix user's key line."""
    result = fixes.setup(get_settings(), from_addrs=from_addr)
    if as_json:
        print(result.model_dump_json())
        return
    console.print(f"remediate key: {result.key_path}{' (new)' if result.created else ''}", highlight=False)
    console.print(
        f"\nOn each host, as root: a `{result.fix_user}` user with root sudo, and this line in "
        f'~{result.fix_user}/.ssh/authorized_keys (see deploy/README.md, "Setting up approved fixes"):\n',
        highlight=False,
    )
    console.print(result.authorized_keys_line, highlight=False, markup=False, soft_wrap=True)


@fix_app.command("list")
def fix_list(
    host: Annotated[str | None, typer.Option("--host", help="Only this host.")] = None,
    as_json: JsonOpt = False,
) -> None:
    """Open findings that come with a fix."""
    items = fixes.list_fixes(get_settings(), host)
    if as_json:
        print(json.dumps([i.model_dump(mode="json") for i in items]))
        return
    if not items:
        console.print("No open findings with a fix.")
        return
    table = Table("severity", "host", "fix", "risk", "verified", "state", "finding")
    for i in items:
        table.add_row(
            f"[{SEVERITY_STYLE.get(i.severity, '')}]{i.severity}[/]",
            i.host,
            i.fix.action,
            i.fix.risk,
            i.verification or "-",
            f"applied ({i.applied.fix_id})" if i.applied else "offered",
            escape(i.dedupe_key),
        )
    console.print(table)


def _print_plan(item: fixes.FixSummary) -> None:
    fix = item.fix
    console.print(f"[bold]{escape(fix.summary)}[/bold]", highlight=False)
    console.print(
        f"{item.dedupe_key} on {item.host}: {fix.action} v{fix.action_version}, risk {fix.risk}, "
        f"verification {item.verification or '-'}",
        highlight=False,
        markup=False,
    )
    console.print("\nCommands it may run:")
    for line in fix.commands:
        console.print(f"  {line}", highlight=False, markup=False)
    for title, lines in (("Checked afterwards", fix.verify), ("Undo", fix.rollback), ("Notes", fix.notes)):
        if lines:
            console.print(f"\n{title}:")
            for line in lines:
                console.print(f"  • {line}", highlight=False, markup=False)
    console.print(f"\nplan sha256 {fix.plan_sha256}", highlight=False)


@fix_app.command("show")
def fix_show(
    key: Annotated[str, typer.Argument(help="Dedupe key (or a unique prefix).")], as_json: JsonOpt = False
) -> None:
    """The fix's plan: every command it may run, how it is checked, and how it is undone."""
    try:
        item = fixes.show(get_settings(), key)
    except StandaloneError as exc:
        raise _fail(exc, as_json) from exc
    if as_json:
        print(item.model_dump_json())
        return
    _print_plan(item)
    if item.applied:
        console.print(f"\nApplied ({item.applied.fix_id}, {item.applied.at:%Y-%m-%d %H:%M}).")


def _run_fix(
    key: str, mode: str, confirm: str | None, unverified: bool, fix_user: str, as_json: bool
) -> None:
    settings = get_settings()
    try:
        item = fixes.show(settings, key)
    except StandaloneError as exc:
        raise _fail(exc, as_json) from exc
    if confirm is None:
        if as_json:
            raise _fail(StandaloneError("--json needs --confirm <host name>"), as_json, code=2)
        _print_plan(item)
        verb = "apply this fix to" if mode == "apply" else "undo this fix on"
        confirm = typer.prompt(f"\nTo {verb} {item.host}, type the host name (anything else cancels)")
        if confirm != item.host:
            console.print("Cancelled; nothing changed.")
            raise typer.Exit(code=1)
    try:
        result = asyncio.run(
            fixes.run_fix(
                settings, key, confirm=confirm, mode=mode, fix_user=fix_user, allow_unverified=unverified
            )
        )
    except StandaloneError as exc:
        raise _fail(exc, as_json) from exc
    if as_json:
        print(result.model_dump_json())
    else:
        out = result.outcome
        style = {"succeeded": "green", "rolled_back": "yellow", "stale": "yellow"}.get(out.status, "red")
        console.print(f"\n[{style}]{out.status}[/] ({result.fix_id}): {escape(out.message)}", highlight=False)
        for step in out.steps:
            console.print(
                f"  [{step.phase}] exit {step.exit_status}  {step.command}", highlight=False, markup=False
            )
        if out.status == "succeeded" and mode == "apply":
            console.print(f"\nRun `hc check --host {result.host}` to see the result.")
    if result.outcome.status in ("failed", "refused"):
        raise typer.Exit(code=1)


FixUserOpt = Annotated[str, typer.Option("--fix-user", help="The SSH user fixes run as (root sudo).")]
UnverifiedOpt = Annotated[
    bool, typer.Option("--unverified", help="Allow a finding the verifier hasn't confirmed (you checked it).")
]


@fix_app.command("apply")
def fix_apply(
    key: Annotated[str, typer.Argument(help="Dedupe key (or a unique prefix).")],
    confirm: ConfirmOpt = None,
    unverified: UnverifiedOpt = False,
    fix_user: FixUserOpt = fixes.DEFAULT_FIX_USER,
    as_json: JsonOpt = False,
) -> None:
    """Apply a finding's fix after you confirm it here: baseline, change, verify, undo on a problem."""
    _run_fix(key, "apply", confirm, unverified, fix_user, as_json)


@fix_app.command("undo")
def fix_undo(
    key: Annotated[str, typer.Argument(help="Dedupe key (or a unique prefix).")],
    confirm: ConfirmOpt = None,
    fix_user: FixUserOpt = fixes.DEFAULT_FIX_USER,
    as_json: JsonOpt = False,
) -> None:
    """Undo a fix applied from here, with what it saved."""
    _run_fix(key, "rollback", confirm, False, fix_user, as_json)


@app.command()
def recon(
    host: Annotated[str, typer.Option("--host", help="Host name from `hc host list`.")],
    no_agents: Annotated[
        bool, typer.Option("--no-agents", help="Code's proposals only, no Claude call.")
    ] = False,
    apply: Annotated[
        bool, typer.Option("--apply", help="Store the proposal; later `hc check` runs use it.")
    ] = False,
    budget_usd: BudgetOpt = None,
    timeout: TimeoutOpt = 60.0,
    as_json: JsonOpt = False,
) -> None:
    """Map a host read-only (OS, web server, PHP pools, site owners, logs) and propose agent settings."""
    try:
        out = service.recon(
            get_settings(),
            host,
            use_claude=not no_agents,
            budget_usd=budget_usd,
            apply=apply,
            timeout=timeout,
        )
    except StandaloneError as exc:
        raise _fail(exc, as_json) from exc
    if as_json:
        print(out.model_dump_json())
        return
    if out.recon is None:
        console.print(f"[red]recon failed:[/red] {'; '.join(out.errors)}", highlight=False)
        raise typer.Exit(1)
    console.print(out.recon.profile, highlight=False)
    table = Table("agent", "change", "why", title="Proposed settings")
    for c in out.recon.changes:
        what = [f"{k} = {json.dumps(v)}" for k, v in c.settings.items()]
        if c.enabled is not None:
            what.insert(0, "on" if c.enabled else "off")
        table.add_row(c.agent, "\n".join(what), c.reason)
    console.print(table if out.recon.changes else "No changes: the defaults fit this host.")
    for line in [*out.recon.notes, *out.errors]:
        console.print(f"[yellow]note:[/yellow] {line}", highlight=False)
    if out.applied:
        console.print("[green]Stored.[/green] The next `hc check` uses these settings.")
    elif out.recon.changes:
        console.print("[dim]Run again with --apply to store them.[/dim]")
    console.print(f"[dim]${out.cost_usd:.2f}[/dim]")


@app.command()
def investigate(
    question: Annotated[str, typer.Argument(help='What to find out, e.g. "how did this shell get in?"')],
    host: Annotated[str, typer.Option("--host", help="Host name from `hc host list`.")],
    budget_usd: BudgetOpt = None,
    as_json: JsonOpt = False,
) -> None:
    """Ask a read-only Claude investigator about a host. Findings it reports are tracked."""
    try:
        result = service.investigate(get_settings(), host, question, budget_usd=budget_usd)
    except StandaloneError as exc:
        raise _fail(exc, as_json) from exc
    if as_json:
        print(result.model_dump_json())
        return
    console.print(Markdown(result.answer))
    for rf in result.findings:
        console.print(
            f"[{SEVERITY_STYLE[rf.finding.severity.value]}]{rf.finding.severity.value}[/] {rf.finding.title}",
            highlight=False,
        )
    console.print(
        f"[dim]{len(result.tool_calls)} read-only commands, ${result.usage.get('cost_usd', 0):.2f}[/dim]"
    )


@app.command()
def correlate(budget_usd: BudgetOpt = None, as_json: JsonOpt = False) -> None:
    """Look for patterns across hosts (same account or IP, one campaign) in the latest facts and findings."""
    try:
        result = service.correlate(get_settings(), budget_usd=budget_usd)
    except StandaloneError as exc:
        raise _fail(exc, as_json) from exc
    if as_json:
        print(result.model_dump_json())
        return
    console.print(result.assessment, highlight=False)
    for rf in result.findings:
        console.print(
            f"[{SEVERITY_STYLE[rf.finding.severity.value]}]{rf.finding.severity.value}[/] {rf.finding.title}",
            highlight=False,
        )
    console.print(f"[dim]{len(result.hosts)} hosts, ${result.usage.get('cost_usd', 0):.2f}[/dim]")


@app.command()
def report(
    host: Annotated[str | None, typer.Option("--host", help="Only this host (default: all).")] = None,
    markdown: Annotated[
        Path | None, typer.Option("--markdown", help="Also write the report to this file.")
    ] = None,
    as_json: JsonOpt = False,
) -> None:
    """Open findings, recent runs (trends) and changes, for the terminal or as Markdown."""
    try:
        data = service.build_report(get_settings(), host=host)
    except StandaloneError as exc:
        raise _fail(exc, as_json) from exc
    text = render_markdown(data)
    if markdown is not None:
        markdown.write_text(text)
    if as_json:
        print(data.model_dump_json())
    else:
        console.print(Markdown(text))


@app.command()
def worker(
    api: Annotated[str | None, typer.Option("--api", help="Control plane URL (or HANDSCHECK_API).")] = None,
    once: Annotated[bool, typer.Option("--once", help="Stop when the job queue is empty.")] = False,
    poll: Annotated[float, typer.Option("--poll", help="Seconds between polls when idle.")] = 10.0,
    as_json: JsonOpt = False,
) -> None:
    """Run as a worker: lease jobs from the control plane, scan, post results (HANDSCHECK_WORKER_TOKEN)."""
    import logging

    from handscheck.worker.client import WorkerAPIError
    from handscheck.worker.loop import WorkerConfigError, serve

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    for noisy in ("asyncssh", "httpx", "httpcore"):  # one line per SSH channel / HTTP request otherwise
        logging.getLogger(noisy).setLevel(logging.WARNING)
    try:
        stats = serve(get_settings(), api_url=api, once=once, poll_seconds=poll)
    except (WorkerConfigError, WorkerAPIError) as exc:
        raise _fail(exc, as_json) from exc
    except KeyboardInterrupt:
        raise typer.Exit(code=0) from None
    if as_json:
        print(json.dumps({"jobs": stats.jobs, "failed": stats.failed, "results": stats.results}))
    else:
        console.print(f"{stats.jobs} job(s), {stats.failed} failed")


def _num(value: float) -> str:
    return str(int(value)) if float(value).is_integer() else f"{value:g}"


if __name__ == "__main__":  # pragma: no cover
    app()
