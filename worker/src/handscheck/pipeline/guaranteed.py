"""Findings a check guarantees from its facts (`Check.guaranteed_findings`), added after the Claude stage. A
planted prepend backdoor must not depend on whether Claude mentions it in a given run: when Claude already
reported the same subject for that agent and site, its finding stands; otherwise the check's finding is added
(and verified like any other medium+ finding)."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from handscheck.agents._framework.findings import (
    SEVERITY_ORDER,
    FindingItem,
    ReportedFinding,
    Verification,
    dedupe_key,
    needs_verification,
    to_finding,
)
from handscheck.agents.exposure.check import LISTING_RULE
from handscheck.remediation.propose import propose_fix, url_dir

if TYPE_CHECKING:
    from handscheck.agents._framework.registry import Agent
    from handscheck.pipeline.run import HostRun


def add_guaranteed_findings(
    run: HostRun,
    agents: dict[str, Agent],
    *,
    still_open: set[str] = frozenset(),  # type: ignore[assignment]
    reviewed: set[tuple[str, str | None]] | None = None,
) -> int:
    """`still_open`: dedupe keys already open. A finding open under its own key, or under the key of Claude's
    finding for the same subject, is not reported again (and so not verified again) unless Claude reviewed
    that agent this run (`reviewed`; None = no Claude stage) and left it out. Returns the net number of
    findings added (folding listings into one per site can remove some)."""
    before = len(run.findings)
    claude = list(run.findings)  # guaranteed findings added below don't hide each other
    for result in run.agents:
        agent = agents.get(result.agent)
        if agent is None or agent.check is None or result.facts is None:
            continue
        for item in agent.check.guaranteed_findings(result.facts):
            finding = to_finding(
                item, agent=result.agent, version=agent.definition.version, host=run.host, site=result.site
            )
            if _already_reported(claude, result.agent, result.site, item) or any(
                rf.finding.dedupe_key == finding.dedupe_key for rf in run.findings
            ):
                continue
            if (
                reviewed is not None
                and (result.agent, result.site) not in reviewed
                and _open(still_open, result.agent, result.site, item.subject)
            ):
                continue  # facts unchanged: it (or Claude's finding for it) is open since an earlier run
            # The same fix Claude's finding would offer (shown only once the verifier confirms it).
            finding.fix = propose_fix(finding, result.facts)
            status = "pending" if needs_verification(item.severity) else "not_required"
            run.findings.append(
                ReportedFinding(
                    finding=finding,
                    confidence=item.confidence,
                    host=run.host,
                    verification=Verification(status=status),
                )
            )
    fold_listings(run, agents, still_open, reviewed)
    return len(run.findings) - before


SITE_LISTING_KIND = "directory_listing"
_LISTING_WORDS = ("listing", "indexes", "browsable", "autoindex", "index_of")


def fold_listings(
    run: HostRun,
    agents: dict[str, Agent],
    still_open: set[str] = frozenset(),  # type: ignore[assignment]
    reviewed: set[tuple[str, str | None]] | None = None,
) -> None:
    """Folders that list their files share one cause: the site lets the web server list folders. They become
    one finding per site (`exposure:directory_listing:<host>:<site>:/`) with every folder as evidence and one
    site-wide fix, instead of a finding and a fix per folder. Claude's listing findings and the check's are
    folded in; open per-folder findings from earlier runs are named in `supersedes` so the control plane
    resolves them. Like the other guaranteed findings, it isn't reported again while open and unreviewed
    (facts unchanged), unless per-folder findings are still open to replace. Done in code, not by Claude: the
    facts already say which folders list."""
    agent = agents.get("exposure")
    for result in run.agents:
        if result.agent != "exposure" or result.facts is None or agent is None:
            continue
        site = result.site
        root = result.facts.get("root")
        root = root if isinstance(root, str) else ""
        mine = [
            rf
            for rf in run.findings
            if rf.finding.agent == "exposure"
            and rf.finding.site == site
            and _is_listing(rf.finding.dedupe_key, rf.finding.rule_ids)
        ]
        folders = {url_dir(p, root) for p in result.facts.get("directory_listings") or []}
        folders |= {url_dir(_subject(rf.finding.dedupe_key), root) for rf in mine}
        listed = sorted(f for f in folders if f and f != "/") or sorted(f for f in folders if f)
        if not listed:
            continue
        key = dedupe_key("exposure", SITE_LISTING_KIND, run.host, site, "/")
        uploads = any("/wp-content/uploads/" in f for f in listed)
        severity = max(
            ["high" if uploads else "medium", *(rf.finding.severity.value for rf in mine)],
            key=lambda s: SEVERITY_ORDER.get(s, 0),
        )
        where = site or run.host
        title = (
            f"Folder {listed[0]} on {where} shows a list of its files to anyone"
            if len(listed) == 1
            else f"{len(listed)} folders on {where} show a list of their files to anyone"
        )
        shown = ", ".join(listed[:10]) + (f" and {len(listed) - 10} more" if len(listed) > 10 else "")
        item = FindingItem(
            kind=SITE_LISTING_KIND,
            subject="/",
            severity=severity,
            confidence="high",
            title=title,
            summary=(
                f'Requesting {shown} returns an "Index of" page, so anyone can list and download every file '
                "in them"
                + (" (uploaded files, which often include customer documents)" if uploads else "")
                + ". They share one cause: the site lets the web server list any folder without an index "
                "file. Turning listings off for the whole site fixes all of them, and any folder that would "
                "start listing later."
            ),
            evidence=[f"directory_listings: {f}" for f in listed],
            rule_ids=[LISTING_RULE],
            recommended_action=(
                "Turn off directory listings for the whole site: `Options -Indexes` in the .htaccess of its "
                "web root (Apache), or `autoindex off` (nginx)."
            ),
        )
        finding = to_finding(
            item, agent="exposure", version=agent.definition.version, host=run.host, site=site
        )
        finding.fix = propose_fix(finding, result.facts)
        finding.supersedes = sorted(
            k
            for k in still_open
            if k != key
            and k.startswith("exposure:")
            and k.split(":", 4)[2:4] == [run.host, site or "-"]
            and _is_listing(k, [])
        )[:100]
        run.findings = [rf for rf in run.findings if rf not in mine]
        if (
            reviewed is not None
            and ("exposure", site) not in reviewed
            and key in still_open
            and not finding.supersedes
        ):
            continue
        status = "pending" if needs_verification(severity) else "not_required"
        run.findings.append(
            ReportedFinding(
                finding=finding, confidence="high", host=run.host, verification=Verification(status=status)
            )
        )


def _subject(key: str) -> str:
    parts = key.split(":", 4)
    return parts[4] if len(parts) == 5 else ""


def _is_listing(key: str, rule_ids: list[str]) -> bool:
    parts = key.split(":", 4)
    kind = parts[1] if len(parts) == 5 else ""
    return LISTING_RULE in rule_ids or any(w in kind for w in _LISTING_WORDS)


def _already_reported(
    findings: list[ReportedFinding], agent: str, site: str | None, item: FindingItem
) -> bool:
    """Claude reported it: same agent and site, and its key, title or evidence names the same subject."""
    return any(
        rf.finding.agent == agent
        and rf.finding.site == site
        and _names(item.subject.strip(), rf.finding.dedupe_key, rf.finding.title, rf.finding.evidence)
        for rf in findings
    )


def _open(still_open: set[str], agent: str, site: str | None, subject: str) -> bool:
    """An open finding (dedupe key `agent:kind:host:site:subject`) of the same agent and site names it."""
    return any(
        key.startswith(agent + ":") and f":{site or '-'}:" in key and _names(subject.strip(), key, "", [])
        for key in still_open
    )


def _names(subject: str, key: str, title: str, evidence: list[str]) -> bool:
    """Whether a finding's key or texts name `subject`. A short subject without a path (a login such as
    `root`) must be the key's subject or a whole word in the evidence, so "web root" in a title doesn't hide a
    rogue admin."""
    if "/" in subject:
        return subject in key or subject in title or any(subject in e for e in evidence)
    word = re.compile(rf"(?<![\w.@-]){re.escape(subject)}(?![\w@-])")
    return key.endswith(":" + subject) or any(word.search(e) for e in evidence)
