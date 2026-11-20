"""Guaranteed findings are added after the Claude stage unless Claude already reported the same subject."""

from __future__ import annotations

from handscheck.agents._framework.findings import FindingItem, ReportedFinding, Verification, to_finding
from handscheck.agents._framework.registry import all_agents
from handscheck.agents.malware.check import PREPEND_RULE
from handscheck.pipeline.guaranteed import add_guaranteed_findings
from tests.agents.conftest import replay_run
from tests.public_build import requires_rules

GAMMA = "/var/www/gamma.lab.test"


def _claude_finding(
    subject: str,
    *,
    agent: str = "malware",
    title: str = "Prepend backdoor",
    evidence: list[str] | None = None,
) -> ReportedFinding:
    item = FindingItem(
        kind="claude_kind",
        subject=subject,
        severity="critical",
        confidence="high",
        title=title,
        summary="s",
        evidence=evidence or [],
        rule_ids=[],
        recommended_action="r",
    )
    finding = to_finding(item, agent=agent, version=1, host="lab-wp2", site="gamma.lab.test")
    return ReportedFinding(
        finding=finding, confidence="high", host="lab-wp2", verification=Verification(status="pending")
    )


async def test_added_without_claude_and_verified_like_any_finding() -> None:
    run = await replay_run("lab-wp2")  # deterministic checks only: run_host adds them itself
    prepends = [f for f in run.findings if PREPEND_RULE in f.finding.rule_ids]
    assert [(f.finding.site, f.finding.severity, f.verification.status) for f in prepends] == [
        ("gamma.lab.test", "critical", "pending")
    ]
    assert prepends[0].finding.dedupe_key.endswith(f":{GAMMA}/.user.ini")
    clean = await replay_run("lab-wp1")
    assert not [f for f in clean.findings if PREPEND_RULE in f.finding.rule_ids]


async def test_not_added_twice_when_claude_reported_it() -> None:
    run = await replay_run("lab-wp2")
    total = len(run.findings)  # every guaranteed finding on lab-wp2 (no Claude stage)
    run.findings = [_claude_finding(f"{GAMMA}/.user.ini")]
    assert add_guaranteed_findings(run, all_agents()) == total - 1 and len(run.findings) == total
    run.findings = [_claude_finding(f"{GAMMA}/readme.html")]  # something else
    assert add_guaranteed_findings(run, all_agents()) == total


async def test_guaranteed_findings_do_not_hide_each_other() -> None:
    """The www-data cron's evidence names /dev/shm/.x: the hidden-folder finding is still added."""
    run = await replay_run("lab-wp2")
    keys = [f.finding.dedupe_key for f in run.findings]
    assert any(k.endswith(":/var/spool/cron/crontabs/www-data") for k in keys)
    assert any(k.endswith(":/dev/shm/.x") for k in keys)
    assert len(keys) == len(set(keys))


@requires_rules
async def test_a_short_subject_needs_a_whole_word_match() -> None:
    run = await replay_run("lab-wp2")
    total = len(run.findings)
    run.findings = [
        _claude_finding("wp-config", agent="wordpress", title="wp-config.php readable in the web root")
    ]
    assert add_guaranteed_findings(run, all_agents()) == total  # the `root` admin is still added
    run.findings = [_claude_finding("root", agent="wordpress", title="Rogue administrator")]
    assert add_guaranteed_findings(run, all_agents()) == total - 1
    run.findings = [
        _claude_finding("x", agent="wordpress", title="Rogue admins", evidence=["admins: root, bob"])
    ]
    assert add_guaranteed_findings(run, all_agents()) == total - 1


@requires_rules
async def test_deterministic_findings_alone_meet_every_canary_expectation() -> None:
    """Every planted item in lab/canary/expectations.yaml is found (at its severity bar) without Claude, and
    nothing is reported on the clean host or for its look-alikes."""
    from tests.canary.evaluate import score

    findings = []
    for host in ("lab-wp1", "lab-wp2", "lab-locked"):
        findings += [rf.model_dump(mode="json") for rf in (await replay_run(host)).findings]
    result = score(findings, require_verification=False)
    assert result["missing"] == [] and result["violations"] == []
    assert not [f for f in findings if f["host"] == "lab-wp1"]


@requires_rules
async def test_guaranteed_findings_offer_the_same_fixes() -> None:
    """The listable folder and the rogue admin on gamma get their fix even when Claude didn't report them."""
    run = await replay_run("lab-wp2")
    fixes = {f.finding.dedupe_key.split(":")[1]: f.finding.fix for f in run.findings if f.finding.fix}
    assert fixes["directory_listing"] is not None and fixes["directory_listing"].action == "disable_indexes"
    assert fixes["directory_listing"].params["dir"] == "/"  # the whole site (see test_listings_fold...)
    assert fixes["directory_listing"].params["listings"] == ["/wp-content/uploads/leads/"]
    assert fixes["suspicious_admin"] is not None and fixes["suspicious_admin"].action == "neutralize_wp_admin"
    # The web shell in uploads is quarantined; the prepend target next to it is not (every page loads it).
    assert fixes["backdoor_code"] is not None and fixes["backdoor_code"].action == "quarantine_file"
    assert fixes["backdoor_code"].params["files"] == [
        "/var/www/gamma.lab.test/wp-content/uploads/2026/10/cache.php"
    ]
    assert fixes["uploads_run_php"] is not None and fixes["uploads_run_php"].action == "deny_php_in_uploads"
    assert fixes["uploads_run_php"].params["uploads"] == "/wp-content/uploads/"
    # The vulnerable Slider Revolution gets a virtual patch for its anonymous AJAX action.
    assert fixes["vulnerable_plugin"] is not None and fixes["vulnerable_plugin"].action == "virtual_patch"
    assert fixes["vulnerable_plugin"].params["ajax_actions"] == ["revslider_ajax_action"]
    # the folder, the root and two tempuser admins, the shell, PHP in uploads, the plugin
    assert len([f for f in run.findings if f.finding.fix]) == 7


def _listing_claude(subject: str, severity: str = "medium") -> ReportedFinding:
    rf = _claude_finding(subject, agent="exposure", title=f"{subject} is browsable")
    rf.finding.dedupe_key = rf.finding.dedupe_key.replace(":claude_kind:", ":browsable_folder:")
    rf.finding.severity = rf.finding.severity.__class__(severity)
    return rf


async def test_listings_fold_into_one_finding_and_fix_for_the_site() -> None:
    """Folders that list their files are one finding per site, whoever reported them, with a site-wide fix,
    and open per-folder findings from earlier runs are named as superseded."""
    run = await replay_run("lab-wp2")
    exposure = next(r for r in run.agents if r.agent == "exposure" and r.site == "gamma.lab.test")
    assert exposure.facts is not None
    exposure.facts["directory_listings"] = ["/wp-content/uploads/leads/", "/wp-admin/css/"]
    run.findings = [_listing_claude(f"{GAMMA}/wp-content/uploads/2024/", "critical")]
    old = "exposure:directory_listing:lab-wp2:gamma.lab.test:/wp-content/uploads/leads/"
    other_site = "exposure:directory_listing:lab-wp2:alpha.lab.test:/wp-content/uploads/"
    add_guaranteed_findings(
        run, all_agents(), still_open={old, other_site, "exposure:xmlrpc:lab-wp2:gamma.lab.test:/x"}
    )

    listings = [f.finding for f in run.findings if "directory-listing" in " ".join(f.finding.rule_ids)]
    gamma = [f for f in listings if f.site == "gamma.lab.test"]
    assert len(gamma) == 1
    site = gamma[0]
    assert site.dedupe_key == "exposure:directory_listing:lab-wp2:gamma.lab.test:/"
    assert site.title == "3 folders on gamma.lab.test show a list of their files to anyone"
    assert site.evidence == [
        "directory_listings: /wp-admin/css/",
        "directory_listings: /wp-content/uploads/2024/",
        "directory_listings: /wp-content/uploads/leads/",
    ]
    assert site.severity.value == "critical"  # Claude rated one folder higher
    assert site.supersedes == [old]  # not another site's, not another kind's
    assert site.fix is not None and site.fix.params["dir"] == "/"
    assert site.fix.params["listings"] == [
        "/wp-admin/css/",
        "/wp-content/uploads/leads/",
    ]  # verified after the fix: the folders the worker saw listing
    assert not [f for f in run.findings if ":browsable_folder:" in f.finding.dedupe_key]


async def test_a_single_listing_is_still_a_site_finding_with_medium_severity_outside_uploads() -> None:
    run = await replay_run("lab-wp2")
    exposure = next(r for r in run.agents if r.agent == "exposure" and r.site == "gamma.lab.test")
    assert exposure.facts is not None
    exposure.facts["directory_listings"] = ["/downloads/"]
    run.findings = []
    add_guaranteed_findings(run, all_agents())
    (site,) = [f.finding for f in run.findings if f.finding.dedupe_key.endswith("gamma.lab.test:/")]
    assert site.severity.value == "medium" and site.title.startswith("Folder /downloads/ on gamma.lab.test")
    assert site.supersedes == []
