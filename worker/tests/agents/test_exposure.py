from datetime import date

from handscheck.agents.exposure.check import (
    ExposureFacts,
    eol_status,
    listing_candidates,
    parse_php_version,
)
from tests.agents.conftest import collect_facts
from tests.public_build import requires_rules


@requires_rules
async def test_compromised_site() -> None:
    facts = await collect_facts("lab-wp2", "exposure", site="gamma.lab.test")
    assert isinstance(facts, ExposureFacts) and facts.warnings == []
    assert [(f.path, f.http_status) for f in facts.sensitive_files] == [
        ("/var/www/gamma.lab.test/backup-2026-10.sql", 200)
    ]
    assert [(f.path, f.served) for f in facts.phpinfo_files] == [("/var/www/gamma.lab.test/info.php", True)]
    assert facts.directory_listings == ["/wp-content/uploads/leads/"]
    assert facts.php_eol and facts.php_eol.past and facts.php_version == "7.0.33"
    assert facts.os_eol and facts.os_eol.past and facts.os_version == "ubuntu 16.04"


@requires_rules
async def test_clean_sites() -> None:
    for host, site in (
        ("lab-wp1", "alpha.lab.test"),
        ("lab-wp1", "beta.lab.test"),
        ("lab-wp2", "delta.lab.test"),
    ):
        facts = await collect_facts(host, "exposure", site=site)
        assert isinstance(facts, ExposureFacts) and facts.warnings == [] and facts.probe_errors == []
        assert facts.sensitive_files == [] and facts.phpinfo_files == [] and facts.directory_listings == []
        assert facts.listing_probes > 0
        # Hygiene facts that are true on the lab images too (reported, but not compromise):
        assert facts.xmlrpc_enabled is True and facts.code_writable_by_web_user is True
    alpha = await collect_facts("lab-wp1", "exposure", site="alpha.lab.test")
    assert isinstance(alpha, ExposureFacts) and alpha.php_eol and not alpha.php_eol.past


@requires_rules
def test_helpers() -> None:
    assert parse_php_version("PHP 8.3.6 (cli) (built: Apr 15 2024)\nCopyright") == "8.3.6"
    assert parse_php_version("bash: php: not found") is None
    eol = eol_status("php", "7.4", date(2026, 11, 14))
    assert eol and eol.past and eol.eol == date(2022, 11, 28)
    assert eol_status("php", "9.9", date(2026, 11, 14)) is None
    dirs = [
        "/w/a",
        "/w/wp-content",
        "/w/wp-content/uploads",
        "/w/wp-content/uploads/2026",
        "/w/.git",
        "/w/b/c",
    ]
    assert listing_candidates(dirs, ["/w/wp-content"], "/w", 3) == [
        "/w/wp-content/uploads",
        "/w/wp-content/uploads/2026",
        "/w/a",
    ]


def test_a_dump_that_gains_data_is_a_change_but_a_similar_backup_is_not() -> None:
    from handscheck.agents.exposure.check import ExposureFacts, SensitiveFile, size_class
    from handscheck.pipeline.diff import diff_views

    def facts(size: int) -> ExposureFacts:
        return ExposureFacts(
            sensitive_files=[SensitiveFile(path="/var/www/x/backup.sql", size=size, http_status=200)]
        )

    assert [size_class(s) for s in (None, 0, 88, 3066, 5 * 1024**2, 200 * 1024**2)] == [
        "unknown",
        "empty",
        "<1KB",
        "<1MB",
        "<100MB",
        ">=100MB",
    ]
    grew = diff_views("exposure", facts(88).diff_view(), facts(3066).diff_view())
    assert [(c.collection, c.op) for c in grew] == [("sensitive_files", "changed")]
    assert diff_views("exposure", facts(3000).diff_view(), facts(3066).diff_view()) == []


def test_guaranteed_exposures_need_http_confirmation() -> None:
    from handscheck.agents.exposure.check import CHECK

    facts = {
        "sensitive_files": [
            {"path": "/s/backup-2026-10.sql", "size": 4000, "http_status": 200},
            {"path": "/s/db.sql.gz", "size": 4000, "http_status": 200},
            {"path": "/s/.env", "size": 90, "http_status": 200},
            {"path": "/s/old.sql", "size": 4000, "http_status": 403},  # blocked
            {"path": "/s/site.zip", "size": 9000, "http_status": 200},  # an archive: left to the agent
            {"path": "/s/debug.log", "size": 9000, "http_status": 200},
            {"path": "/s/x.sql", "size": 10, "http_status": None},  # not probed
        ],
        "directory_listings": ["/wp-content/uploads/leads/", "/downloads/"],
        "phpinfo_files": [{"path": "/s/info.php", "served": True}, {"path": "/s/i2.php", "served": False}],
    }
    found = CHECK().guaranteed_findings(facts)
    assert [(f.kind, f.subject, f.severity) for f in found] == [
        ("downloadable_dump", "/s/backup-2026-10.sql", "high"),
        ("downloadable_dump", "/s/db.sql.gz", "high"),
        ("downloadable_dump", "/s/.env", "high"),
        ("directory_listing", "/wp-content/uploads/leads/", "high"),
        ("directory_listing", "/downloads/", "medium"),
        ("public_phpinfo", "/s/info.php", "medium"),
    ]
