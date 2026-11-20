"""`health` (watch pass): parsers, carried probe history, and the impact rules (pressure alone: none)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from handscheck.agents._framework.check import Output
from handscheck.agents.health.check import (
    CHECK,
    HealthFacts,
    count_max_children,
    count_requests,
    parse_meminfo,
    parse_services,
    pool_for,
)
from handscheck.contracts import Finding, Severity
from handscheck.remediation.propose import propose_fix

NOW = 1_795_000_000
SETTINGS: dict[str, Any] = {
    "slow_s": 5.0,
    "slow_factor": 3.0,
    "lookback_minutes": 90,
    "access_log_lines": 20000,
}


def test_services_from_systemd_or_ps() -> None:
    units = Output(
        stdout="php8.3-fpm.service loaded active running The PHP 8.3 FastCGI Process Manager\n"
        "apache2.service loaded inactive dead The Apache HTTP Server\n"
        "nginx.service not-found inactive dead nginx.service\n"
    )
    assert [(s.name, s.active) for s in parse_services(units, None)] == [
        ("apache2", False),
        ("nginx", False),
        ("php8.3-fpm", True),
    ]
    no_systemd = Output(stdout="", exit_status=1)
    ps = Output(
        stdout="php-fpm: master process (/etc/php/7.0/fpm/php-fpm.conf)\n/usr/sbin/apache2 -k start\nbash\n"
    )
    assert [(s.name, s.active) for s in parse_services(no_systemd, ps)] == [
        ("apache2", True),
        ("php7.0-fpm", True),
    ]


def test_meminfo_maxchildren_pools_and_traffic() -> None:
    assert parse_meminfo(
        "MemTotal: 4000000 kB\nMemAvailable: 300000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n"
    ) == (
        4000000,
        300000,
        0,
    )
    since = datetime(2026, 11, 19, 10, 0, tzinfo=UTC)
    warning = "WARNING: [pool www] server reached pm.max_children setting (12), consider raising it"
    log = (
        f"[19-Nov-2026 09:30:00] {warning}\n"
        f"[19-Nov-2026 10:15:00] {warning}\n"
        "[19-Nov-2026 10:16:00] NOTICE: something else\n"
    )
    assert count_max_children(log, since) == 1
    assert pool_for("php8.3-fpm\n", ["php8.3-fpm"]) == "php8.3-fpm"  # from the vhost's socket path
    assert pool_for("php7.4-fpm\n", ["php8.3-fpm"]) is None  # not a pool on this server
    t = (since + timedelta(minutes=5)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    req = f'[{t}] "GET / HTTP/1.1" 200 5 "-"'
    access = (
        f'1.2.3.4 - - {req} "Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com)"\n'
        f'1.2.3.5 - - {req} "Mozilla/5.0 (Windows NT 10.0)"\n'
        f'10.0.0.1 - - {req} "handscheck/0.1.0 (+https://handscheck.ai; read-only check)"\n'
    )
    assert count_requests(access, since) == ["Bytespider", "Mozilla/5.0"]  # our own probes aren't traffic


def facts_with(series: dict[str, list[tuple[int | None, float | None]]], **extra: Any) -> dict[str, Any]:
    """Facts whose probe history for each site is the given (status, seconds) list, oldest first."""
    probes = {
        site: [
            {
                "time": NOW - 1800 * (len(points) - i - 1),
                "status": st,
                "elapsed_s": el,
                "error": None if st else "timeout",
            }
            for i, (st, el) in enumerate(points)
        ]
        for site, points in series.items()
    }
    base = {"now": NOW, "probes": probes, "rule_settings": {"slow_s": 5.0, "slow_factor": 3.0}}
    return HealthFacts.model_validate({**base, **extra}).model_dump(mode="json")


def found(facts: dict[str, Any]) -> list[tuple[str, str]]:
    return [(f.kind, f.severity) for f in CHECK().guaranteed_findings(facts)]


def test_down_needs_two_bad_passes_after_a_good_one() -> None:
    assert found(facts_with({"a.test": [(200, 0.3), (502, 0.1), (None, 10.0)]})) == [("site_down", "high")]
    assert found(facts_with({"a.test": [(200, 0.3), (200, 0.3), (502, 0.1)]})) == []  # one bad pass
    assert found(facts_with({"a.test": [(502, 0.1), (502, 0.1), (502, 0.1)]})) == []  # was never up
    assert found(facts_with({"a.test": [(200, 0.3), (403, 0.2), (401, 0.2)]})) == []  # 4xx isn't down


def test_slow_against_its_usual_two_passes_in_a_row() -> None:
    assert found(facts_with({"a.test": [(200, 0.4), (200, 0.5), (200, 7.0), (200, 8.5)]})) == [
        ("site_slow", "medium")
    ]
    assert (
        found(facts_with({"a.test": [(200, 0.4), (200, 0.5), (200, 0.4), (200, 8.5)]})) == []
    )  # one slow pass
    # Always about 6 s: slow, but not slower than usual.
    assert found(facts_with({"a.test": [(200, 6.0), (200, 6.2), (200, 6.5), (200, 6.1)]})) == []


def test_pressure_without_impact_is_no_finding() -> None:
    calm = facts_with(
        {"a.test": [(200, 0.4), (200, 0.5), (200, 0.4)]},
        max_children={"php8.3-fpm": 40},
        load=[25.0, 20.0, 18.0],
        cores=2,
        mem_available_kb=50_000,
    )
    assert found(calm) == []


def test_carry_keeps_the_last_probes() -> None:
    previous = facts_with({"a.test": [(200, 0.3)] * 12})
    current = CHECK().parse(
        {
            "now": Output(stdout=f"{NOW} +0000\n"),
            "probe@a.test": Output(stdout='{"status": 502, "elapsed_s": 0.1}'),
        },
        SETTINGS,
    )
    carried = CHECK().carry(previous, current)
    assert len(carried.probes["a.test"]) == 12 and carried.probes["a.test"][-1].status == 502


def health_finding(kind: str = "site_slow", site: str = "a.test") -> Finding:
    return Finding(
        dedupe_key=f"health:{kind}:web1:-:{site}@2026-11-19 10:00 UTC",
        agent="health",
        agent_version=1,
        severity=Severity.medium,
        title="slow",
        summary="s",
    )


def test_restart_is_offered_only_with_a_visible_cause() -> None:
    slow = {"a.test": [(200, 0.4), (200, 0.5), (200, 7.0), (200, 8.5)]}
    services = [{"name": "php8.3-fpm", "active": True}, {"name": "apache2", "active": True}]
    saturated = facts_with(
        slow, site_pools={"a.test": "php8.3-fpm"}, services=services, max_children={"php8.3-fpm": 3}
    )
    fix = propose_fix(health_finding(), saturated)
    assert fix is not None and fix.action == "restart_service"
    assert fix.params == {"site": "a.test", "service": "php8.3-fpm", "slow_s": 5.0}

    stopped = facts_with(
        slow,
        site_pools={"a.test": "php8.3-fpm"},
        services=[{"name": "php8.3-fpm", "active": True}, {"name": "apache2", "active": False}],
    )
    fix = propose_fix(health_finding("site_down"), stopped)
    assert fix is not None and fix.params["service"] == "apache2"

    unexplained = facts_with(
        slow, site_pools={"a.test": "php8.3-fpm"}, services=services, max_children={"php8.3-fpm": 0}
    )
    assert propose_fix(health_finding(), unexplained) is None  # no visible cause: people diagnose
