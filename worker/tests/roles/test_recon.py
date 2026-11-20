"""Recon (M7c) offline: the inventory parsers, the changes code makes alone, validation against the agents'
settings schemas, and the recon job on replayed lab output with and without (scripted) Claude."""

from __future__ import annotations

import json
from typing import Any

from handscheck.agents._framework.check import Output
from handscheck.agents._framework.host_settings import validate_change
from handscheck.agents._framework.registry import all_agents
from handscheck.contracts import HostAgentState, SettingChange
from handscheck.roles.recon.inventory import (
    ReconInventory,
    SiteInfo,
    build_inventory,
    code_changes,
    parse_os_release,
    parse_owners,
    parse_pool_users,
)
from handscheck.worker.roles import merge_changes, repeats
from tests.agents.fake_claude import ScriptedAPI, section, text, tool
from tests.public_build import requires_prompts
from tests.worker.test_roles import example, run

DEFS = {n: a.definition for n, a in all_agents().items()}


def test_parsers() -> None:
    assert parse_os_release('NAME="Ubuntu"\nPRETTY_NAME="Ubuntu 22.04.4 LTS"\n') == "Ubuntu 22.04.4 LTS"
    pools = (
        "/etc/php/8.3/fpm/pool.d/www.conf:user = www-data\n"
        "/etc/php/8.3/fpm/pool.d/shop.conf:user = deploy\n"
        "/etc/php/7.4/fpm/pool.d/www.conf:user = www-data\n"
        "/etc/php/8.3/cli/php.ini:user = nobody\n"
        "/etc/php5/fpm/pool.d/www.conf:user = www-data\n"
    )
    assert parse_pool_users(pools) == {
        "php5-fpm": ["www-data"],
        "php7.4-fpm": ["www-data"],
        "php8.3-fpm": ["deploy", "www-data"],
    }
    assert parse_owners("deploy /var/www/a b\nwww-data /var/www/c\n") == {
        "/var/www/a b": "deploy",
        "/var/www/c": "www-data",
    }
    inv = build_inventory(
        {
            "apache_user": Output(stdout="export APACHE_RUN_USER=www-data\n"),
            "nginx_user": Output(stdout="user nginx;\n"),
            "sizes": Output(stdout="1234 /var/log/secure\n"),
            "sudo_lines": Output(stdout="31000\n"),
            "wp_cli": Output(stdout="/usr/local/bin/wp\n"),
        },
        [],
    )
    assert (inv.apache_user, inv.nginx_user, inv.wp_cli) == ("www-data", "nginx", "/usr/local/bin/wp")
    assert inv.logs == {"/var/log/secure": 1234} and inv.sudo_lines == 31000


def wp(name: str, owner: str) -> SiteInfo:
    return SiteInfo(name=name, type="wordpress", server="apache", docroot=f"/var/www/{name}", owner=owner)


def test_code_changes_from_clear_cut_facts() -> None:
    inv = ReconInventory(
        sites=[wp("a.test", "deploy"), wp("b.test", "deploy")],
        pool_users={"php8.3-fpm": ["deploy", "www-data"]},
        logs={"/var/log/secure": 10},
        sudo_lines=50_000,
    )
    changes, notes = code_changes(inv, DEFS, [])
    by_agent = {c.agent: c.settings for c in changes}
    assert by_agent["activity"] == {"auth_log_path": "/var/log/secure"}
    assert "wordpress" not in by_agent  # wp-cli runs as www-data only: the owner is a note
    assert any("belong to deploy" in n for n in notes)
    assert by_agent["users"]["auth_log_path"] == "/var/log/secure"
    assert by_agent["persistence"]["web_users"] == ["www-data", "apache", "nginx", "deploy"]  # added only
    assert any("sudo command lines" in n for n in notes)
    for change in changes:
        assert validate_change(change, DEFS)[1] is None

    # Already stored: nothing to propose again.
    stored = [HostAgentState(agent=c.agent, settings=c.settings) for c in changes]
    assert code_changes(inv, DEFS, stored)[0] == []


def test_busy_access_logs_get_more_lines() -> None:
    # ga-aws-24: 12052 requests to one site in the health agent's 90 minutes.
    facts = {"health": {"site_share": [{"name": "beavercountyradio.com", "requests": 12052, "share": 0.8}]}}
    inv = ReconInventory(sites=[wp("beavercountyradio.com", "www-data")], logs={"/var/log/auth.log": 5})
    changes, notes = code_changes(inv, DEFS, [], facts)
    by_agent = {c.agent: c for c in changes}
    assert by_agent["activity"].settings == {"access_log_lines": 20000}  # 12052 x 1.25, up to a 5000 step
    assert "12052 requests in 90 minutes" in by_agent["activity"].reason
    assert "health" not in by_agent  # its default 20000 already covers it
    assert validate_change(by_agent["activity"], DEFS)[1] is None and notes == []

    # A longer lookback needs more lines; one already stored isn't proposed again; quiet sites need nothing.
    longer = [HostAgentState(agent="activity", settings={"lookback_minutes": 180})]
    assert {c.agent: c.settings for c in code_changes(inv, DEFS, longer, facts)[0]}["activity"] == {
        "access_log_lines": 35000  # 12052 x 2 x 1.25 = 30130, up to a 5000 step
    }
    done = [HostAgentState(agent="activity", settings={"access_log_lines": 20000})]
    assert code_changes(inv, DEFS, done, facts)[0] == []
    quiet = {"health": {"site_share": [{"name": "a.test", "requests": 900, "share": 1.0}]}}
    assert code_changes(inv, DEFS, [], quiet)[0] == []
    off = [HostAgentState(agent="activity", settings={"access_log_lines": 0})]
    assert code_changes(inv, DEFS, off, facts)[0] == []
    flood = {"health": {"site_share": [{"name": "a.test", "requests": 40000, "share": 1.0}]}}
    assert any("may not reach back 90 minutes" in n for n in code_changes(inv, DEFS, [], flood)[1])


def test_code_leaves_the_defaults_when_unsure() -> None:
    usual = ReconInventory(sites=[wp("a.test", "www-data")], logs={"/var/log/auth.log": 5})
    assert code_changes(usual, DEFS, []) == ([], [])


def test_validation() -> None:
    def check(**kw: Any) -> str | None:
        return validate_change(SettingChange(reason="r", **kw), DEFS)[1]

    assert check(agent="nope", settings={}) == "unknown agent 'nope'"
    assert "always runs" in (check(agent="users", enabled=False) or "")
    assert "unknown setting" in (check(agent="activity", settings={"color": "red"}) or "")
    assert "invalid settings" in (check(agent="activity", settings={"lookback_minutes": 5}) or "")
    assert "invalid settings" in (check(agent="activity", settings={"lookback_minutes": "90"}) or "")
    assert "nothing differs" in (check(agent="activity", settings={"lookback_minutes": 90}) or "")
    assert check(agent="wordpress", enabled=False) is None
    assert "only run as www-data" in (check(agent="wordpress", settings={"wp_cli_user": "deploy"}) or "")


def test_claude_adds_to_code_changes() -> None:
    code = [SettingChange(agent="activity", settings={"auth_log_path": "/var/log/secure"}, reason="owner")]
    claude = [
        SettingChange(agent="activity", settings={"access_log_lines": 20000}, reason="busy logs"),
        SettingChange(agent="wordpress", enabled=False, reason="no WordPress"),
    ]
    merged = {c.agent: c for c in merge_changes(code, claude)}
    assert merged["activity"].settings == {"auth_log_path": "/var/log/secure", "access_log_lines": 20000}
    assert merged["activity"].reason == "owner busy logs" and merged["wordpress"].enabled is False


def test_a_reworded_code_note_is_a_repeat() -> None:
    code = [
        "WordPress files belong to deployboy, tyler, not www-data. wp-cli reads the databases as "
        "www-data; if it can't read a site's wp-config.php, its sessions and admins go unchecked."
    ]
    claude = (
        "All WordPress files belong to deployboy or tyler, not www-data. wp-cli (/usr/local/bin/wp) can "
        "only run as www-data, so it may not be able to read wp-config.php or report administrators for "
        "every site."
    )
    assert repeats(claude, code)
    assert not repeats("PHP 7.4 (php7.4-fpm) is installed and no longer gets security updates.", code)
    assert not repeats("anything", [])


async def test_recon_job_without_claude_maps_the_lab_host() -> None:
    result = await run(example("job.recon", options={"use_claude": False}))
    assert result.status == "ok", result.errors
    r = result.recon
    assert r is not None and r.model is None and "Ubuntu 16.04" in r.profile
    assert r.inventory["pool_users"] == {"php7.0-fpm": ["www-data"]}
    assert {s["name"]: s["owner"] for s in r.inventory["sites"]} == {
        "delta.lab.test": "www-data",
        "gamma.lab.test": "www-data",
    }
    assert r.changes == []  # the lab's defaults fit
    assert any("code only" in n for n in r.notes)


@requires_prompts
async def test_recon_job_with_claude_keeps_valid_changes_only() -> None:
    def claude(req: dict[str, Any], i: int) -> Any:
        if i == 0:
            assert "Recon" in req["system"][0]["text"]
            inventory = json.loads(section(req, "inventory"))
            assert inventory["os"].startswith("Ubuntu 16.04")
            assert json.loads(section(req, "notes_by_code")) == []
            return tool("grep -s -h CustomLog /etc/apache2/sites-enabled/gamma.lab.test.conf", sudo=True)
        value = {"field": "access_log_lines", "value_json": "20000"}
        return text(
            {
                "profile": "Ubuntu 16.04, Apache with PHP 7.0 FPM, two WordPress sites.",
                "changes": [
                    {"agent": "activity", "enabled": None, "settings": [value], "reason": "busy logs"},
                    {"agent": "users", "enabled": False, "settings": [], "reason": "quiet"},
                    {
                        "agent": "health",
                        "enabled": None,
                        "settings": [{"field": "slow_s", "value_json": "fast"}],
                        "reason": "bad json",
                    },
                ],
                "notes": ["Check the backups folder by hand."],
            }
        )

    result = await run(example("job.recon"), ScriptedAPI(claude))
    r = result.recon
    assert r is not None and r.model == "claude-opus-5-5" and r.profile.startswith("Ubuntu 16.04, Apache")
    assert [(c.agent, c.settings) for c in r.changes] == [("activity", {"access_log_lines": 20000})]
    assert result.status == "partial"
    assert any("always runs" in e for e in result.errors) and any("valid JSON" in e for e in result.errors)
    assert "Check the backups folder by hand." in r.notes and result.claude_cost_usd > 0
