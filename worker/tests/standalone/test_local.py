"""`hc check --local` and `hc sites --local` (Track S1) offline: the local runner replays captured output."""

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from handscheck.cli import app
from handscheck.config import Settings
from handscheck.standalone import service
from handscheck.standalone.service import StandaloneError
from handscheck.standalone.state import SCHEMA_VERSION, StandaloneState, StoredHost
from tests.agents.replay import ReplayRunner
from tests.standalone.test_checks import _Checksums, _Http

cli = CliRunner()


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    monkeypatch.setenv("HANDSCHECK_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(service.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(service.socket, "gethostname", lambda: "Web-01.example.com")
    seen: dict[str, Any] = {"checksums": 0, "runners": []}

    def fake_local(name: str, **kwargs: Any) -> ReplayRunner:
        seen["runners"].append(name)
        return ReplayRunner.load("lab-wp2")

    def no_ssh(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("a local check must not open SSH")

    class CountingChecksums(_Checksums):
        def __init__(self, **kwargs: Any) -> None:
            seen["checksums"] += 1
            super().__init__(**kwargs)

    monkeypatch.setattr(service, "LocalRunner", fake_local)
    monkeypatch.setattr(service, "SSHRunner", no_ssh)
    monkeypatch.setattr(service, "HttpxProber", _Http)
    monkeypatch.setattr(service, "WordPressOrgChecksums", CountingChecksums)
    return seen


def test_check_local_registers_this_machine_and_stores_the_run(env: dict[str, Any]) -> None:
    result = cli.invoke(app, ["check", "--local", "--json"])
    assert result.exit_code == 0, result.output
    [outcome] = json.loads(result.output)
    run = outcome["run"]
    assert run["host"] == "web-01" and run["claude"] is False and outcome["run_id"]
    assert env["runners"] == ["web-01"]
    assert env["checksums"] == 0  # free mode: no outbound fetches unless --checksums
    system = next(a for a in run["agents"] if a["agent"] == "system")
    assert system["facts"]["uid0_accounts"] == ["root", "sysbackup"]
    assert any(f["finding"]["dedupe_key"].startswith("system:") for f in run["findings"])

    [host] = json.loads(cli.invoke(app, ["host", "list", "--json"]).output)
    assert host["name"] == "web-01" and host["local"] is True and host["address"] == "127.0.0.1"

    second = json.loads(cli.invoke(app, ["check", "system", "--local", "--json"]).output)[0]
    assert not second["run"]["agents"][0]["baseline"]  # diffed against the first local run
    diff = json.loads(cli.invoke(app, ["diff", "--host", "web-01", "--json"]).output)
    assert diff["run_id"] == second["run_id"]
    findings = json.loads(cli.invoke(app, ["findings", "list", "--host", "web-01", "--json"]).output)
    assert findings


def test_checksums_are_opt_in(env: dict[str, Any]) -> None:
    result = cli.invoke(app, ["check", "wordpress", "--local", "--checksums", "--name", "box", "--json"])
    assert result.exit_code == 0, result.output
    assert env["checksums"] == 1


def test_root_is_refused_unless_allowed(env: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service.os, "geteuid", lambda: 0)
    refused = cli.invoke(app, ["check", "--local", "--json"])
    assert refused.exit_code == 1 and "refusing to run checks as root" in refused.output
    assert env["runners"] == []
    allowed = cli.invoke(app, ["check", "system", "--local", "--allow-root", "--json"])
    assert allowed.exit_code == 0, allowed.output


def test_local_flags_are_exclusive(env: dict[str, Any]) -> None:
    both = cli.invoke(app, ["check", "--local", "--host", "x", "--json"])
    assert both.exit_code == 1 and "--local" in json.loads(both.output)["error"]
    stray = cli.invoke(app, ["check", "--host", "x", "--checksums", "--json"])
    assert stray.exit_code == 1 and "only apply with --local" in stray.output
    sites = cli.invoke(app, ["sites", "--json"])
    assert sites.exit_code == 1 and "--host NAME or --local" in sites.output


def test_sites_local(env: dict[str, Any]) -> None:
    result = cli.invoke(app, ["sites", "--local", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["host"] == "web-01" and {"gamma.lab.test", "delta.lab.test"} <= {
        s["name"] for s in data["sites"]
    }


def test_local_host_has_no_ssh_paths(env: dict[str, Any], tmp_path: Path) -> None:
    settings = Settings()
    host = service.ensure_local_host(settings)
    with pytest.raises(StandaloneError, match="hc check --local"):
        service.run_checks(settings, ["system"], host_names=[host.name])
    with pytest.raises(StandaloneError, match="no SSH connection"):
        service.target_for(host)
    key = tmp_path / "key"
    key.write_text("x\n")
    service.add_host(settings, "web-02", address="10.0.0.2", key_path=key)
    with pytest.raises(StandaloneError, match="already an SSH host"):
        service.ensure_local_host(settings, "web-02")


@pytest.mark.parametrize(
    ("raw", "expected"), [("Web-01.example.com", "web-01"), ("my_box", "my_box"), ("!!!", "localhost")]
)
def test_local_name(raw: str, expected: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service.socket, "gethostname", lambda: raw)
    assert service.local_name() == expected


def test_state_v6_gains_the_local_column(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    StandaloneState(path)
    with sqlite3.connect(path) as db:
        db.execute("ALTER TABLE hosts DROP COLUMN local")
        db.execute(
            "INSERT INTO hosts (name, address, port, user, added_at)"
            " VALUES ('old', 'h', 22, 'u', '2026-01-01')"
        )
        db.execute("PRAGMA user_version = 6")
    state = StandaloneState(path)
    old = state.get_host("old")
    assert isinstance(old, StoredHost) and old.local is False
    with sqlite3.connect(path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
