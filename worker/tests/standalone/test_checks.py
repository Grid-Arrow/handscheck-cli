"""`hc check`, `hc diff`, `hc sites` and `hc agents` offline: SSH is replaced by captured lab output."""

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from handscheck.cli import app
from handscheck.standalone import service
from handscheck.standalone.state import SCHEMA_VERSION, StandaloneState
from tests.agents.replay import ReplayChecksums, ReplayHttp, ReplayRunner, load_capture

cli = CliRunner()
LAB = ("lab-wp1", "lab-wp2")


class _Http(ReplayHttp):
    def __init__(self) -> None:
        super().__init__({k: v for h in LAB for k, v in load_capture(h)["http"].items()})

    async def close(self) -> None:
        return None


class _Checksums(ReplayChecksums):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__({k: v for h in LAB for k, v in load_capture(h)["checksums"].items()})

    async def close(self) -> None:
        return None


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("HANDSCHECK_STATE_DIR", str(tmp_path / "state"))
    key = tmp_path / "key"
    key.write_text("not used: SSH is replaced by ReplayRunner\n")

    def fake_runner(target: Any, **kwargs: Any) -> ReplayRunner:
        return ReplayRunner.load(target.address)

    monkeypatch.setattr(service, "SSHRunner", fake_runner)
    monkeypatch.setattr(service, "HttpxProber", _Http)
    monkeypatch.setattr(service, "WordPressOrgChecksums", _Checksums)
    for host in ("lab-wp1", "lab-wp2"):
        added = cli.invoke(app, ["host", "add", host, "--address", host, "--key", str(key), "--json"])
        assert added.exit_code == 0, added.output
    return tmp_path


def test_check_then_diff(env: Path) -> None:
    first = cli.invoke(app, ["check", "--host", "lab-wp2", "--no-agents", "--json"])
    assert first.exit_code == 0, first.output
    [outcome] = json.loads(first.output)
    run = outcome["run"]
    assert outcome["run_id"] and run["host"] == "lab-wp2" and run["claude"] is False
    system = next(a for a in run["agents"] if a["agent"] == "system")
    assert system["baseline"] and system["facts"]["uid0_accounts"] == ["root", "sysbackup"]

    hosts = json.loads(cli.invoke(app, ["host", "list", "--json"]).output)
    pinned = {h["name"]: h["host_key_fingerprint"] for h in hosts}
    assert pinned["lab-wp2"] == ReplayRunner.load("lab-wp2").host_key_fingerprint  # trust on first use

    diff = json.loads(cli.invoke(app, ["diff", "--host", "lab-wp2", "--json"]).output)
    assert diff["run_id"] == outcome["run_id"] and set(diff["baseline"]) >= {"system", "users"}

    second = json.loads(
        cli.invoke(app, ["check", "system", "--host", "lab-wp2", "--no-agents", "--json"]).output
    )[0]
    assert [a["agent"] for a in second["run"]["agents"]] == ["system"]
    assert not second["run"]["agents"][0]["baseline"] and second["run"]["agents"][0]["changes"] == []
    diff = json.loads(cli.invoke(app, ["diff", "--host", "lab-wp2", "--json"]).output)
    assert diff["run_id"] == second["run_id"] and diff["changes"] == [] and diff["baseline"] == []


def test_check_human_output_and_all(env: Path) -> None:
    result = cli.invoke(app, ["check", "--all", "--no-agents"])
    assert result.exit_code == 0, result.output
    assert "lab-wp1" in result.output and "lab-wp2" in result.output
    assert "baseline recorded" in result.output and "Claude:" not in result.output
    again = cli.invoke(app, ["diff", "--host", "lab-wp1"])
    assert "baseline" in again.output


def test_check_errors(env: Path) -> None:
    unknown = cli.invoke(app, ["check", "malwar", "--host", "lab-wp1", "--no-agents", "--json"])
    assert unknown.exit_code == 1 and "unknown agent" in json.loads(unknown.output)["error"]
    no_host = cli.invoke(app, ["check", "--no-agents", "--json"])
    assert no_host.exit_code == 1 and "no hosts" in json.loads(no_host.output)["error"]
    no_runs = cli.invoke(app, ["diff", "--host", "lab-wp1", "--json"])
    assert no_runs.exit_code == 1 and "no runs" in json.loads(no_runs.output)["error"]


def test_sites(env: Path) -> None:
    data = json.loads(cli.invoke(app, ["sites", "--host", "lab-wp1", "--json"]).output)
    assert [s["name"] for s in data["sites"]] == ["alpha.lab.test", "beta.lab.test"]
    table = cli.invoke(app, ["sites", "--host", "lab-wp1"])
    assert "alpha.lab.test" in table.output and "6.7.2" in table.output


def test_agents_commands(tmp_path: Path) -> None:
    listed = json.loads(cli.invoke(app, ["agents", "list", "--json"]).output)
    assert [a["name"] for a in listed] == [
        "activity",
        "correlator",
        "exposure",
        "health",
        "malware",
        "persistence",
        "system",
        "users",
        "wordpress",
    ]
    assert "system" in cli.invoke(app, ["agents", "list"]).output
    exported = json.loads(cli.invoke(app, ["agents", "export"]).output)
    assert exported["contract_version"] == 1 and len(exported["agents"]) == 9
    out = tmp_path / "catalog.json"
    written = cli.invoke(app, ["agents", "export", "--out", str(out), "--json"])
    assert json.loads(written.output) == {"written": str(out)} and json.loads(out.read_text())["agents"]


def test_state_migrates_from_v1_and_keeps_latest_snapshot_per_agent(tmp_path: Path) -> None:
    path = tmp_path / "handscheck.sqlite3"
    db = sqlite3.connect(path)
    db.execute(
        "CREATE TABLE hosts (name TEXT PRIMARY KEY, address TEXT NOT NULL, port INTEGER NOT NULL, "
        "user TEXT NOT NULL, key_path TEXT, host_key_fingerprint TEXT, added_at TEXT NOT NULL, "
        "last_tested_at TEXT, last_test_ok INTEGER)"
    )
    db.execute(
        "INSERT INTO hosts VALUES ('h', 'h', 22, 'u', NULL, NULL, '2026-11-01T00:00:00+00:00', NULL, NULL)"
    )
    db.execute("PRAGMA user_version = 1")
    db.commit()
    db.close()

    state = StandaloneState(path)
    assert state.get_host("h") is not None
    with sqlite3.connect(path) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    now = datetime.now(UTC)
    first = state.save_run(
        "h",
        started_at=now,
        finished_at=now,
        status="ok",
        data={},
        snapshots=[("system", None, 1, {"a": 1}), ("users", None, 1, {}), ("malware", "s1", 1, {"m": 1})],
    )
    second = state.save_run(
        "h",
        started_at=now,
        finished_at=now,
        status="ok",
        data={},
        snapshots=[("system", None, 1, {"a": 2}), ("malware", "s2", 1, {"m": 2})],
    )
    latest = {(s.agent, s.site): s for s in state.latest_snapshots("h")}
    assert latest["system", None].run_id == second and latest["system", None].facts == {"a": 2}
    assert latest["users", None].run_id == first
    assert latest["malware", "s1"].run_id == first and latest["malware", "s2"].run_id == second
    assert [r.id for r in state.recent_runs("h")] == [second, first]
    assert state.remove_host("h") and state.latest_snapshots("h") == [] and state.recent_runs("h") == []


def test_state_migrates_v2_snapshots_to_per_site(tmp_path: Path) -> None:
    path = tmp_path / "handscheck.sqlite3"
    db = sqlite3.connect(path)
    db.executescript(
        "CREATE TABLE hosts (name TEXT PRIMARY KEY, address TEXT NOT NULL, port INTEGER NOT NULL,"
        " user TEXT NOT NULL, key_path TEXT, host_key_fingerprint TEXT, added_at TEXT NOT NULL,"
        " last_tested_at TEXT, last_test_ok INTEGER);"
        "CREATE TABLE runs (id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT NOT NULL,"
        " started_at TEXT NOT NULL, finished_at TEXT NOT NULL, status TEXT NOT NULL, data TEXT NOT NULL);"
        "CREATE TABLE snapshots (run_id INTEGER NOT NULL, host TEXT NOT NULL, agent TEXT NOT NULL,"
        " agent_version INTEGER NOT NULL, taken_at TEXT NOT NULL, facts TEXT NOT NULL,"
        " PRIMARY KEY (run_id, agent));"
        "CREATE INDEX snapshots_host_agent ON snapshots (host, agent, run_id);"
        "INSERT INTO runs VALUES (1, 'h', '2026-11-14T00:00Z', '2026-11-14T00:00Z', 'ok', '{}');"
        "INSERT INTO snapshots VALUES (1, 'h', 'system', 1, '2026-11-14T00:00Z', '{\"a\": 1}');"
        "PRAGMA user_version = 2;"
    )
    db.close()
    state = StandaloneState(path)
    [snap] = state.latest_snapshots("h")
    assert (snap.agent, snap.site, snap.facts) == ("system", None, {"a": 1})
    now = datetime.now(UTC)
    state.save_run(
        "h", started_at=now, finished_at=now, status="ok", data={}, snapshots=[("malware", "s", 1, {})]
    )
    assert {(s.agent, s.site) for s in state.latest_snapshots("h")} == {("system", None), ("malware", "s")}
