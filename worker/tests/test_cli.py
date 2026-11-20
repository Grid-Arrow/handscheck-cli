import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from handscheck.cli import app
from handscheck.ssh.probe import BirthTimeStatus, OSInfo, ProbeReport, SudoStatus, WpCliStatus
from handscheck.standalone import service

runner = CliRunner()


def test_help_lists_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "contracts" in result.output
    assert "version" in result.output


def test_version_json() -> None:
    result = runner.invoke(app, ["version", "--json"])
    assert result.exit_code == 0
    assert "version" in json.loads(result.output)


@pytest.fixture
def standalone_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("HANDSCHECK_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("HANDSCHECK_KEY_DIR", str(tmp_path / "keys"))
    return tmp_path


def test_help_lists_standalone_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert "setup" in result.output and "host" in result.output
    host_help = runner.invoke(app, ["host", "--help"])
    for sub in ("add", "list", "remove", "test"):
        assert sub in host_help.output


def test_setup_and_host_commands_json(standalone_env: Path) -> None:
    setup = runner.invoke(app, ["setup", "--from", "192.0.2.1", "--json"])
    assert setup.exit_code == 0, setup.output
    data = json.loads(setup.output)
    assert data["created"] and data["key_path"] == str(standalone_env / "keys" / "id_ed25519_handscheck")
    assert data["authorized_keys_line"].startswith('from="192.0.2.1",')

    added = runner.invoke(app, ["host", "add", "lab-wp1", "--address", "lab-wp1", "--json"])
    assert added.exit_code == 0, added.output
    assert json.loads(added.output)["name"] == "lab-wp1"

    dup = runner.invoke(app, ["host", "add", "lab-wp1", "--address", "lab-wp1", "--json"])
    assert dup.exit_code == 1 and "already exists" in json.loads(dup.output)["error"]

    listed = runner.invoke(app, ["host", "list", "--json"])
    assert [h["name"] for h in json.loads(listed.output)] == ["lab-wp1"]

    removed = runner.invoke(app, ["host", "remove", "lab-wp1", "--json"])
    assert json.loads(removed.output) == {"removed": "lab-wp1"}
    assert json.loads(runner.invoke(app, ["host", "list", "--json"]).output) == []

    unknown = runner.invoke(app, ["host", "test", "nope", "--json"])
    assert unknown.exit_code == 1 and "unknown host" in json.loads(unknown.output)["error"]


def test_host_test_output(standalone_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    report = ProbeReport(
        host="web1",
        address="10.0.0.5",
        port=22,
        ssh_ok=True,
        user="handscheck",
        host_key_fingerprint="SHA256:abc",
        os=OSInfo(id="ubuntu", version_id="16.04", pretty_name="Ubuntu 16.04.7 LTS"),
        sudo=SudoStatus(ok=False, failure="password_required", detail="sudo wanted a password"),
        wp_cli=WpCliStatus(present=False),
        birth_time=BirthTimeStatus(supported=False, fallback="ctime"),
    )
    monkeypatch.setattr(service, "run_host_test", lambda settings, name, timeout: report)
    as_json = runner.invoke(app, ["host", "test", "web1", "--json"])
    assert as_json.exit_code == 1
    data = json.loads(as_json.output)
    assert data["ok"] is False and data["sudo"]["failure"] == "password_required"

    text = runner.invoke(app, ["host", "test", "web1"])
    assert text.exit_code == 1
    assert "Ubuntu 16.04.7 LTS" in text.output and "using ctime" in text.output
    assert "host test failed" in text.output
