"""M1 against the Docker lab hosts: `hc host test` passes on both; the policy holds over a real connection.

Run: docker compose up -d lab-db lab-wp1 lab-wp2 && docker compose run --rm worker pytest -m lab
The lab hosts install every .local/keys/*.pub at start; these tests use the private key next to it.
"""

import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from handscheck.cli import app
from handscheck.config import repo_root
from handscheck.ssh.policy import PolicyViolation
from handscheck.ssh.runner import SSHRunner, SSHTarget

pytestmark = pytest.mark.lab

EXPECTED_OS = {"lab-wp1": "24.04", "lab-wp2": "16.04"}
PROBE_FILE = "/tmp/handscheck-policy-probe"  # must never be created


def _lab_key() -> Path:
    if env := os.environ.get("HANDSCHECK_LAB_KEY"):
        return Path(env)
    root = repo_root()
    assert root is not None, "lab tests run from the repo checkout"
    for name in ("id_ed25519_handscheck", "id_ed25519_lab"):
        if (path := root / ".local" / "keys" / name).is_file():
            return path
    pytest.skip("no lab key in .local/keys/ (run `hc setup` or lab/smoke.sh, then restart the lab hosts)")


@pytest.fixture
def lab_key() -> Path:
    return _lab_key()


@pytest.fixture
def cli_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HANDSCHECK_STATE_DIR", str(tmp_path / "state"))


def _target(name: str, key: Path) -> SSHTarget:
    return SSHTarget(name=name, address=name, user="handscheck", key_path=key)


@pytest.mark.parametrize("host", sorted(EXPECTED_OS))
def test_host_test_passes(host: str, lab_key: Path, cli_env: None) -> None:
    runner = CliRunner()
    added = runner.invoke(app, ["host", "add", host, "--address", host, "--key", str(lab_key), "--json"])
    assert added.exit_code == 0, added.output

    first = runner.invoke(app, ["host", "test", host, "--json"])
    report = json.loads(first.output)
    assert first.exit_code == 0 and report["ok"], report
    assert report["user"] == "handscheck"
    assert report["os"]["id"] == "ubuntu" and report["os"]["version_id"] == EXPECTED_OS[host]
    assert report["sudo"]["ok"]
    assert report["wp_cli"]["present"] and report["wp_cli"]["version"]
    assert report["host_key_fingerprint"].startswith("SHA256:")
    assert not report["host_key_pinned"]
    if EXPECTED_OS[host] == "16.04":  # coreutils 8.25 has no statx: %W is 0
        assert not report["birth_time"]["supported"] and report["birth_time"]["fallback"] == "ctime"

    second = json.loads(runner.invoke(app, ["host", "test", host, "--json"]).output)
    assert second["ok"] and second["host_key_pinned"]
    assert second["host_key_fingerprint"] == report["host_key_fingerprint"]


@pytest.mark.parametrize("host", sorted(EXPECTED_OS))
async def test_policy_refuses_writes_over_a_real_connection(host: str, lab_key: Path) -> None:
    async with SSHRunner(_target(host, lab_key)) as runner:
        refused = [
            f"touch {PROBE_FILE}",
            f"sudo tee {PROBE_FILE}",
            f"cat /etc/hostname; touch {PROBE_FILE}",
            f"cat /etc/hostname > {PROBE_FILE}",
            f"find /tmp -maxdepth 0 -exec touch {PROBE_FILE} \\;",
            "curl http://example.com",
            "bash -c id",
            "systemctl restart apache2",
        ]
        for command in refused:
            with pytest.raises(PolicyViolation):
                await runner.run(command)
        assert runner.commands_run == []  # nothing was sent

        # The probe file was never created, and the connection still works for reads.
        check = await runner.run(["test", "-e", PROBE_FILE])
        assert check.exit_status == 1
        assert (await runner.run(["cat", "/etc/hostname"])).ok


@pytest.mark.parametrize("host", sorted(EXPECTED_OS))
async def test_sudo_outside_sudoers_is_reported(host: str, lab_key: Path) -> None:
    async with SSHRunner(_target(host, lab_key)) as runner:
        allowed = await runner.run(["ls", "-d", "/root/."], sudo=True)
        outside = await runner.run(["id"], sudo=True)  # allowed by the policy, not by the lab sudoers
    assert allowed.ok
    assert not outside.ok and outside.sudo_failure == "password_required"
