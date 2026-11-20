"""LocalRunner (Track S): real subprocesses in the worker container, held to the SSH command policy."""

import asyncio
import os
from pathlib import Path
from typing import Any

import pytest

from handscheck.ssh import local as local_mod
from handscheck.ssh.local import SAFE_PATH, LocalRunner
from handscheck.ssh.policy import PolicyViolation
from handscheck.ssh.runner import with_sudo


async def test_runs_allowed_command_without_a_shell() -> None:
    async with LocalRunner("me") as r:
        result = await r.run("cat /etc/os-release")
    assert result.ok and "ID=" in result.stdout
    assert result.command == "cat /etc/os-release"
    assert r.commands_run == ["cat /etc/os-release"]
    assert r.host_key_fingerprint is None


async def test_policy_violation_starts_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    spawned: list[tuple[Any, ...]] = []

    async def spy(*argv: Any, **kwargs: Any) -> Any:
        spawned.append(argv)
        raise AssertionError("must not spawn")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spy)
    r = LocalRunner("me")
    for command in ["rm -rf /", "cat /etc/passwd; id", "curl http://x", "cat /x > /tmp/y", "sh -c id"]:
        with pytest.raises(PolicyViolation):
            await r.run(command)
    with pytest.raises(PolicyViolation):
        await r.run(["tee", "/etc/passwd"], sudo=True)
    with pytest.raises(PolicyViolation):
        await r.run("cat /etc/passwd; id", sudo=True)
    assert spawned == [] and r.commands_run == []


async def test_shell_metacharacters_stay_literal(tmp_path: Path) -> None:
    marker = tmp_path / "pwned"
    async with LocalRunner("me") as r:
        result = await r.run(["grep", "-c", f"x; touch {marker}", "/etc/os-release"])
        expanded = await r.run(["ls", "-d", str(tmp_path / "*")])
    assert result.exit_status == 1 and result.stdout.strip() == "0"  # a pattern, not a command
    assert not marker.exists()
    assert expanded.exit_status != 0  # no glob expansion: there is no file literally named "*"


async def test_fixed_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake = tmp_path / "cat"
    fake.write_text("#!/bin/sh\necho hijacked\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")
    monkeypatch.setenv("LD_PRELOAD", "/nonexistent.so")
    calls: list[dict[str, Any]] = []
    real = asyncio.create_subprocess_exec

    async def spy(*argv: Any, **kwargs: Any) -> Any:
        calls.append({"argv": argv, **kwargs})
        return await real(*argv, **kwargs)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spy)
    result = await LocalRunner("me").run(["cat", "/etc/hostname"])
    assert "hijacked" not in result.stdout and result.ok
    [call] = calls
    assert call["env"] == {"LC_ALL": "C", "LANG": "C", "PATH": SAFE_PATH}
    assert call["argv"][:4] == ("timeout", "-k", "5", "60")
    assert call["argv"][4:] == ("cat", "/etc/hostname")
    assert call["stdin"] == asyncio.subprocess.DEVNULL and call["start_new_session"]


async def test_sudo_prefix_matches_the_ssh_runner(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[Any, ...]] = []
    real = asyncio.create_subprocess_exec

    async def spy(*argv: Any, **kwargs: Any) -> Any:
        seen.append(argv)
        return await real("true", **kwargs)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spy)
    r = LocalRunner("me")
    result = await r.run(["ls", "/root"], sudo=True)
    as_www = await r.run("wp --version", sudo=True, sudo_user="www-data")
    assert seen[0][4:] == ("sudo", "-n", "--", "ls", "/root")
    assert as_www.command == "sudo -n -u www-data -- wp --version"
    assert result.sudo and as_www.sudo
    assert with_sudo("id", sudo=False, sudo_user=None) == "id"
    assert with_sudo(["id"], sudo=True, sudo_user="www-data") == ["sudo", "-n", "-u", "www-data", "--", "id"]


async def test_output_is_capped_and_flagged() -> None:
    r = LocalRunner("me", max_output=1000)
    result = await r.run(["cat", "/dev/zero"], timeout=20)
    assert len(result.stdout) == 1000 and result.stdout_truncated
    assert result.exit_status is None and not result.ok and not result.timed_out
    assert result.duration_s < 10


async def test_timeout_stops_the_command(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(local_mod, "_KILL_GRACE", 1)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)  # cat blocks opening it: nobody ever writes
    result = await LocalRunner("me").run(["cat", str(fifo)], timeout=1)
    assert result.timed_out and result.exit_status is None and not result.ok
    assert result.duration_s < 5


async def test_failures_are_reported_not_raised() -> None:
    result = await LocalRunner("me").run(["cat", "/definitely/missing"])
    assert result.exit_status == 1 and "No such file" in result.stderr and result.sudo_failure is None
