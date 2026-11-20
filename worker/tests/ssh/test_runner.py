"""SSHRunner against an in-process asyncssh server (no Docker): policy, sudo, caps, timeouts, host keys."""

import asyncio
from pathlib import Path

import asyncssh
import pytest
from pydantic import SecretStr

from handscheck.contracts import HostTarget
from handscheck.ssh import runner as runner_mod
from handscheck.ssh.policy import PolicyViolation
from handscheck.ssh.pool import RunnerPool
from handscheck.ssh.runner import (
    HostKeyMismatch,
    SSHError,
    SSHRunner,
    SSHTarget,
    detect_sudo_failure,
)
from tests.fakessh import OS_RELEASE, FakeHost, target


async def test_runs_normalized_command_with_host_side_timeout(fake_host: FakeHost) -> None:
    async with SSHRunner(target(fake_host)) as r:
        result = await r.run("cat /etc/os-release")
    assert result.ok
    assert result.stdout == OS_RELEASE
    assert result.command == "cat /etc/os-release"
    assert fake_host.received == ["timeout -k 5 60 cat /etc/os-release"]
    assert r.commands_run == ["cat /etc/os-release"]


async def test_policy_violation_sends_nothing(fake_host: FakeHost) -> None:
    async with SSHRunner(target(fake_host)) as r:
        for command in ["rm -rf /", "cat /etc/passwd; id", "curl http://x", "cat /x > /tmp/y"]:
            with pytest.raises(PolicyViolation):
                await r.run(command)
        with pytest.raises(PolicyViolation):
            await r.run("cat /etc/passwd; id", sudo=True)
        with pytest.raises(PolicyViolation):
            await r.run(["tee", "/etc/passwd"], sudo=True)
    assert fake_host.received == []
    assert r.commands_run == []


async def test_quoting_reaches_host_literally(fake_host: FakeHost) -> None:
    async with SSHRunner(target(fake_host)) as r:
        result = await r.run(["grep", "-c", "a; rm -rf /", "/etc/passwd"])
    assert fake_host.received == ["timeout -k 5 60 grep -c 'a; rm -rf /' /etc/passwd"]
    assert result.stdout.strip() == "grep -c 'a; rm -rf /' /etc/passwd"


async def test_sudo_is_non_interactive(fake_host: FakeHost) -> None:
    async with SSHRunner(target(fake_host)) as r:
        result = await r.run(["ls", "/root"], sudo=True)
        as_www = await r.run("wp --version", sudo=True, sudo_user="www-data")
    assert result.ok and result.sudo
    assert fake_host.received[0].endswith("sudo -n -- ls /root")
    assert as_www.command == "sudo -n -u www-data -- wp --version"


async def test_sudo_failures_are_reported(fake_host: FakeHost) -> None:
    async with SSHRunner(target(fake_host)) as r:
        needs_password = await r.run(["id"], sudo=True)
        not_allowed = await r.run(["whoami"], sudo=True)
        plain_failure = await r.run(["cat", "/missing"])
    assert needs_password.sudo_failure == "password_required" and not needs_password.ok
    assert not_allowed.sudo_failure == "not_allowed"
    assert plain_failure.sudo_failure is None and plain_failure.exit_status == 1


async def test_output_is_capped_and_flagged(fake_host: FakeHost) -> None:
    async with SSHRunner(target(fake_host), max_output=250_000) as r:
        result = await r.run("cat /big")
        after = await r.run("cat /etc/os-release")  # the connection is still usable
    assert len(result.stdout) == 250_000
    assert result.stdout_truncated and result.truncated
    assert result.exit_status is None and not result.ok
    assert not result.timed_out and result.duration_s < 5
    assert after.ok


async def test_local_timeout(fake_host: FakeHost, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner_mod, "_LOCAL_GRACE", 0.0)
    monkeypatch.setattr(runner_mod, "_KILL_GRACE", 0)
    async with SSHRunner(target(fake_host)) as r:
        result = await r.run("cat /slow", timeout=1)
    assert result.timed_out and result.exit_status is None and not result.ok
    assert result.duration_s < 5


async def test_host_side_timeout_exit_124(fake_host: FakeHost) -> None:
    async with SSHRunner(target(fake_host)) as r:
        result = await r.run("cat /timeout-on-host")
    assert result.timed_out and not result.ok


async def test_connection_is_reused(fake_host: FakeHost) -> None:
    async with SSHRunner(target(fake_host)) as r:
        await r.run(["cat", "/first"])
        await asyncio.gather(*(r.run(["cat", f"/file{i}"]) for i in range(8)))  # > MAX_CHANNELS
    assert fake_host.connections == 1
    assert len(fake_host.received) == 9


async def test_first_contact_records_fingerprint(fake_host: FakeHost) -> None:
    async with SSHRunner(target(fake_host)) as r:
        pass
    assert r.host_key_fingerprint == fake_host.host_key.get_fingerprint("sha256")


async def test_pinned_key_matches(fake_host: FakeHost) -> None:
    pinned = fake_host.host_key.get_fingerprint("sha256")
    async with SSHRunner(target(fake_host, host_key_fingerprint=pinned)) as r:
        assert (await r.run("cat /etc/os-release")).ok


async def test_pinned_key_mismatch_refuses_before_auth(fake_host: FakeHost) -> None:
    other = asyncssh.generate_private_key("ssh-ed25519").get_fingerprint("sha256")
    r = SSHRunner(target(fake_host, host_key_fingerprint=other))
    with pytest.raises(HostKeyMismatch) as info:
        await r.connect()
    assert info.value.expected == other
    assert info.value.actual == fake_host.host_key.get_fingerprint("sha256")
    assert fake_host.auth_attempts == 0
    assert fake_host.received == []


async def test_wrong_key_is_an_ssh_error(fake_host: FakeHost) -> None:
    wrong = asyncssh.generate_private_key("ssh-ed25519").export_private_key("openssh").decode()
    with pytest.raises(SSHError, match="authentication failed"):
        await SSHRunner(target(fake_host, private_key=SecretStr(wrong))).connect()


async def test_unreachable_is_an_ssh_error(fake_host: FakeHost) -> None:
    with pytest.raises(SSHError, match="cannot connect"):
        await SSHRunner(target(fake_host, port=1), connect_timeout=5).connect()


async def test_key_file(fake_host: FakeHost, tmp_path: Path) -> None:
    key_path = tmp_path / "id"
    fake_host.client_key.write_private_key(key_path)
    async with SSHRunner(target(fake_host, private_key=None, key_path=key_path)) as r:
        assert (await r.run("cat /etc/os-release")).ok


def test_from_job_host_target_keeps_key_in_memory(fake_host: FakeHost) -> None:
    key_text = fake_host.client_key.export_private_key("openssh").decode()
    job_target = HostTarget(
        host_id="h1", name="web1", address="10.0.0.5", user="handscheck", private_key=SecretStr(key_text)
    )
    t = SSHTarget.from_host_target(job_target)
    assert t.key_path is None
    assert t.load_key().public_data == fake_host.client_key.public_data
    assert key_text not in repr(t)


@pytest.mark.parametrize(
    ("stderr", "expected"),
    [
        ("sudo: a password is required\n", "password_required"),
        ("sudo: a terminal is required to read the password\n", "password_required"),
        (
            "Sorry, user handscheck is not allowed to execute '/usr/bin/id' as root on lab-wp1.\n",
            "not_allowed",
        ),
        ("handscheck is not in the sudoers file.  This incident will be reported.\n", "not_allowed"),
        ("sudo: user handscheck may not run sudo on lab-wp1\n", "not_allowed"),
        ("ls: cannot access '/nope': No such file or directory\n", None),
    ],
)
def test_detect_sudo_failure(stderr: str, expected: str | None) -> None:
    assert detect_sudo_failure(1, stderr) == expected
    assert detect_sudo_failure(0, stderr) is None


async def test_pool_reuses_one_runner_per_host(fake_host: FakeHost) -> None:
    async with RunnerPool(default_timeout=30) as pool:
        first = pool.get(target(fake_host))
        assert pool.get(target(fake_host)) is first
        assert (await first.run("cat /etc/os-release")).ok
    assert fake_host.received == ["timeout -k 5 30 cat /etc/os-release"]
    assert first._conn is None  # closed with the pool
