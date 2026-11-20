import pytest

from handscheck.ssh.probe import parse_birth_time, parse_os_release, parse_wp_version, probe_host
from handscheck.ssh.runner import SSHRunner
from tests.fakessh import FakeHost, target

# Captured from the lab hosts.
OS_RELEASE_2404 = """PRETTY_NAME="Ubuntu 24.04.5 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.5 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
"""
OS_RELEASE_1604 = """NAME="Ubuntu"
VERSION="16.04.7 LTS (Xenial Xerus)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 16.04.7 LTS"
VERSION_ID="16.04"
"""


def test_parse_os_release() -> None:
    noble = parse_os_release(OS_RELEASE_2404)
    assert (noble.id, noble.version_id, noble.pretty_name) == ("ubuntu", "24.04", "Ubuntu 24.04.5 LTS")
    xenial = parse_os_release(OS_RELEASE_1604)
    assert (xenial.name, xenial.version_id) == ("Ubuntu", "16.04")


def test_parse_os_release_tolerates_junk() -> None:
    info = parse_os_release("# comment\n\nnot a pair\nID='debian'\n")
    assert info.id == "debian" and info.version_id is None


@pytest.mark.parametrize(
    ("stdout", "supported"),
    [
        ("1794619897 1794619897\n", True),  # 24.04 (statx)
        ("0 1794619897\n", False),  # 16.04: coreutils 8.25 prints 0
        ("- 1794619897\n", False),
        ("? 1794619897\n", False),
        ("", False),
    ],
)
def test_parse_birth_time(stdout: str, supported: bool) -> None:
    status = parse_birth_time(stdout)
    assert status.supported is supported
    assert status.fallback == (None if supported else "ctime")


def test_parse_wp_version() -> None:
    assert parse_wp_version("WP-CLI 2.11.0\n") == "2.11.0"
    assert parse_wp_version("PHP Warning: x\nWP-CLI 2.10.0\n") == "2.10.0"
    assert parse_wp_version("bash: wp: command not found") is None


async def test_probe_happy_path(fake_host: FakeHost) -> None:
    async with SSHRunner(target(fake_host)) as runner:
        report = await probe_host(runner)
    assert report.ok, report.errors
    assert report.user == "handscheck"
    assert report.os is not None and report.os.version_id == "24.04"
    assert report.sudo is not None and report.sudo.ok
    assert report.wp_cli is not None and report.wp_cli.version == "2.11.0"
    assert report.birth_time is not None and report.birth_time.supported
    assert report.host_key_fingerprint == fake_host.host_key.get_fingerprint("sha256")
    assert not report.host_key_pinned
    # Every command was read-only and went through the policy (the runner records the normalized form).
    assert runner.commands_run == [
        "id -un",
        "cat /etc/os-release",
        "sudo -n -- ls -d /root/.",
        "which wp",
        "/usr/local/bin/wp --version",
        "stat -c '%W %Z' /etc/passwd",
    ]


async def test_probe_reports_sudo_and_birth_problems(fake_host: FakeHost) -> None:
    fake_host.sudo_works = False
    fake_host.birth = "0 1794619897"
    async with SSHRunner(target(fake_host)) as runner:
        report = await probe_host(runner)
    assert report.ssh_ok and not report.ok
    assert report.sudo is not None and report.sudo.failure == "password_required"
    assert report.birth_time is not None and report.birth_time.fallback == "ctime"


async def test_probe_reports_connection_failure(fake_host: FakeHost) -> None:
    runner = SSHRunner(target(fake_host, host_key_fingerprint="SHA256:not-the-key"))
    report = await probe_host(runner)
    assert not report.ssh_ok and not report.ok
    assert "host key for fake changed" in report.errors[0]
    assert fake_host.received == []
