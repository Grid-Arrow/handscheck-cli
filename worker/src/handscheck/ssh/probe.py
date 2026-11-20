"""Connection test for a host (`hc host test`, and later the control plane's "test connection").

Checks: SSH + the user we log in as, read-only sudo, OS name/version, wp-cli, and whether `stat %W` (file
birth time) works. Old kernels/coreutils (Ubuntu 16.04) print 0 for %W; checks then fall back to ctime.
Parsing is pure and unit-tested; `probe_host` only runs read-only commands through the runner and its policy.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from handscheck.ssh.runner import CommandResult, HostKeyMismatch, SSHError, SSHRunner

BIRTH_TIME_SAMPLE = "/etc/passwd"
SUDO_PROBE = ["ls", "-d", "/root/."]  # needs root (/root is 0700) and is in the read-only sudoers set


class OSInfo(BaseModel):
    id: str | None = None
    name: str | None = None
    version_id: str | None = None
    pretty_name: str | None = None


class SudoStatus(BaseModel):
    ok: bool
    failure: Literal["password_required", "not_allowed", "error"] | None = None
    detail: str | None = None


class WpCliStatus(BaseModel):
    present: bool
    path: str | None = None
    version: str | None = None


class BirthTimeStatus(BaseModel):
    supported: bool
    fallback: Literal["ctime"] | None = None
    sample_path: str = BIRTH_TIME_SAMPLE
    raw: str | None = None


class ProbeReport(BaseModel):
    host: str
    address: str
    port: int
    ssh_ok: bool
    user: str | None = None
    host_key_fingerprint: str | None = None
    host_key_pinned: bool = False
    """True when the fingerprint matched a previously pinned one."""
    os: OSInfo | None = None
    sudo: SudoStatus | None = None
    wp_cli: WpCliStatus | None = None
    birth_time: BirthTimeStatus | None = None
    errors: list[str] = Field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.ssh_ok and self.sudo is not None and self.sudo.ok and not self.errors


# ── pure parsers ─────────────────────────────────────────────────────────────


def parse_os_release(text: str) -> OSInfo:
    values: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return OSInfo(
        id=values.get("ID"),
        name=values.get("NAME"),
        version_id=values.get("VERSION_ID"),
        pretty_name=values.get("PRETTY_NAME"),
    )


def parse_birth_time(stdout: str) -> BirthTimeStatus:
    """`stat -c '%W %Z' FILE` → supported when %W is a positive epoch. 0, '-' or '?' mean unknown."""
    raw = stdout.strip()
    first = raw.split()[0] if raw else ""
    supported = first.isdigit() and int(first) > 0
    return BirthTimeStatus(supported=supported, fallback=None if supported else "ctime", raw=raw or None)


def parse_wp_version(stdout: str) -> str | None:
    """`wp --version` → 'WP-CLI 2.11.0' → '2.11.0'."""
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("WP-CLI "):
            return line.removeprefix("WP-CLI ").strip() or None
    return None


def sudo_status(result: CommandResult) -> SudoStatus:
    if result.ok:
        return SudoStatus(ok=True)
    if result.sudo_failure is not None:
        detail = {
            # With -n, sudo says "a password is required" both when the user needs a password and when the
            # command simply isn't in the NOPASSWD rules (seen on Ubuntu 16.04 and 24.04).
            "password_required": "sudo wanted a password: the probe command (ls) is not in the NOPASSWD "
            "sudoers rules, or sudo needs a password for this user",
            "not_allowed": "sudoers does not allow the read-only probe command (ls)",
        }[result.sudo_failure]
        return SudoStatus(ok=False, failure=result.sudo_failure, detail=detail)
    detail = result.stderr.strip()[:300] or f"exit status {result.exit_status}"
    return SudoStatus(ok=False, failure="error", detail=detail)


# ── the probe ────────────────────────────────────────────────────────────────


async def probe_host(runner: SSHRunner, *, timeout: float = 20.0) -> ProbeReport:
    target = runner.target
    report = ProbeReport(host=target.name, address=target.address, port=target.port, ssh_ok=False)
    try:
        await runner.connect()
    except HostKeyMismatch as exc:
        report.errors.append(str(exc))
        return report
    except SSHError as exc:
        report.errors.append(str(exc))
        return report

    report.host_key_fingerprint = runner.host_key_fingerprint
    report.host_key_pinned = target.host_key_fingerprint is not None
    try:
        whoami = await runner.run(["id", "-un"], timeout=timeout)
        report.ssh_ok = whoami.ok
        report.user = whoami.stdout.strip() or None
        if not whoami.ok:
            report.errors.append(f"`id -un` failed: {whoami.stderr.strip()[:300]}")
            return report

        os_release = await runner.run(["cat", "/etc/os-release"], timeout=timeout)
        if os_release.ok:
            report.os = parse_os_release(os_release.stdout)
        else:
            report.errors.append("could not read /etc/os-release")

        report.sudo = sudo_status(await runner.run(SUDO_PROBE, sudo=True, timeout=timeout))

        which = await runner.run(["which", "wp"], timeout=timeout)
        wp_path = which.stdout.strip().splitlines()[0] if which.ok and which.stdout.strip() else None
        if wp_path:
            version = await runner.run([wp_path, "--version"], timeout=timeout)
            report.wp_cli = WpCliStatus(present=True, path=wp_path, version=parse_wp_version(version.stdout))
        else:
            report.wp_cli = WpCliStatus(present=False)

        birth = await runner.run(["stat", "-c", "%W %Z", BIRTH_TIME_SAMPLE], timeout=timeout)
        if birth.ok:
            report.birth_time = parse_birth_time(birth.stdout)
        else:
            report.errors.append(f"`stat %W` failed: {birth.stderr.strip()[:300]}")
    except SSHError as exc:
        report.errors.append(str(exc))
    return report
