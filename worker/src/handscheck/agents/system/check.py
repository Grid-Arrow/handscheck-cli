"""`system` check: root accounts, unpackaged systemd units and set-id files, sudo binary mode, preload,
modprobe files, package inventory and integrity, kernel, reboot and pending updates.

All commands are read-only and run through the SSH command policy. They are single words lists (no pipes or
globs) and work on Ubuntu 16.04 (findutils 4.6, dpkg 1.18) through 24.04 (usr-merged).
"""

from __future__ import annotations

import fnmatch
import posixpath
import re
from typing import Any

from pydantic import BaseModel

from handscheck.agents._framework.check import (
    Check,
    CheckContext,
    DiffView,
    Facts,
    Output,
    Raw,
    canonical_path,
    grep_h_lines,
    output_warning,
    parse_dpkg_search,
    path_aliases,
    split_fields,
)
from handscheck.agents._framework.findings import FindingItem
from handscheck.ssh.probe import parse_os_release

UNIT_DIRS = (
    "/etc/systemd/system",
    "/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/usr/local/lib/systemd/system",
)
UNIT_PATTERN = "*/systemd/system/*"
_UNIT_DIR_PREFIXES = tuple(canonical_path(d) + "/" for d in UNIT_DIRS)
SUDO_BINARY = "/usr/bin/sudo"
EXPECTED_SUDO_MODE = "4755"
SMALL_FILES = (
    "/etc/os-release",
    "/proc/sys/kernel/random/boot_id",
    "/proc/uptime",
    "/etc/ld.so.preload",
    "/run/reboot-required",
    "/run/reboot-required.pkgs",
    "/var/lib/update-notifier/updates-available",
)
UNIT_KEYS = ("Description", "ExecStart", "ExecStartPre", "ExecStartPost", "User", "OnCalendar", "WantedBy")
MAX_UNIT_FILES = 50
MAX_LOOKUP_PATHS = 400
EXTRA_UID0_RULE = "system.extra-uid0"
SUDO_RULE = "system.sudo-binary-mode"
SETID_RULE = "system.unpackaged-setid-system-bin"
# Canonical (usr-merge folded) /usr/bin, /usr/sbin, /bin, /sbin: packages own everything there; local
# installs go to /usr/local or /opt.
SYSTEM_BIN_DIRS = ("/bin/", "/sbin/")


def _exec_path(unit_line: str) -> str:
    """ExecStart=-/usr/sbin/x --flag → /usr/sbin/x (systemd's -@:+! prefixes stripped)."""
    key, _, value = unit_line.partition("=")
    words = value.strip().lstrip("-@:+!").split()
    return words[0] if key.startswith("Exec") and words else ""


class UnitFile(BaseModel):
    path: str
    kind: str
    """file | link"""
    target: str | None = None
    owner: str | None = None
    mtime: int | None = None
    enabled_by: list[str] = []
    """Links (e.g. in multi-user.target.wants) that point at this unit."""
    lines: list[str] = []
    """Key lines (ExecStart=, User=, …) from the unit file."""


class SetIdFile(BaseModel):
    path: str
    mode: str
    owner: str
    group: str


class OwnedFile(BaseModel):
    path: str
    package: str | None = None


class BinaryMode(BaseModel):
    path: str
    mode: str
    owner: str
    group: str


class VerifyIssue(BaseModel):
    path: str
    flags: str


class Updates(BaseModel):
    pending: int | None = None
    security: int | None = None


class SystemFacts(Facts):
    os_pretty_name: str | None = None
    os_version_id: str | None = None
    kernel: str | None = None
    boot_id: str | None = None
    boot_time: int | None = None
    """Approximate boot time (epoch seconds), from /proc/uptime and the host clock."""
    uptime_s: int | None = None
    uid0_accounts: list[str] = []
    sudo_binary: BinaryMode | None = None
    sudo_binary_ok: bool | None = None
    """True when /usr/bin/sudo is 4755 root:root (chmod 000 sudo is an incident symptom)."""
    ld_so_preload: list[str] = []
    unpackaged_units: list[UnitFile] = []
    dangling_unit_links: list[UnitFile] = []
    """Unit links whose target doesn't exist (leftovers of removed packages): inert, listed for cleanup."""
    packaged_units: int = 0
    units_matched_via_usr_merge: int = 0
    """Packaged units found under a /lib or /usr/lib name that dpkg doesn't know (it recorded the other one).
    A naive `dpkg -S` reports these as unpackaged on 24.04; 0 on hosts without the /usr merge."""
    unpackaged_setid_files: list[SetIdFile] = []
    setid_files: int = 0
    modprobe_files: list[OwnedFile] = []
    packages: dict[str, str] = {}
    reboot_required: bool = False
    reboot_required_packages: list[str] = []
    updates: Updates | None = None
    verified_packages: list[str] = []
    tampered_files: list[VerifyIssue] = []
    """dpkg --verify md5 mismatches on non-conffiles, and missing binaries."""

    def diff_view(self) -> DiffView:
        attributes: dict[str, Any] = {
            "os": self.os_pretty_name,
            "kernel": self.kernel,
            "ld_so_preload": self.ld_so_preload,
            "reboot_required": self.reboot_required,
        }
        if self.sudo_binary:
            b = self.sudo_binary
            attributes["sudo_binary"] = f"{b.mode} {b.owner}:{b.group}"
        return {
            "boot": {"boot_id": self.boot_id} if self.boot_id else {},
            "attributes": attributes,
            "uid0_accounts": dict.fromkeys(self.uid0_accounts, True),
            "unpackaged_units": {
                u.path: {"kind": u.kind, "target": u.target, "lines": u.lines} for u in self.unpackaged_units
            },
            "unpackaged_setid_files": {
                f.path: f"{f.mode} {f.owner}:{f.group}" for f in self.unpackaged_setid_files
            },
            "modprobe_files": {f.path: f.package for f in self.modprobe_files},
            "packages": dict(self.packages),
            "tampered_files": {t.path: t.flags for t in self.tampered_files},
        }

    def metrics(self) -> dict[str, float]:
        m: dict[str, float] = {
            "packages_installed": len(self.packages),
            "uid0_accounts": len(self.uid0_accounts),
            "unpackaged_units": len(self.unpackaged_units),
            "unpackaged_setid_files": len(self.unpackaged_setid_files),
            "tampered_files": len(self.tampered_files),
            "reboot_required": int(self.reboot_required),
        }
        if self.updates and self.updates.pending is not None:
            m["pending_updates"] = self.updates.pending
        if self.updates and self.updates.security is not None:
            m["security_updates"] = self.updates.security
        if self.uptime_s is not None:
            m["uptime_days"] = round(self.uptime_s / 86400, 2)
        return m


# ── collect ──────────────────────────────────────────────────────────────────


class SystemCheck(Check[SystemFacts]):
    name = "system"
    facts_model = SystemFacts

    async def collect(self, ctx: CheckContext, settings: dict[str, Any]) -> dict[str, Output]:
        raw: dict[str, Output] = {}
        raw["passwd"] = await ctx.run(["cat", "/etc/passwd"])
        raw["kernel"] = await ctx.run(["uname", "-r"])
        raw["now"] = await ctx.run(["date", "+%s"])
        raw["files"] = await ctx.run(["grep", "-s", "-H", "", "--", *SMALL_FILES])
        raw["sudo_stat"] = await ctx.run(["stat", "--printf", r"%n\t%a\t%U\t%G\n", SUDO_BINARY])
        raw["units"] = await collect_units(ctx)
        raw["units_owned"] = await ctx.run(["dpkg-query", "-S", UNIT_PATTERN])
        candidates = unpackaged_unit_paths(raw["units"], raw["units_owned"], settings)
        if candidates:
            pattern = "^(" + "|".join(UNIT_KEYS) + ")="
            raw["unit_lines"] = await ctx.run(
                ["grep", "-s", "-H", "-E", pattern, "--", *candidates[:MAX_UNIT_FILES]]
            )
        raw["modprobe"] = await ctx.run(
            ["find", "/etc/modprobe.d", "-maxdepth", "1", "-type", "f", "-printf", r"%p\n"]
        )
        if settings["setid_scan"]:
            prune: list[str] = []
            for i, skip in enumerate(settings["setid_skip_dirs"]):
                prune += (["-o"] if i else []) + ["-path", skip]
            raw["setid"] = await ctx.run_privileged(
                [
                    "find",
                    "/",
                    "-xdev",
                    *(["(", *prune, ")", "-prune", "-o"] if prune else []),
                    "(",
                    "-perm",
                    "-4000",
                    "-o",
                    "-perm",
                    "-2000",
                    ")",
                    "-type",
                    "f",
                    "-printf",
                    r"%p\t%m\t%u\t%g\n",
                ],
                timeout=settings["setid_scan_timeout_s"],
            )
        lookup = sorted(
            {p for p in raw["modprobe"].lines()} | {f[0] for f in _setid_rows(raw.get("setid", Output()))}
        )[:MAX_LOOKUP_PATHS]
        if lookup:
            # Batched: a host can have hundreds of set-id files (and the policy caps a command's length).
            raw["owned_lookup"] = await ctx.run_batched(
                ["dpkg-query", "-S"], _with_aliases(lookup), separator=False
            )
        raw["packages"] = await ctx.run(
            ["dpkg-query", "-W", "-f", r"${binary:Package}\t${Version}\t${Status}\n"], max_output=4_000_000
        )
        installed = parse_packages(raw["packages"].stdout)
        to_verify = [p for p in settings["verify_packages"] if p in installed]
        if settings["dpkg_verify"] and (to_verify or not settings["verify_packages"]):
            raw["verify"] = await ctx.run_privileged(
                ["dpkg", "--verify", *to_verify], timeout=settings["dpkg_verify_timeout_s"]
            )
        return raw

    def guaranteed_findings(self, facts: dict[str, Any]) -> list[FindingItem]:
        """Root-level backdoors of the Oct 2026 incident that the facts prove on their own: a second uid-0
        account, a broken sudo binary (the lockout) and an unpackaged set-uid file in a system bin directory
        (the fake service's "binary"). Reported every time, not only when Claude mentions them."""
        out = []
        for name in facts.get("uid0_accounts") or []:
            if name == "root":
                continue
            out.append(
                FindingItem(
                    kind="extra_uid0",
                    subject=name,
                    severity="critical",
                    confidence="high",
                    title=f"Second root account: {name} has uid 0",
                    summary=(
                        f"The account {name} has user id 0 in /etc/passwd, so logging in as it is logging "
                        "in as root. The October 2026 attackers added one after gaining root. Ubuntu never "
                        "creates one."
                    ),
                    evidence=[f"uid0_accounts: {facts.get('uid0_accounts')}"],
                    rule_ids=[EXTRA_UID0_RULE],
                    recommended_action=(
                        f"If nobody on your team created {name}, lock it (usermod -L -s /usr/sbin/nologin "
                        f"{name}), check its authorized_keys and treat the server as compromised."
                    ),
                )
            )
        sudo = facts.get("sudo_binary") or {}
        if facts.get("sudo_binary_ok") is False and sudo:
            mode, owner, group = sudo.get("mode"), sudo.get("owner"), sudo.get("group")
            path = str(sudo.get("path") or SUDO_BINARY)
            out.append(
                FindingItem(
                    kind="sudo_binary_tampered",
                    subject=path,
                    severity="high",
                    confidence="high",
                    title=(
                        f"{path} is {mode} {owner}:{group} (expected {EXPECTED_SUDO_MODE} root:root): "
                        "sudo is broken"
                    ),
                    summary=(
                        f"{path} has mode {mode}, owner {owner}:{group}. sudo needs {EXPECTED_SUDO_MODE} "
                        "root:root, so admins cannot use it. In the October 2026 incident the attacker ran "
                        "chmod 000 on it to lock admins out; it is how the break-in was noticed."
                    ),
                    evidence=[f"sudo_binary: {path} {mode} {owner}:{group}"],
                    rule_ids=[SUDO_RULE],
                    recommended_action=(
                        f"From a root console, restore it (chown root:root {path}; chmod "
                        f"{EXPECTED_SUDO_MODE} {path}), then find out who changed it: it is usually a "
                        "sign of a break-in."
                    ),
                )
            )
        units = facts.get("unpackaged_units") or []
        for f in facts.get("unpackaged_setid_files") or []:
            path = str(f.get("path", ""))
            if not canonical_path(path).startswith(SYSTEM_BIN_DIRS):
                continue
            run_by = [
                posixpath.basename(str(u.get("path", "")))
                for u in units
                if any(
                    canonical_path(_exec_path(line)) == canonical_path(path) for line in u.get("lines") or []
                )
            ]
            started = f", started by {', '.join(run_by)}" if run_by else ""
            out.append(
                FindingItem(
                    kind="unpackaged_setid",
                    subject=path,
                    severity="critical",
                    confidence="high",
                    title=f"Set-uid file no package owns: {path} ({f.get('mode')} {f.get('owner')}){started}",
                    summary=(
                        f"{path} is set-uid/set-gid (mode {f.get('mode')}, owner {f.get('owner')}) in a "
                        "system binary directory, but no installed package owns it. Packages install "
                        "everything there; a hand-placed set-uid file is how an attacker keeps root"
                        + (f", and the unpackaged service {', '.join(run_by)} runs it." if run_by else ".")
                    ),
                    evidence=[
                        f"unpackaged_setid_files: {path} {f.get('mode')} {f.get('owner')}:{f.get('group')}"
                    ]
                    + [f"unpackaged_units: {u} runs {path}" for u in run_by],
                    rule_ids=[SETID_RULE],
                    recommended_action=(
                        f"If nobody on your team installed it, copy {path} aside for analysis, remove its "
                        "set-uid bit, disable any service that runs it, and treat the server as compromised."
                    ),
                )
            )
        return out

    def parse(self, raw: Raw, settings: dict[str, Any]) -> SystemFacts:
        warnings = [w for key, out in raw.items() if (w := output_warning(key, out))]
        facts = SystemFacts(warnings=warnings)

        passwd = raw.get("passwd", Output.missing())
        facts.uid0_accounts = uid0_accounts(passwd.stdout)
        if not passwd.ok:
            facts.warnings.append("could not read /etc/passwd")

        facts.kernel = raw.get("kernel", Output.missing()).stdout.strip() or None
        files = grep_h_lines(raw.get("files", Output.missing()).stdout)
        os_info = parse_os_release("\n".join(files.get("/etc/os-release", [])))
        facts.os_pretty_name, facts.os_version_id = os_info.pretty_name, os_info.version_id
        boot_id = files.get("/proc/sys/kernel/random/boot_id", [])
        facts.boot_id = boot_id[0].strip() if boot_id else None
        facts.uptime_s, facts.boot_time = parse_uptime(
            files.get("/proc/uptime", []), raw.get("now", Output.missing()).stdout
        )
        facts.ld_so_preload = [
            line.strip()
            for line in files.get("/etc/ld.so.preload", [])
            if line.strip() and not line.strip().startswith("#")
        ]
        facts.reboot_required = "/run/reboot-required" in files
        facts.reboot_required_packages = sorted(
            {p.strip() for p in files.get("/run/reboot-required.pkgs", []) if p.strip()}
        )
        facts.updates = parse_updates_available(files.get("/var/lib/update-notifier/updates-available", []))

        facts.sudo_binary = parse_stat_line(raw.get("sudo_stat", Output.missing()).stdout)
        if facts.sudo_binary is not None:
            b = facts.sudo_binary
            facts.sudo_binary_ok = b.mode == EXPECTED_SUDO_MODE and b.owner == "root" and b.group == "root"

        units = analyze_units(
            raw.get("units", Output.missing()),
            raw.get("units_owned", Output.missing()),
            raw.get("unit_lines", Output.missing()),
            settings,
        )
        facts.unpackaged_units = units.unpackaged
        facts.dangling_unit_links = units.dangling
        facts.packaged_units = units.packaged
        facts.units_matched_via_usr_merge = units.via_usr_merge
        if not raw.get("units_owned", Output.missing()).lines():
            facts.warnings.append("dpkg knows no systemd unit files: unit ownership could not be checked")

        lookup = parse_dpkg_search(raw.get("owned_lookup", Output.missing()).stdout)
        facts.modprobe_files = [
            OwnedFile(path=p, package=_first(lookup.get(canonical_path(p))))
            for p in sorted(raw.get("modprobe", Output.missing()).lines())
        ]
        setid = _setid_rows(raw.get("setid", Output.missing()))
        facts.setid_files = len(setid)
        ignore = settings["ignore_setid_paths"]
        facts.unpackaged_setid_files = [
            SetIdFile(path=p, mode=m, owner=u, group=g)
            for p, m, u, g in setid
            if canonical_path(p) not in lookup and not _matches(p, ignore)
        ]

        facts.packages = parse_packages(raw.get("packages", Output.missing()).stdout)
        verify = raw.get("verify")
        if verify is not None:
            facts.verified_packages = [p for p in settings["verify_packages"] if p in facts.packages]
            facts.tampered_files = parse_dpkg_verify(verify.stdout)
        return facts


CHECK = SystemCheck


# ── shared with `persistence` (timers) ───────────────────────────────────────


async def collect_units(ctx: CheckContext) -> Output:
    """Every unit file and link in the system unit directories (memoized, so persistence reuses it)."""
    return await ctx.run(
        [
            "find",
            *UNIT_DIRS,
            "-maxdepth",
            "2",
            "(",
            "-type",
            "f",
            "-o",
            "-type",
            "l",
            ")",
            "-printf",
            r"%p\t%y\t%l\t%u\t%T@\n",
        ]
    )


class UnitAnalysis(BaseModel):
    unpackaged: list[UnitFile]
    packaged: int
    via_usr_merge: int
    dangling: list[UnitFile] = []


def _unit_rows(units: Output) -> dict[str, tuple[str, str, str, int | None]]:
    """canonical path → (kind, link target, owner, mtime). /lib and /usr/lib duplicates fold together."""
    rows: dict[str, tuple[str, str, str, int | None]] = {}
    for line in units.lines():
        fields = split_fields(line, 5)
        if not fields:
            continue
        path, kind, target, owner, mtime = fields
        rows.setdefault(canonical_path(path), (kind, target, owner, _int(mtime)))
    return rows


def unpackaged_unit_paths(units: Output, owned_out: Output, settings: dict[str, Any]) -> list[str]:
    """Regular unit files not owned by a package (the ones whose contents we read)."""
    owned = parse_dpkg_search(owned_out.stdout)
    return [
        path
        for path, (kind, _, _, _) in sorted(_unit_rows(units).items())
        if kind == "f" and path not in owned and not _ignored_unit(path, settings)
    ]


def analyze_units(
    units: Output, owned_out: Output, lines_out: Output, settings: dict[str, Any]
) -> UnitAnalysis:
    rows = _unit_rows(units)
    owned = parse_dpkg_search(owned_out.stdout)
    owned_names = {line.partition(": ")[2].strip() for line in owned_out.stdout.splitlines() if ": /" in line}
    found_names = {line.split("\t", 1)[0] for line in units.lines()}
    unit_lines = grep_h_lines(lines_out.stdout)

    unpackaged: dict[str, UnitFile] = {}
    dangling: list[UnitFile] = []
    links: list[tuple[str, str, str, int | None]] = []
    packaged = via_merge = 0
    for path, (kind, target, owner, mtime) in sorted(rows.items()):
        if path in owned:
            packaged += 1
            # Found under a name dpkg doesn't know (it recorded the other /usr-merge name): the quirk that
            # a naive `dpkg -S <found path>` reports as unpackaged.
            if any(name in found_names and name not in owned_names for name in path_aliases(path)):
                via_merge += 1
            continue
        if _ignored_unit(path, settings):
            continue
        if kind == "l":
            links.append((path, target, owner, mtime))
            continue
        lines = [
            ln.strip()
            for p in path_aliases(path)
            for ln in unit_lines.get(p, [])
            if ln.strip().split("=", 1)[0] in UNIT_KEYS
        ]
        unpackaged[path] = UnitFile(path=path, kind="file", owner=owner, mtime=mtime, lines=lines)

    for path, target, owner, mtime in links:
        resolved = canonical_path(posixpath.normpath(posixpath.join(posixpath.dirname(path), target)))
        if resolved == "/dev/null":
            continue  # a masked unit (an operator choice), not something that runs
        if resolved in owned or (resolved in rows and resolved not in unpackaged):
            continue  # enables (or aliases) a packaged unit
        if resolved in unpackaged:
            unpackaged[resolved].enabled_by.append(path)
            continue
        link = UnitFile(path=path, kind="link", target=target, owner=owner, mtime=mtime)
        if resolved.startswith(_UNIT_DIR_PREFIXES):
            # Points into a unit directory at a file that isn't there (e.g. php8.3-fpm.service still enabled
            # after php8.3 was removed): it can't start anything.
            dangling.append(link)
            continue
        unpackaged[path] = link

    return UnitAnalysis(
        unpackaged=list(unpackaged.values()), packaged=packaged, via_usr_merge=via_merge, dangling=dangling
    )


def _ignored_unit(path: str, settings: dict[str, Any]) -> bool:
    return _matches(posixpath.basename(path), settings["ignore_units"])


# ── pure parsers ─────────────────────────────────────────────────────────────


def uid0_accounts(passwd: str) -> list[str]:
    names = []
    for line in passwd.splitlines():
        parts = line.split(":")
        if len(parts) >= 7 and parts[2].strip() == "0":
            names.append(parts[0])
    return names


def parse_uptime(uptime_lines: list[str], now: str) -> tuple[int | None, int | None]:
    if not uptime_lines:
        return None, None
    try:
        uptime = int(float(uptime_lines[0].split()[0]))
    except (ValueError, IndexError):
        return None, None
    try:
        return uptime, int(now.strip()) - uptime
    except ValueError:
        return uptime, None


def parse_stat_line(stdout: str) -> BinaryMode | None:
    line = stdout.strip()
    fields = split_fields(line, 4) if line else None
    if not fields:
        return None
    path, mode, owner, group = fields
    return BinaryMode(path=path, mode=mode.zfill(4), owner=owner, group=group)


_UPDATES = re.compile(r"^(\d+) (?:packages?|updates?) can be (?:updated|applied)")
_SECURITY = re.compile(r"^(\d+) (?:of these )?updates? (?:are|is) (?:a )?(?:standard )?security updates?")


def parse_updates_available(lines: list[str]) -> Updates | None:
    """/var/lib/update-notifier/updates-available (the motd text): 16.04 and 24.04 wordings."""
    if not lines:
        return None
    updates = Updates()
    for line in lines:
        text = line.strip()
        if m := _UPDATES.match(text):
            updates.pending = int(m.group(1))
        elif m := _SECURITY.match(text):
            updates.security = int(m.group(1))
    if updates.pending is not None and updates.security is None:
        updates.security = 0
    return updates


def parse_packages(stdout: str) -> dict[str, str]:
    """`dpkg-query -W -f '${binary:Package}\\t${Version}\\t${Status}\\n'` → installed {name: version}."""
    packages: dict[str, str] = {}
    for line in stdout.splitlines():
        fields = split_fields(line, 3)
        if fields and fields[2].strip().endswith(" installed"):
            packages[fields[0]] = fields[1]
    return packages


_VERIFY = re.compile(r"^(?P<flags>\S{9}|missing)\s+(?P<conf>c\s+)?(?P<path>/.*)$")
_BIN_DIRS = ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/usr/local/sbin/")


def parse_dpkg_verify(stdout: str) -> list[VerifyIssue]:
    """md5 mismatches on non-conffiles, plus missing executables (minimal images drop docs, not binaries)."""
    issues = []
    for line in stdout.splitlines():
        m = _VERIFY.match(line.strip())
        if not m or m.group("conf"):
            continue
        flags, path = m.group("flags"), m.group("path")
        if flags == "missing":
            if path.startswith(_BIN_DIRS):
                issues.append(VerifyIssue(path=path, flags=flags))
        elif flags[2] == "5":
            issues.append(VerifyIssue(path=path, flags=flags))
    return issues


def _setid_rows(out: Output) -> list[tuple[str, str, str, str]]:
    rows = []
    for line in out.lines():
        fields = split_fields(line, 4)
        if fields:
            rows.append((fields[0], fields[1].zfill(4), fields[2], fields[3]))
    return rows


def _with_aliases(paths: list[str]) -> list[str]:
    """Each path plus its /usr-merge alias, so dpkg finds it under whichever name it recorded."""
    out: dict[str, None] = {}
    for path in paths:
        for candidate in path_aliases(path):
            out[candidate] = None
    return list(out)


def _matches(value: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(value, p) for p in patterns)


def _first(values: list[str] | None) -> str | None:
    return values[0] if values else None


def _int(value: str) -> int | None:
    try:
        return int(float(value))
    except ValueError:
        return None
