from typing import Any

from handscheck.agents._framework.check import canonical_path, parse_dpkg_search, path_aliases
from handscheck.agents.system.check import (
    SystemFacts,
    analyze_units,
    parse_dpkg_verify,
    parse_packages,
    parse_stat_line,
    parse_updates_available,
    uid0_accounts,
)
from tests.agents.conftest import collect_facts, out

WANTS = "/etc/systemd/system/multi-user.target.wants"


async def test_compromised_lab_host_facts() -> None:
    """lab-wp2 (16.04) carries lab/fixtures/host-compromise."""
    facts = await collect_facts("lab-wp2", "system")
    assert isinstance(facts, SystemFacts)
    assert facts.uid0_accounts == ["root", "sysbackup"]
    assert [u.path for u in facts.unpackaged_units] == ["/etc/systemd/system/dbus-socket-helper.service"]
    unit = facts.unpackaged_units[0]
    assert "ExecStart=/usr/sbin/authd" in unit.lines
    assert unit.enabled_by == ["/etc/systemd/system/multi-user.target.wants/dbus-socket-helper.service"]
    assert [(f.path, f.mode) for f in facts.unpackaged_setid_files] == [("/usr/sbin/authd", "4755")]
    assert facts.sudo_binary_ok is True
    assert facts.os_version_id == "16.04" and facts.units_matched_via_usr_merge == 0
    assert facts.packages and facts.warnings == []


async def test_clean_lab_host_has_no_false_positives() -> None:
    """lab-wp1 (24.04, usr-merged): nothing unpackaged, though dpkg knows units under the other /usr name."""
    facts = await collect_facts("lab-wp1", "system")
    assert isinstance(facts, SystemFacts)
    assert facts.uid0_accounts == ["root"]
    assert facts.unpackaged_units == []
    assert facts.packaged_units > 100 and facts.units_matched_via_usr_merge > 0
    assert facts.unpackaged_setid_files == [] and facts.setid_files > 0
    assert facts.tampered_files == [] and len(facts.verified_packages) >= 10
    assert facts.sudo_binary_ok is True and facts.ld_so_preload == []


async def test_sudo_lockout_lab_host() -> None:
    facts = await collect_facts("lab-locked", "system", sudo_ok=False)
    assert isinstance(facts, SystemFacts)
    assert facts.sudo_binary is not None and facts.sudo_binary.mode == "0000"
    assert facts.sudo_binary_ok is False
    assert any("without sudo" in w for w in facts.warnings)


def _units(*rows: str) -> Any:
    return out("\n".join(rows) + "\n")


def test_usr_merge_quirk_is_not_unpackaged(system_settings: dict[str, Any]) -> None:
    # Found only under /usr/lib, dpkg recorded /lib (and the reverse): both packaged.
    found = _units(
        "/usr/lib/systemd/system/phpsessionclean.service\tf\t\troot\t1700000000.0",
        "/lib/systemd/system/getty@.service\tf\t\troot\t1700000000.0",
    )
    owned = out(
        "php-common: /lib/systemd/system/phpsessionclean.service\n"
        "systemd: /usr/lib/systemd/system/getty@.service\n"
    )
    result = analyze_units(found, owned, out(), system_settings)
    assert result.unpackaged == [] and result.packaged == 2 and result.via_usr_merge == 2


def test_unit_links(system_settings: dict[str, Any]) -> None:
    found = _units(
        "/etc/systemd/system/evil.service\tf\t\troot\t1700000000.0",
        f"{WANTS}/evil.service\tl\t/etc/systemd/system/evil.service\troot\t1",
        f"{WANTS}/cron.service\tl\t/lib/systemd/system/cron.service\troot\t1",
        "/etc/systemd/system/sshd.service\tl\t/lib/systemd/system/ssh.service\troot\t1",
        "/etc/systemd/system/masked.service\tl\t/dev/null\troot\t1",
        "/etc/systemd/system/other.service\tl\t/opt/x/other.service\troot\t1",
        "/etc/systemd/system/snap-core-1.mount\tf\t\troot\t1",
        "/lib/systemd/system/cron.service\tf\t\troot\t1",
        "/lib/systemd/system/ssh.service\tf\t\troot\t1",
    )
    owned = out("cron: /lib/systemd/system/cron.service\nopenssh-server: /lib/systemd/system/ssh.service\n")
    lines = out("/etc/systemd/system/evil.service:ExecStart=/tmp/x\n/etc/systemd/system/evil.service:Foo=1\n")
    result = analyze_units(found, owned, lines, system_settings)
    by_path = {u.path: u for u in result.unpackaged}
    assert set(by_path) == {"/etc/systemd/system/evil.service", "/etc/systemd/system/other.service"}
    evil = by_path["/etc/systemd/system/evil.service"]
    assert evil.lines == ["ExecStart=/tmp/x"]
    assert evil.enabled_by == [f"{WANTS}/evil.service"]
    assert by_path["/etc/systemd/system/other.service"].kind == "link"


def test_canonical_paths_and_dpkg_search() -> None:
    assert canonical_path("/usr/lib/systemd/system/x") == "/lib/systemd/system/x"
    assert canonical_path("/usr/bin/sudo") == "/bin/sudo"
    assert canonical_path("/usr/local/bin/wp") == "/usr/local/bin/wp"
    assert canonical_path("/usr/libexec/x") == "/usr/libexec/x"
    assert path_aliases("/usr/sbin/authd") == ["/sbin/authd", "/usr/sbin/authd"]
    assert path_aliases("/etc/modprobe.d/x.conf") == ["/etc/modprobe.d/x.conf"]
    owned = parse_dpkg_search(
        "diversion by dash from: /bin/sh\n"
        "libc-bin, libc6:amd64: /usr/lib/x\n"
        "dpkg-query: no path found matching pattern /usr/sbin/authd\n"
    )
    assert owned == {"/lib/x": ["libc-bin", "libc6"]}


def test_uid0_and_stat() -> None:
    lines = [
        "root:x:0:0:root:/root:/bin/bash",
        "bad",
        "toor:x:0:0::/root:/bin/sh",
        "bob:x:1000:1000::/h:/bin/sh",
    ]
    assert uid0_accounts("\n".join(lines)) == ["root", "toor"]
    stat = parse_stat_line("/usr/bin/sudo\t0\troot\troot\n")
    assert stat is not None and stat.mode == "0000"
    assert parse_stat_line("") is None


def test_dpkg_verify() -> None:
    text = (
        "??5??????   /usr/bin/ps\n"
        "??5?????? c /etc/sudoers\n"
        "missing     /usr/share/doc/bash/README\n"
        "missing     /usr/sbin/sshd\n"
        "?????????   /usr/bin/unreadable\n"
    )
    assert [(i.path, i.flags) for i in parse_dpkg_verify(text)] == [
        ("/usr/bin/ps", "??5??????"),
        ("/usr/sbin/sshd", "missing"),
    ]


def test_updates_available_wordings() -> None:
    noble = parse_updates_available(
        ["", "5 updates can be applied immediately.", "2 of these updates are standard security updates."]
    )
    assert noble is not None and (noble.pending, noble.security) == (5, 2)
    xenial = parse_updates_available(["12 packages can be updated.", "7 updates are security updates."])
    assert xenial is not None and (xenial.pending, xenial.security) == (12, 7)
    none = parse_updates_available(["0 updates can be applied immediately."])
    assert none is not None and (none.pending, none.security) == (0, 0)
    assert parse_updates_available([]) is None


def test_packages_only_installed() -> None:
    text = "bash\t5.2\tinstall ok installed\nold\t1.0\tdeinstall ok config-files\nbroken line\n"
    assert parse_packages(text) == {"bash": "5.2"}


def test_diff_view_leaves_out_volatile_values() -> None:
    a = SystemFacts(uptime_s=10, boot_time=100, kernel="6.8", boot_id="b1", packages={"bash": "5.2"})
    b = a.model_copy(update={"uptime_s": 99999, "boot_time": 101})
    assert a.diff_view() == b.diff_view()


def test_dangling_unit_links_are_not_unpackaged(system_settings: dict[str, Any]) -> None:
    """Seen on a real host: php8.3-fpm.service still enabled after php8.3 was removed."""
    found = _units(f"{WANTS}/php8.3-fpm.service\tl\t/lib/systemd/system/php8.3-fpm.service\troot\t1")
    result = analyze_units(found, out(""), out(), system_settings)
    assert result.unpackaged == [] and [u.path for u in result.dangling] == [f"{WANTS}/php8.3-fpm.service"]


def test_setid_scan_skips_container_layers(system_settings: dict[str, Any]) -> None:
    assert "/var/lib/containerd" in system_settings["setid_skip_dirs"]


def test_guaranteed_root_backdoors() -> None:
    from handscheck.agents.system.check import CHECK

    facts: dict[str, Any] = {
        "uid0_accounts": ["root", "sysbackup"],
        "sudo_binary": {"path": "/usr/bin/sudo", "mode": "0000", "owner": "root", "group": "root"},
        "sudo_binary_ok": False,
        "unpackaged_setid_files": [
            {"path": "/usr/sbin/authd", "mode": "4755", "owner": "root", "group": "root"},
            {"path": "/bin/helper", "mode": "4755", "owner": "root", "group": "root"},  # usr-merged name
            {"path": "/usr/local/bin/vendor-tool", "mode": "4755", "owner": "root", "group": "root"},
            {"path": "/opt/app/bin/ping", "mode": "4755", "owner": "root", "group": "root"},
        ],
        "unpackaged_units": [
            {
                "path": "/etc/systemd/system/dbus-socket-helper.service",
                "lines": ["ExecStart=-/usr/sbin/authd -d"],
            },
            {"path": "/etc/systemd/system/app.service", "lines": ["ExecStart=/opt/app/bin/app"]},
        ],
    }
    found = CHECK().guaranteed_findings(facts)
    assert [(f.kind, f.subject, f.severity) for f in found] == [
        ("extra_uid0", "sysbackup", "critical"),
        ("sudo_binary_tampered", "/usr/bin/sudo", "high"),
        ("unpackaged_setid", "/usr/sbin/authd", "critical"),
        ("unpackaged_setid", "/bin/helper", "critical"),
    ]
    assert "dbus-socket-helper.service" in found[2].title and "started by" not in found[3].title


def test_nothing_guaranteed_on_a_healthy_system() -> None:
    from handscheck.agents.system.check import CHECK

    facts: dict[str, Any] = {
        "uid0_accounts": ["root"],
        "sudo_binary": {"path": "/usr/bin/sudo", "mode": "4755", "owner": "root", "group": "root"},
        "sudo_binary_ok": True,
        "unpackaged_setid_files": [
            {"path": "/usr/local/bin/vendor-tool", "mode": "4755", "owner": "root", "group": "root"}
        ],
    }
    assert CHECK().guaranteed_findings(facts) == []
    assert CHECK().guaranteed_findings({"sudo_binary_ok": None}) == []  # not checked (no read access)
