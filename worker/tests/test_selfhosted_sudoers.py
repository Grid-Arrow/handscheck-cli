"""The self-hosted sudoers file (Track S1) grants every command the checks run with sudo, nothing that writes.

`packaging/selfhosted/sudoers-handscheck` is what `install.sh` puts in /etc/sudoers.d/. The commands come from
the captured lab runs (`tests/agents/captured/`, which the replay tests prove are all a scan sends). A small
matcher applies the file the way sudo does for these simple rules: a command path, optionally an argument
pattern where `*` matches anything (spaces too), and negated aliases. lab/selfhosted.sh checks the real file
with visudo and runs the checks through it.
"""

import fnmatch
import gzip
import json
import posixpath
import re
import shlex
from dataclasses import dataclass
from pathlib import Path

import pytest

SUDOERS = Path(__file__).parents[1] / "packaging" / "selfhosted" / "sudoers-handscheck"
CAPTURED = Path(__file__).parent / "agents" / "captured"


@dataclass(frozen=True)
class Spec:
    path: str
    args: str | None  # None: any arguments

    def matches(self, argv: list[str]) -> bool:
        name, *rest = argv
        if posixpath.basename(self.path) != name and self.path != name:
            return False
        return self.args is None or fnmatch.fnmatchcase(" ".join(rest), self.args)


def _parse() -> tuple[dict[str, list[Spec]], list[tuple[str, list[str]]]]:
    text = re.sub(r"\\\n\s*", "", SUDOERS.read_text())
    aliases: dict[str, list[Spec]] = {}
    rules: list[tuple[str, list[str]]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if m := re.fullmatch(r"Cmnd_Alias (\w+) = (.+)", line):
            specs = []
            for item in m.group(2).split(","):
                path, _, args = item.strip().partition(" ")
                specs.append(Spec(path, args or None))
            aliases[m.group(1)] = specs
        elif m := re.fullmatch(r"handscheck ALL=\((\S+)\) NOPASSWD: (.+)", line):
            rules.append((m.group(1), [x.strip() for x in m.group(2).split(",")]))
        else:
            raise AssertionError(f"unexpected sudoers line: {line}")
    return aliases, rules


def allowed(runas: str, argv: list[str]) -> bool:
    aliases, rules = _parse()
    for user, items in rules:
        if user != runas:
            continue
        granted = any(s.matches(argv) for i in items if not i.startswith("!") for s in aliases[i])
        denied = any(s.matches(argv) for i in items if i.startswith("!") for s in aliases[i[1:]])
        if granted and not denied:
            return True
    return False


def _captured_sudo_commands() -> list[tuple[str, list[str]]]:
    out = []
    for path in sorted(CAPTURED.glob("*.json.gz")):
        for record in json.loads(gzip.decompress(path.read_bytes()))["commands"]:
            argv = shlex.split(record["command"])
            if argv[0] != "sudo":
                continue
            end = argv.index("--")
            runas = argv[argv.index("-u") + 1] if "-u" in argv[:end] else "root"
            out.append((runas, argv[end + 1 :]))
    return out


def test_every_captured_sudo_command_is_granted() -> None:
    commands = _captured_sudo_commands()
    assert len(commands) > 100
    refused = [(u, shlex.join(a)[:120]) for u, a in commands if not allowed(u, a)]
    assert refused == []


@pytest.mark.parametrize(
    ("runas", "command"),
    [
        ("root", "cat /etc/shadow"),
        ("root", "ls -d /root/."),
        ("root", "stat -c %U /var/www"),
        ("root", "find /var/www -type f -name '*.php' -printf %p"),
        ("root", "dpkg --verify coreutils"),
        ("root", "tail -c 4000000 /var/log/auth.log"),
        ("www-data", "wp db query 'SELECT 1' --path=/var/www/x"),
    ],
)
def test_reads_are_granted(runas: str, command: str) -> None:
    assert allowed(runas, shlex.split(command))


@pytest.mark.parametrize(
    ("runas", "command"),
    [
        ("root", "find /var/www -name x -delete"),
        ("root", "find /var/www -exec rm {} ;"),
        ("root", "find -exec sh ;"),
        ("root", "find /tmp -execdir sh ;"),
        ("root", "find / -ok sh ;"),
        ("root", "find / -fprintf /etc/cron.d/x %p"),
        ("root", "find / -fls /etc/passwd"),
        ("root", "dpkg -i /tmp/evil.deb"),
        ("root", "dpkg --purge openssh-server"),
        ("root", "tee /etc/passwd"),
        ("root", "sh -c id"),
        ("root", "journalctl"),
        ("root", "wp db query 'SELECT 1'"),
        ("www-data", "wp eval 'system(\"id\");'"),
        ("www-data", "cat /var/www/x/wp-config.php"),
        ("nobody", "cat /etc/shadow"),
    ],
)
def test_writes_and_other_commands_are_refused(runas: str, command: str) -> None:
    assert not allowed(runas, shlex.split(command))


def test_matcher_rejects_unknown_lines() -> None:
    aliases, rules = _parse()
    assert set(aliases) == {"HC_READ", "HC_FIND_WRITES", "HC_WP"}
    assert [u for u, _ in rules] == ["root", "www-data"]
