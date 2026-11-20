"""The SSH command policy: the only gate between a check or agent and a target host's shell.

CLAUDE.md safety rule 1: scans are read-only. Every command the runner sends goes through
`CommandPolicy.check`, which splits the command into words (POSIX quoting; never a regex over the string),
refuses anything that is not on the read-only allowlist or that uses a writing/executing option, and returns a
*normalized* command string.

The runner sends only that normalized string: each word re-quoted with `shlex.join`, so the remote shell sees
literal words. There is no pipe, redirection, chaining, substitution, globbing, tilde or variable expansion on
the remote side, even if a check of the parser here were wrong. Commands that need a glob should use `find`.

Extending the allowlist: add a rule to `_RULES` with a test for both an allowed and a refused form
(`worker/tests/ssh/test_policy.py`). Don't add anything that can write, delete, install, restart, execute
another program or script, or reach the network.
"""

from __future__ import annotations

import posixpath
import re
import shlex
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

MAX_COMMAND_LENGTH = 8192

# Directories an absolute command path may live in (anything else, e.g. /tmp/cat, is refused).
_SAFE_BIN_DIRS = ("/bin/", "/usr/bin/", "/sbin/", "/usr/sbin/", "/usr/local/bin/")

# Unquoted shell operators (see split_words).
_OPERATOR_REASONS = {
    ";": "command chaining (;) is not allowed",
    "&": "background/chaining (&) is not allowed",
    "&&": "command chaining (&&) is not allowed",
    "|": "pipes (|) are not allowed",
    "||": "command chaining (||) is not allowed",
    ">": "output redirection (>) is not allowed",
    ">>": "output redirection (>>) is not allowed",
    "<": "input redirection (<) is not allowed",
    "(": "subshells are not allowed",
    ")": "subshells are not allowed",
}

# Commands refused with a specific reason (anything off the allowlist is refused anyway; these just explain).
_DENY_REASONS: dict[str, str] = {
    **dict.fromkeys(
        (
            "rm rmdir unlink shred truncate mv cp dd install ln mkdir touch tee chmod chown chgrp chattr "
            "setfacl mkfs mknod patch vi vim nano ed sed awk gawk mawk perl split rsync tar unzip gzip "
            "gunzip zip"
        ).split(),
        "can write or delete files",
    ),
    **dict.fromkeys(
        (
            "curl wget nc ncat netcat socat ssh scp sftp ftp telnet git openssl dig nslookup host ping "
            "traceroute"
        ).split(),
        "network access from the target host is not allowed",
    ),
    **dict.fromkeys(
        (
            "apt apt-get aptitude snap pip pip3 npm gem composer yum dnf update-alternatives a2enmod "
            "a2dismod a2ensite a2dissite"
        ).split(),
        "package or configuration changes are not allowed",
    ),
    **dict.fromkeys(
        (
            "service reboot shutdown halt poweroff init telinit kill pkill killall apachectl apache2ctl "
            "nginx php-fpm mount umount swapoff sysctl iptables ufw useradd userdel usermod groupadd passwd "
            "chpasswd visudo at batch"
        ).split(),
        "changing services, processes, users or system state is not allowed",
    ),
    **dict.fromkeys(
        (
            "sh bash dash zsh ksh csh fish python python3 ruby node lua eval exec source . env xargs nohup "
            "setsid timeout nice ionice chroot su doas runuser script watch busybox"
        ).split(),
        "running a shell, interpreter or another program is not allowed",
    ),
}

# sudo: who we may run as. www-data is for wp-cli (site code is owned by www-data).
DEFAULT_SUDO_USERS = frozenset({"root", "www-data"})


class PolicyViolation(Exception):
    """A command was refused by the policy. Never sent to the host."""

    def __init__(self, command: str, reason: str) -> None:
        super().__init__(f"refused by SSH command policy: {reason}: {command!r}")
        self.command = command
        self.reason = reason


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    argv: tuple[str, ...] = ()
    """The parsed words (with sudo normalized to `sudo -n [-u USER] -- ...`)."""
    sudo_user: str | None = None

    @property
    def command(self) -> str:
        """The normalized command line the runner sends: every word quoted, nothing for a shell to expand."""
        return shlex.join(self.argv)


class _Refuse(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# ── Argument helpers ─────────────────────────────────────────────────────────


def _split_options(args: Sequence[str]) -> tuple[list[str], list[str]]:
    """(options, positionals). Everything after `--` is positional. `-` alone is positional (stdin)."""
    options: list[str] = []
    positionals: list[str] = []
    end = False
    for arg in args:
        if end:
            positionals.append(arg)
        elif arg == "--":
            end = True
        elif arg.startswith("-") and arg != "-":
            options.append(arg)
        else:
            positionals.append(arg)
    return options, positionals


def _long_matches(option: str, denied: Sequence[str]) -> str | None:
    """GNU getopt accepts unambiguous prefixes (--foll = --follow): a prefix of a denied option is denied."""
    name = option.split("=", 1)[0]
    if not name.startswith("--") or len(name) < 3:
        return None
    for d in denied:
        if d.startswith(name):
            return d
    return None


def _deny_options(args: Sequence[str], *, short: str = "", long: Sequence[str] = ()) -> None:
    """Refuse short option letters (also inside clusters like -fn) and long options (and their prefixes).

    Deliberately over-strict: a clustered option's value is scanned too (e.g. `-n5f` is refused for tail).
    """
    options, _ = _split_options(args)
    for opt in options:
        if opt.startswith("--"):
            hit = _long_matches(opt, long)
            if hit:
                raise _Refuse(f"option {hit} is not allowed")
        else:
            for ch in opt[1:]:
                if ch in short:
                    raise _Refuse(f"option -{ch} is not allowed")


def _only_options(args: Sequence[str], allowed: set[str], *, positionals: bool = True) -> None:
    options, pos = _split_options(args)
    for opt in options:
        if opt.split("=", 1)[0] not in allowed:
            raise _Refuse(f"option {opt} is not allowed")
    if pos and not positionals:
        raise _Refuse("arguments are not allowed")


# ── Per-command rules ────────────────────────────────────────────────────────

Rule = Callable[[list[str]], None]


def _any(args: list[str]) -> None:
    """Read-only command with no writing or executing options."""


def _tail(args: list[str]) -> None:
    _deny_options(args, short="fF", long=("--follow", "--retry", "--pid"))


def _find(args: list[str]) -> None:
    denied = {"-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls"}
    for arg in args:
        if arg in denied:
            raise _Refuse(f"find {arg} is not allowed (it writes, deletes or runs commands)")


def _sort(args: list[str]) -> None:
    _deny_options(args, short="oT", long=("--output", "--temporary-directory", "--compress-program"))


def _uniq(args: list[str]) -> None:
    _, pos = _split_options(args)
    if len(pos) > 1:
        raise _Refuse("uniq with an OUTPUT file argument writes a file")


def _date(args: list[str]) -> None:
    _deny_options(args, short="s", long=("--set",))
    _, pos = _split_options(args)
    if any(not p.startswith("+") for p in pos):
        raise _Refuse("date with a non-format argument sets the clock")


def _hostname(args: list[str]) -> None:
    _only_options(
        args,
        {
            "-f",
            "--fqdn",
            "--long",
            "-s",
            "--short",
            "-d",
            "--domain",
            "-i",
            "-I",
            "--ip-address",
            "--all-ip-addresses",
            "-A",
            "--all-fqdns",
        },
        positionals=False,
    )


def _lastlog(args: list[str]) -> None:
    _deny_options(args, short="CS", long=("--clear", "--set"))


def _ss(args: list[str]) -> None:
    _deny_options(args, short="KD", long=("--kill", "--diag"))


def _file(args: list[str]) -> None:
    _deny_options(args, short="C", long=("--compile",))


def _dpkg(args: list[str]) -> None:
    allowed = {
        "-l",
        "--list",
        "-L",
        "--listfiles",
        "-s",
        "--status",
        "-S",
        "--search",
        "-p",
        "--print-avail",
        "--get-selections",
        "--print-architecture",
        "--print-foreign-architectures",
        "-V",
        "--verify",
        "-C",
        "--audit",
        "--compare-versions",
        "--version",
    }
    options, _ = _split_options(args)
    if not options:
        raise _Refuse("dpkg needs a query option (e.g. -l, -L, -S, -s, -V)")
    _only_options(args, allowed)


def _dpkg_query(args: list[str]) -> None:
    _deny_options(args, long=("--admindir", "--root", "--instdir"))


def _apt_cache(args: list[str]) -> None:
    _deny_options(args, short="oc", long=("--option", "--config-file"))
    _, pos = _split_options(args)
    read = {
        "policy",
        "show",
        "showpkg",
        "showsrc",
        "madison",
        "depends",
        "rdepends",
        "search",
        "pkgnames",
        "stats",
        "dump",
    }
    if not pos or pos[0] not in read:
        raise _Refuse(f"apt-cache subcommand must be one of {sorted(read)}")


def _systemctl(args: list[str]) -> None:
    _deny_options(
        args,
        short="HM",
        long=(
            "--host",
            "--machine",
            "--force",
            "--root",
            "--runtime",
            "--global",
            "--now",
            "--kill-who",
            "--signal",
        ),
    )
    _, pos = _split_options(args)
    read = {
        "list-units",
        "list-unit-files",
        "list-timers",
        "list-sockets",
        "list-dependencies",
        "status",
        "show",
        "cat",
        "is-active",
        "is-enabled",
        "is-failed",
        "is-system-running",
        "get-default",
    }
    if pos and pos[0] not in read:
        raise _Refuse(f"systemctl {pos[0]} is not allowed (read-only subcommands: {sorted(read)})")


def _journalctl(args: list[str]) -> None:
    _deny_options(
        args,
        short="f",
        long=(
            "--follow",
            "--vacuum-size",
            "--vacuum-time",
            "--vacuum-files",
            "--rotate",
            "--flush",
            "--sync",
            "--relinquish-var",
            "--smart-relinquish-var",
            "--setup-keys",
            "--update-catalog",
            "--force",
            "--interval",
        ),
    )


def _crontab(args: list[str]) -> None:
    rest = list(args)
    if "-u" in rest:
        i = rest.index("-u")
        if i + 1 >= len(rest):
            raise _Refuse("crontab -u needs a user")
        del rest[i : i + 2]
    if rest != ["-l"]:
        raise _Refuse("only `crontab -l [-u USER]` is allowed")


def _php(args: list[str]) -> None:
    if not args:
        raise _Refuse("php needs one of -v, -m, -i, --ini")
    _only_options(args, {"-v", "--version", "-m", "-i", "--ini"}, positionals=False)


def _ip(args: list[str]) -> None:
    allowed_opts = {
        "-4",
        "-6",
        "-br",
        "-brief",
        "-o",
        "-oneline",
        "-j",
        "-json",
        "-d",
        "-details",
        "-s",
        "-stats",
        "-c",
        "-color",
        "-p",
        "-pretty",
    }
    rest = list(args)
    while rest and rest[0].startswith("-"):
        opt = rest.pop(0).split("=", 1)[0]
        if opt not in allowed_opts:
            raise _Refuse(f"ip option {opt} is not allowed")
    objects = {"addr", "address", "a", "route", "r", "link", "l", "neigh", "n", "rule", "maddr", "netconf"}
    if not rest or rest[0] not in objects:
        raise _Refuse(f"ip object must be one of {sorted(objects)}")
    if len(rest) > 1 and rest[1] not in {"show", "list", "ls", "get"}:
        raise _Refuse(f"ip {rest[0]} {rest[1]} is not allowed (only show/list/get)")


# wp-cli. Commands that *load WordPress* are refused: loading it (even `wp user list --skip-plugins
# --skip-themes`) makes WordPress spawn wp-cron with a loopback HTTP request from the host, which runs overdue
# scheduled events with every plugin loaded (seen in the lab, M3). Allowed: commands that never load WordPress
# (`wp --version`, `wp cli …`, `wp core version`) and `wp db query` with one of the fixed SELECT templates
# below, which only reads wp-config.php for the database credentials.
WP_DB_QUERIES: dict[str, str] = {
    "admins": (
        "SELECT u.ID, u.user_login, u.user_email, u.user_registered FROM {p}users u "
        "JOIN {p}usermeta m ON m.user_id = u.ID AND m.meta_key = '{p}capabilities' "
        "WHERE m.meta_value LIKE '%\"administrator\"%' ORDER BY u.ID"
    ),
    "first_user": "SELECT ID, user_login, user_registered FROM {p}users ORDER BY ID LIMIT 1",
    # WordPress login sessions (IP, login time, user agent per session) for the watch pass (M7).
    "sessions": (
        "SELECT u.ID, u.user_login, u.user_email, IF(c.meta_value LIKE '%\"administrator\"%', 1, 0), "
        "m.meta_value FROM {p}users u "
        "JOIN {p}usermeta m ON m.user_id = u.ID AND m.meta_key = 'session_tokens' "
        "LEFT JOIN {p}usermeta c ON c.user_id = u.ID AND c.meta_key = '{p}capabilities' ORDER BY u.ID"
    ),
}
"""Read-only queries the policy lets `wp db query` run; `{p}` is the table prefix ([A-Za-z0-9_], ≤ 32)."""

_WP_NO_LOAD = {("cli", "version"), ("cli", "info"), ("core", "version")}
_WP_PREFIX = r"[A-Za-z0-9_]{1,32}"


def _wp_query_allowed(sql: str) -> bool:
    for template in WP_DB_QUERIES.values():
        parts = [re.escape(piece) for piece in template.split("{p}")]
        pattern = parts[0] + "".join(f"(?P<p{i}>{_WP_PREFIX})" + rest for i, rest in enumerate(parts[1:]))
        m = re.fullmatch(pattern, sql)
        if m and len(set(m.groupdict().values())) == 1:
            return True
    return False


def _wp(args: list[str]) -> None:
    options, pos = _split_options(args)
    names = {opt.split("=", 1)[0] for opt in options}
    if not pos:
        if names and names <= {"--version", "--info"}:
            return
        raise _Refuse("wp needs a subcommand")
    sub = tuple(pos[:2])
    if sub == ("db", "query"):
        if len(pos) != 3 or not _wp_query_allowed(pos[2]):
            raise _Refuse("wp db query only runs handscheck's fixed read-only SELECT templates")
        for name in sorted(names - {"--path"}):
            raise _Refuse(f"wp db query option {name} is not allowed (it would reach the mysql client)")
        return
    if sub not in _WP_NO_LOAD:
        raise _Refuse(
            f"wp {' '.join(sub)} is not allowed: it loads WordPress, which can spawn wp-cron (only "
            "`wp core version`, `wp cli version|info` and the fixed `wp db query` templates are allowed)"
        )
    allowed_opts = {"--path", "--skip-plugins", "--skip-themes", "--skip-packages", "--quiet", "--no-color"}
    for name in sorted(names - allowed_opts):
        raise _Refuse(f"wp option {name} is not allowed")


_RULES: dict[str, Rule] = {
    # files and text
    **dict.fromkeys(
        (
            "cat zcat head ls stat wc md5sum sha1sum sha256sum sha512sum readlink realpath basename dirname "
            "strings cmp diff test grep egrep fgrep zgrep cut which true"
        ).split(),
        _any,
    ),
    "tail": _tail,
    "find": _find,
    "sort": _sort,
    "uniq": _uniq,
    "file": _file,
    # system and users
    **dict.fromkeys(
        (
            "uname id whoami groups uptime nproc lsb_release getconf w who last ps df du free getent lsblk "
            "findmnt lsof arch"
        ).split(),
        _any,
    ),
    "date": _date,
    "hostname": _hostname,
    "lastlog": _lastlog,
    "ss": _ss,
    "ip": _ip,
    # packages and services
    "dpkg": _dpkg,
    "dpkg-query": _dpkg_query,
    "apt-cache": _apt_cache,
    "systemctl": _systemctl,
    "journalctl": _journalctl,
    "crontab": _crontab,
    # web stack
    "php": _php,
    "wp": _wp,
}


@dataclass(frozen=True)
class CommandPolicy:
    sudo_users: frozenset[str] = field(default=DEFAULT_SUDO_USERS)

    def check(self, command: str | Sequence[str]) -> Decision:
        """Parse and judge a command. Never raises for a bad command; returns allowed=False with a reason."""
        try:
            argv = self._tokenize(command)
            argv, sudo_user = self._judge(argv)
        except _Refuse as refusal:
            return Decision(allowed=False, reason=refusal.reason)
        return Decision(allowed=True, reason="allowed", argv=tuple(argv), sudo_user=sudo_user)

    def enforce(self, command: str | Sequence[str]) -> Decision:
        """Like check(), but raises PolicyViolation when refused."""
        decision = self.check(command)
        if not decision.allowed:
            shown = command if isinstance(command, str) else shlex.join(command)
            raise PolicyViolation(shown, decision.reason)
        return decision

    # ── internals ──

    @staticmethod
    def _tokenize(command: str | Sequence[str]) -> list[str]:
        if isinstance(command, str):
            raw = command
            _check_raw(raw)
            argv = []
            for word, is_operator in split_words(raw):
                if is_operator:
                    raise _Refuse(_OPERATOR_REASONS.get(word, f"shell operator {word!r} is not allowed"))
                argv.append(word)
        else:
            argv = list(command)
            _check_raw(" ".join(argv))
        if not argv:
            raise _Refuse("empty command")
        for tok in argv:
            # Sent quoted, these would be literal anyway; refusing them makes the intent error obvious.
            # (${...} stays allowed: dpkg-query -f '${Package}' needs it, and it is never expanded.)
            if "`" in tok or "$(" in tok:
                raise _Refuse("command substitution is not allowed")
        return argv

    def _judge(self, argv: list[str]) -> tuple[list[str], str | None]:
        if _command_name(argv[0]) == "sudo":
            sudo_user, inner = self._parse_sudo(argv[1:])
            if not inner:
                raise _Refuse("sudo needs a command")
            if _command_name(inner[0]) == "sudo":
                raise _Refuse("nested sudo is not allowed")
            self._judge_plain(inner)
            prefix = ["sudo", "-n"] + (["-u", sudo_user] if sudo_user != "root" else []) + ["--"]
            return prefix + inner, sudo_user
        self._judge_plain(argv)
        return argv, None

    def _parse_sudo(self, args: list[str]) -> tuple[str, list[str]]:
        user = "root"
        i = 0
        while i < len(args):
            arg = args[i]
            if arg == "--":
                i += 1
                break
            if not arg.startswith("-"):
                break
            if arg in ("-n", "--non-interactive"):
                i += 1
            elif arg in ("-u", "--user"):
                if i + 1 >= len(args):
                    raise _Refuse("sudo -u needs a user")
                user = args[i + 1]
                i += 2
            elif arg.startswith("--user="):
                user = arg.split("=", 1)[1]
                i += 1
            elif arg.startswith("-u") and len(arg) > 2:
                user = arg[2:]
                i += 1
            else:
                raise _Refuse(f"sudo option {arg} is not allowed (only -n and -u USER)")
        if user not in self.sudo_users:
            raise _Refuse(f"sudo as {user!r} is not allowed")
        return user, args[i:]

    @staticmethod
    def _judge_plain(argv: list[str]) -> None:
        first = argv[0]
        if "=" in first and not first.startswith("/"):
            raise _Refuse("environment assignments are not allowed")
        if "/" in first and (not first.startswith(_SAFE_BIN_DIRS) or posixpath.normpath(first) != first):
            raise _Refuse(f"command path {first!r} is not in a system bin directory")
        name = _command_name(first)
        rule = _RULES.get(name)
        if rule is None:
            reason = _DENY_REASONS.get(name, "not on the read-only allowlist")
            raise _Refuse(f"{name}: {reason}")
        rule(argv[1:])


_OPERATOR_CHARS = frozenset("();<>|&")
_DQUOTE_ESCAPES = frozenset('"\\$`')


def split_words(raw: str) -> list[tuple[str, bool]]:
    """Split a command line like a POSIX shell does, without expanding anything.

    Returns (word, is_operator) pairs. Unquoted runs of ;&|<>() are operators; quoted or backslash-escaped
    ones are ordinary characters inside a word (`grep ';' f` is fine, `cat f; id` is not). Unlike shlex with
    punctuation_chars, this keeps track of quoting, so a quoted ';' is not mistaken for an operator.
    """
    words: list[tuple[str, bool]] = []
    buf: list[str] = []
    in_word = False
    i, n = 0, len(raw)

    def flush() -> None:
        nonlocal buf, in_word
        if in_word:
            words.append(("".join(buf), False))
        buf, in_word = [], False

    while i < n:
        c = raw[i]
        if c in " \t":
            flush()
            i += 1
        elif c == "'":
            end = raw.find("'", i + 1)
            if end < 0:
                raise _Refuse("could not parse command: no closing quotation")
            buf.append(raw[i + 1 : end])
            in_word = True
            i = end + 1
        elif c == '"':
            in_word = True
            i += 1
            while True:
                if i >= n:
                    raise _Refuse("could not parse command: no closing quotation")
                c = raw[i]
                if c == '"':
                    i += 1
                    break
                if c == "\\" and i + 1 < n and raw[i + 1] in _DQUOTE_ESCAPES:
                    buf.append(raw[i + 1])
                    i += 2
                    continue
                buf.append(c)
                i += 1
        elif c == "\\":
            if i + 1 >= n:
                raise _Refuse("could not parse command: trailing backslash")
            buf.append(raw[i + 1])
            in_word = True
            i += 2
        elif c in _OPERATOR_CHARS:
            flush()
            end = i
            while end < n and raw[end] in _OPERATOR_CHARS:
                end += 1
            words.append((raw[i:end], True))
            i = end
        else:
            buf.append(c)
            in_word = True
            i += 1
    flush()
    return words


def _command_name(word: str) -> str:
    return word.rsplit("/", 1)[-1]


def _check_raw(raw: str) -> None:
    if len(raw) > MAX_COMMAND_LENGTH:
        raise _Refuse(f"command longer than {MAX_COMMAND_LENGTH} characters")
    for ch, what in (("\n", "newline"), ("\r", "carriage return"), ("\x00", "NUL byte")):
        if ch in raw:
            raise _Refuse(f"{what} in command is not allowed")


DEFAULT_POLICY = CommandPolicy()
