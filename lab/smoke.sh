#!/bin/sh
# Smoke test: the WordPress lab hosts accept the local key over SSH, read-only sudo works, write sudo is
# refused, and every site serves WordPress; lab-locked is reachable with sudo locked out.
# Run from the repo root after `docker compose up -d`.
set -eu

KEY=.local/keys/id_ed25519_lab
if [ ! -f "$KEY" ]; then
    mkdir -p .local/keys
    ssh-keygen -q -t ed25519 -N '' -C handscheck-lab -f "$KEY"
    echo "generated $KEY; restart the lab hosts so they pick it up: docker compose restart lab-wp1 lab-wp2 lab-locked" >&2
    exit 1
fi

SSH="ssh -i $KEY -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
fail=0

check_host() {
    name=$1 ssh_port=$2 http_port=$3; shift 3
    i=0
    until $SSH -p "$ssh_port" handscheck@127.0.0.1 true 2>/dev/null; do
        i=$((i + 1)); [ "$i" -gt 60 ] && { echo "FAIL $name: ssh not reachable"; fail=1; return; }
        sleep 2
    done
    os=$($SSH -p "$ssh_port" handscheck@127.0.0.1 '. /etc/os-release && echo "$PRETTY_NAME"')
    echo "ok   $name: ssh as handscheck ($os)"

    if $SSH -p "$ssh_port" handscheck@127.0.0.1 'sudo -n stat -c %a /usr/bin/sudo' >/dev/null; then
        echo "ok   $name: read-only sudo (stat)"
    else
        echo "FAIL $name: read-only sudo"; fail=1
    fi
    if $SSH -p "$ssh_port" handscheck@127.0.0.1 'sudo -n touch /root/should-not-exist' 2>/dev/null; then
        echo "FAIL $name: sudo allowed a write"; fail=1
    else
        echo "ok   $name: write via sudo refused"
    fi
    for site in "$@"; do
        body=$(curl -fsS -H "Host: $site" "http://127.0.0.1:$http_port/" || true)
        if echo "$body" | grep -q "$site (lab)"; then
            echo "ok   $name: $site serves WordPress"
        else
            echo "FAIL $name: $site"; fail=1
        fi
    done
}

# lab-locked carries the sudo-lockout fixture: SSH works, /usr/bin/sudo is mode 000, so sudo must fail.
check_locked() {
    name=$1 ssh_port=$2
    i=0
    until $SSH -p "$ssh_port" handscheck@127.0.0.1 true 2>/dev/null; do
        i=$((i + 1)); [ "$i" -gt 60 ] && { echo "FAIL $name: ssh not reachable"; fail=1; return; }
        sleep 2
    done
    mode=$($SSH -p "$ssh_port" handscheck@127.0.0.1 'stat -c %a /usr/bin/sudo')
    if [ "$mode" = "0" ] && ! $SSH -p "$ssh_port" handscheck@127.0.0.1 'sudo -n ls /root' 2>/dev/null; then
        echo "ok   $name: ssh as handscheck; sudo locked out (mode $mode), as planted"
    else
        echo "FAIL $name: expected /usr/bin/sudo mode 0 and sudo refused (mode $mode)"; fail=1
    fi
}

check_host lab-wp1 2221 8081 alpha.lab.test beta.lab.test
check_host lab-wp2 2222 8082 gamma.lab.test delta.lab.test
check_locked lab-locked 2223
exit $fail
