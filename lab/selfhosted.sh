#!/bin/sh
# Self-hosted lab run (Track S1): build the bundle and install it with its own install.sh.
#
# 1. Fresh install, in throwaway containers from the 16.04 and 24.04 lab images with the `handscheck` user removed:
#    install.sh creates the user and installs the strict sudoers file (checked by visudo); `hc check --local`
#    refuses root and runs as handscheck through that sudoers file; `install.sh --uninstall --purge` removes it all.
# 2. On lab-wp1 (24.04, clean) and lab-wp2 (16.04, compromised), where `handscheck` already exists for SSH:
#    install.sh leaves the user alone and installs its sudoers file (the lab's own file is restored afterwards, so
#    the managed lab tests are unaffected), then `sudo -u handscheck hc check --local --json` is saved to
#    .local/selfhosted/<host>.json for `pytest -m lab tests/lab/test_selfhosted_lab.py`.
#
# Run from the repo root after `docker compose up -d` (and lab/smoke.sh). No Claude, nothing leaves the lab.
# SKIP_BUILD=1 reuses the newest bundle in worker/dist/.
set -eu

arch=${ARCH:-$(docker version -f '{{.Server.Arch}}')}
if [ -z "${SKIP_BUILD:-}" ]; then
    sh worker/packaging/selfhosted/build.sh "$arch" >/dev/null
fi
bundle=$(ls -1t worker/dist/handscheck-*-linux-"$arch".tar.gz | head -n 1)
echo "bundle: $bundle"
mkdir -p .local/selfhosted
fail=0

# ── 1. fresh install and uninstall ───────────────────────────────────────────
fresh() {
    image=$1
    if docker run --rm -i -v "$PWD/$bundle:/tmp/handscheck.tar.gz:ro" --entrypoint sh "$image" -s <<'EOF'
set -eu
userdel -r handscheck 2>/dev/null || true
rm -f /etc/sudoers.d/handscheck
cd /tmp && tar -xzf handscheck.tar.gz
sh handscheck/install.sh --print-sudoers | grep -q 'Cmnd_Alias HC_READ'
sh /tmp/handscheck/install.sh --yes
test "$(getent passwd handscheck | cut -d: -f6,7)" = "/var/lib/handscheck:/usr/sbin/nologin"
test "$(stat -c '%U %a' /etc/sudoers.d/handscheck)" = "root 440"
test "$(stat -c %U /opt/handscheck/bin/hc)" = root
! su -s /bin/sh handscheck -c 'test -w /opt/handscheck/bin/hc'
hc check --local system 2>&1 | grep -q 'refusing to run checks as root'
sudo -u handscheck hc check --local system users persistence --json > /tmp/run.json
grep -q '"sudo_ok": true' /tmp/run.json
test -f /var/lib/handscheck/.local/share/handscheck/handscheck.sqlite3
! sudo -u handscheck sudo -n dpkg -i /tmp/x.deb 2>/dev/null
! sudo -u handscheck sudo -n find /tmp -delete 2>/dev/null
sh /opt/handscheck/install.sh --yes    # upgrade in place: still works
sudo -u handscheck hc version >/dev/null
sh /opt/handscheck/install.sh --uninstall --purge --yes
test ! -e /opt/handscheck && test ! -e /usr/local/bin/hc && test ! -e /etc/sudoers.d/handscheck
! id handscheck 2>/dev/null && test ! -e /var/lib/handscheck
EOF
    then
        echo "ok   $image: fresh install, strict sudoers, check as handscheck, upgrade, uninstall --purge"
    else
        echo "FAIL $image: fresh install"; fail=1
    fi
}
fresh handscheck-lab-ubuntu-16.04
fresh handscheck-lab-ubuntu-24.04

# ── 2. the lab hosts, with their fixtures ────────────────────────────────────
for host in lab-wp1 lab-wp2; do
    docker compose cp "$bundle" "$host:/tmp/handscheck.tar.gz" >/dev/null 2>&1
    docker compose exec -T "$host" sh -c 'set -e; cp /etc/sudoers.d/handscheck /root/sudoers-handscheck.lab
        rm -rf /tmp/handscheck && cd /tmp && tar -xzf handscheck.tar.gz && rm handscheck.tar.gz
        sh /tmp/handscheck/install.sh --yes >/dev/null && rm -rf /tmp/handscheck'
    os=$(docker compose exec -T "$host" sh -c '. /etc/os-release && echo "$PRETTY_NAME"')
    echo "ok   $host: installed with install.sh ($os, $(docker compose exec -T "$host" hc version | head -n 1))"

    state=/home/handscheck/.local/share/handscheck
    docker compose exec -T "$host" rm -rf "$state"
    if docker compose exec -T "$host" sudo -u handscheck hc check --local --name "$host" --json \
        >".local/selfhosted/$host.json"; then
        echo "ok   $host: sudo -u handscheck hc check --local -> .local/selfhosted/$host.json"
    else
        echo "FAIL $host: hc check --local failed"; cat ".local/selfhosted/$host.json"; fail=1
    fi
    docker compose exec -T "$host" sh -c 'install -m 0440 /root/sudoers-handscheck.lab /etc/sudoers.d/handscheck \
        && rm /root/sudoers-handscheck.lab'
done
exit $fail
