#!/bin/sh
# Replay the Oct 21 2026 login pattern on lab-wp2 with current timestamps, for an end-to-end run of the watch
# pass (M7) through the local control plane. Lab only.
#
#   sh lab/replay/oct21.sh          # plant: synchronized logins, forged sessions, login → plugin upload
#   sh lab/replay/oct21.sh clean    # remove the planted sessions (the access-log lines age out of the window)
#
# The lab test tests/lab/test_watch_lab.py plants the same burst through the fix user.
set -eu
ip=198.51.100.7
wpc() { path=$1; shift; docker compose exec -T lab-wp2 wp --allow-root --path="$path" --skip-plugins --skip-themes user meta "$@"; }

if [ "${1:-}" = clean ]; then
    for uid in 1 2 3 4; do wpc /var/www/gamma.lab.test delete "$uid" session_tokens >/dev/null || true; done
    wpc /var/www/delta.lab.test delete 1 session_tokens >/dev/null || true
    echo "replay: planted sessions removed"
    exit 0
fi

t=$(( $(date +%s) - 120 ))
session() { printf '{"%s":{"expiration":%s,"ip":"%s","ua":"Mozilla/5.0 (replay)","login":%s}}' \
    "$(printf 'replay %s %s' "$1" "$2" | sha256sum | cut -c1-64)" "$(( $1 + 172800 ))" "$ip" "$1"; }

# Forged sessions: every gamma user "logs in" the same second (the default threshold is 5 users; gamma has 4,
# so set the activity agent's forged_min_users to 4 to see it here, or rely on the other two findings).
for uid in 1 2 3 4; do wpc /var/www/gamma.lab.test update "$uid" session_tokens "$(session "$t" "$uid")" --format=json >/dev/null; done
# Synchronized logins: labadmin on delta 40 s later, from the same new IP.
wpc /var/www/delta.lab.test update 1 session_tokens "$(session $(( t + 40 )) d)" --format=json >/dev/null
# Login → plugin upload in gamma's access log.
stamp=$(date -u -d "@$t" '+%d/%b/%Y:%H:%M:%S +0000' 2>/dev/null || date -u -r "$t" '+%d/%b/%Y:%H:%M:%S +0000')
later=$(date -u -d "@$(( t + 90 ))" '+%d/%b/%Y:%H:%M:%S +0000' 2>/dev/null || date -u -r "$(( t + 90 ))" '+%d/%b/%Y:%H:%M:%S +0000')
printf '%s - - [%s] "POST /wp-login.php HTTP/1.1" 302 0 "-" "Mozilla/5.0 (replay)"\n%s - - [%s] "POST /wp-admin/update.php?action=upload-plugin HTTP/1.1" 200 812 "-" "Mozilla/5.0"\n' \
    "$ip" "$stamp" "$ip" "$later" | docker compose exec -T lab-wp2 tee -a /var/log/apache2/gamma.lab.test-access.log >/dev/null
echo "replay: Oct 21 burst planted on lab-wp2 from $ip at $(date -u -r "$t" 2>/dev/null || date -u -d "@$t")"
