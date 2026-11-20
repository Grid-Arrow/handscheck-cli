#!/bin/sh
# Planted host-level compromise (M2), modeled on what the Oct 2026 attacker left on aws24
# (docs/incidents/2026-10-wordpress-compromise.md). Synthetic and inert: nothing here runs or reaches the network.
# Applied by hosts/common/entrypoint.sh on every start when LAB_FIXTURES contains "host-compromise"; idempotent.
# What the system/users/persistence checks must report is listed in lab/fixtures/README.md.
set -eu

# 1. An extra uid-0 account (created after the kernel LPE in the incident).
grep -q '^sysbackup:' /etc/passwd || useradd -o -u 0 -g 0 -M -d /root -s /bin/bash -c 'system backup' sysbackup

# 2. A fake systemd service imitating a D-Bus helper, enabled in multi-user.target, pointing at an unpackaged
#    set-uid "binary". The binary is a do-nothing script (the kernel ignores the set-uid bit on scripts), and the
#    lab containers have no systemd, so nothing starts it.
printf '#!/bin/sh\nexit 0\n' > /usr/sbin/authd
chmod 4755 /usr/sbin/authd
cat > /etc/systemd/system/dbus-socket-helper.service <<'UNIT'
[Unit]
Description=D-Bus Socket Helper
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/authd
Restart=always

[Install]
WantedBy=multi-user.target
UNIT
mkdir -p /etc/systemd/system/multi-user.target.wants
ln -sfn /etc/systemd/system/dbus-socket-helper.service \
    /etc/systemd/system/multi-user.target.wants/dbus-socket-helper.service

# 3. A hidden directory in /dev/shm owned by www-data, holding a "checker" list like the ones the attackers left
#    in /tmp. /dev/shm is a fresh tmpfs on every container start, so this is re-created each time.
mkdir -p /dev/shm/.x
printf '# checker: planted backdoors (lab fixture)\n/var/www/example/wp-content/uploads/x.php\n' > /dev/shm/.x/checker
chown -R www-data:www-data /dev/shm/.x
chmod 700 /dev/shm/.x

# 4. A www-data crontab (a re-infector). Inert: it points at the non-executable checker file, so cron's attempt
#    fails with "permission denied" and nothing runs.
printf '*/30 * * * * /dev/shm/.x/checker >/dev/null 2>&1\n' > /var/spool/cron/crontabs/www-data
chown www-data:crontab /var/spool/cron/crontabs/www-data
chmod 600 /var/spool/cron/crontabs/www-data

echo "lab: fixture host-compromise applied"
