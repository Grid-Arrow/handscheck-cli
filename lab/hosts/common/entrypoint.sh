#!/bin/sh
# Lab host startup: install scan keys, install the WordPress sites on first boot, start services.
# Env: LAB_HOST (e.g. lab-wp1), LAB_SITES (space-separated site names; empty = no sites, no database),
# LAB_DB_HOST, LAB_DB_USER, LAB_DB_PASSWORD, LAB_FIXTURES (space-separated folders in lab/fixtures/, mounted at
# /lab-fixtures, applied on every start).
set -eu

: "${LAB_HOST:?}" "${LAB_SITES=}" "${LAB_DB_HOST:=lab-db}" "${LAB_DB_USER:=wp}" "${LAB_FIXTURES=}"
[ -z "$LAB_SITES" ] || : "${LAB_DB_PASSWORD:?}"

# 1. Public keys from the repo's .local/keys/ (mounted read-only at /lab-keys). Remediate keys
#    (*remediate*.pub) log in only as the fix user; the lab key works for both, for the lab tests.
AUTH=/home/handscheck/.ssh/authorized_keys
: > "$AUTH"
for key in /lab-keys/*.pub; do
    case "$key" in *remediate*) ;; *) [ -f "$key" ] && cat "$key" >> "$AUTH" ;; esac
done
chown handscheck:handscheck "$AUTH" && chmod 600 "$AUTH"
echo "lab: $(wc -l < "$AUTH") authorized key(s) for handscheck"
FIX_AUTH=/home/handscheck-fix/.ssh/authorized_keys
# Like production (the line on the server page): from= the workers (here: private networks) and the
# handscheck-remediate comment, so the users agent sees an expected fix user on the clean host.
: > "$FIX_AUTH"
for key in /lab-keys/*remediate*.pub /lab-keys/id_ed25519_lab.pub; do
    [ -f "$key" ] || continue
    awk '{ printf "from=\"10.*,172.*,192.168.*\",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty %s %s handscheck-remediate@lab\n", $1, $2 }' "$key" >> "$FIX_AUTH"
done
chown handscheck-fix:handscheck-fix "$FIX_AUTH" && chmod 600 "$FIX_AUTH"
echo "lab: $(wc -l < "$FIX_AUTH") authorized key(s) for handscheck-fix"

# 2. Wait for the lab database (only hosts with sites need it).
i=0
until [ -z "$LAB_SITES" ] || mysqladmin ping -h "$LAB_DB_HOST" -u "$LAB_DB_USER" -p"$LAB_DB_PASSWORD" --silent 2>/dev/null; do
    i=$((i + 1)); [ "$i" -gt 60 ] && { echo "lab: database not reachable" >&2; exit 1; }
    sleep 2
done

# 3. Sites (first boot only; the docroots live in a volume).
host_id=$(echo "$LAB_HOST" | tr -c 'a-z0-9\n' '_')
for site in $LAB_SITES; do
    root="/var/www/$site"
    db="wp_${host_id}_$(echo "${site%%.*}" | tr -c 'a-z0-9\n' '_')"

    cat > "/etc/apache2/sites-available/$site.conf" <<EOF
<VirtualHost *:80>
    ServerName $site
    DocumentRoot $root
    <Directory $root>
        AllowOverride All
        Require all granted
    </Directory>
    ErrorLog \${APACHE_LOG_DIR}/$site-error.log
    CustomLog \${APACHE_LOG_DIR}/$site-access.log combined
</VirtualHost>
EOF
    a2ensite -q "$site" >/dev/null

    marker="/var/www/.lab-installed-$site"
    if [ ! -f "$marker" ]; then
        echo "lab: installing WordPress for $site (db $db)"
        rm -rf "$root" && mkdir -p "$root"
        tar -xzf /opt/wordpress.tar.gz -C "$root" --strip-components=1
        mysql -h "$LAB_DB_HOST" -u "$LAB_DB_USER" -p"$LAB_DB_PASSWORD" -e "CREATE DATABASE IF NOT EXISTS \`$db\`"
        # wp-config.php from the sample (wp-cli's `config create` template breaks when the phar is named `wp`).
        # Unique random salts per line; no network calls.
        awk -v db="$db" -v user="$LAB_DB_USER" -v pass="$LAB_DB_PASSWORD" -v dbhost="$LAB_DB_HOST" '
            BEGIN { srand(); chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#%^*()-_[]{}<>~+=,.;:" }
            /put your unique phrase here/ {
                salt = ""; for (i = 0; i < 64; i++) salt = salt substr(chars, int(rand() * length(chars)) + 1, 1)
                sub(/put your unique phrase here/, salt)
            }
            # No background auto-updates: lab fixtures must stay on the pinned WordPress version.
            NR == 1 { print; print "define( '\''AUTOMATIC_UPDATER_DISABLED'\'', true );"; next }
            { sub(/database_name_here/, db); sub(/username_here/, user); sub(/password_here/, pass)
              sub(/'\''localhost'\''/, "'\''" dbhost "'\''"); print }
        ' "$root/wp-config-sample.php" > "$root/wp-config.php"
        admin_pass=$(head -c 18 /dev/urandom | base64 | tr -d '/+=')
        wp --allow-root --path="$root" core install --url="http://$site" --title="$site (lab)" \
            --admin_user=labadmin --admin_password="$admin_pass" --admin_email="admin@$site" \
            --skip-email --quiet
        echo "$admin_pass" > "/root/$site.admin-password" && chmod 600 "/root/$site.admin-password"
        # Realistic (and risky) default from the incident: code owned by www-data.
        chown -R www-data:www-data "$root"
        touch "$marker"
    fi
done

# 4. Planted fixtures (compromises and look-alikes). Kept off lab-wp1, the clean host for no-false-positive tests.
for fixture in $LAB_FIXTURES; do
    sh "/lab-fixtures/$fixture/apply.sh"
done

# 5. Services. No systemd in the container, so start them directly.
# `docker compose restart` keeps the container filesystem, so stale pid files from the previous run survive;
# Apache on 16.04 then refuses to start ("httpd (pid N) already running") and the container exits.
rm -f /run/apache2/apache2.pid /var/run/apache2/apache2.pid /run/sshd.pid /run/crond.pid /run/php/*.pid
"php-fpm${PHP_VERSION}" -D
cron
/usr/sbin/sshd
echo "lab: $LAB_HOST ready (sites: $LAB_SITES)"
exec apache2ctl -D FOREGROUND
