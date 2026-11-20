#!/bin/sh
# Legitimate files that look like compromise (M3), from the incident's "Pitfalls" list. Planted on the clean host:
# the checks must NOT report them (lab/fixtures/README.md). Applied on first boot only.
set -eu
site=${LAB_SITES%% *}
root=/var/www/$site
content=$root/wp-content
marker=/var/www/.lab-fixture-site-lookalikes
[ -f "$marker" ] && { echo "lab: fixture site-lookalikes already applied"; exit 0; }

# MC4WP debug log: a .php file in uploads that exits first.
printf '<?php exit; ?>\n[2026-10-01 12:00:00] INFO: Form 12 > Successfully subscribed lead@example.test\n' \
    > "$content/uploads/mc4wp-debug-log.php"
# "Silence is golden" index stubs.
mkdir -p "$content/uploads"
printf '<?php\n// Silence is golden.\n' > "$content/uploads/index.php"
# All-In-One Security firewall settings: PHP outside plugins/themes, halted before the JSON.
mkdir -p "$content/aios/firewall-rules"
printf '<?php __halt_compiler();\n{"version":"1.0","firewall":{"blocked_ips":[]}}\n' \
    > "$content/aios/firewall-rules/settings.php"
# A custom (non-wordpress.org) plugin with a Composer vendor/bin script (PHP without an extension).
plugin=$content/plugins/handscheck-lab-tools
mkdir -p "$plugin/vendor/bin"
printf '<?php\n/**\n * Plugin Name: Lab Tools (handscheck fixture)\n * Version: 1.0.0\n */\n' > "$plugin/handscheck-lab-tools.php"
printf '#!/usr/bin/env php\n<?php\nrequire __DIR__ . "/../phpunit/phpunit/phpunit";\n' > "$plugin/vendor/bin/phpunit"
chmod 755 "$plugin/vendor/bin/phpunit"
# A harmless PHP handler line in .htaccess (maps .php only: not a handler trick, not a prepend).
printf 'AddType application/x-httpd-php .php\n' >> "$root/.htaccess"
# A media folder without an index file (directory listings are off: must not be reported).
mkdir -p "$content/uploads/2026/10"
printf 'GIF89a' > "$content/uploads/2026/10/logo.gif"

# An ordinary admin login (M7 watch pass): one session for labadmin from a usual IP. Logins from a known IP on
# one site are not reported.
now=$(date +%s)
command wp --allow-root --path="$root" --skip-plugins --skip-themes user meta update 1 session_tokens \
    "{\"$(printf 'lab-lookalike' | sha256sum | cut -c1-64)\":{\"expiration\":$((now + 172800)),\"ip\":\"192.0.2.10\",\"ua\":\"Mozilla/5.0 (lab)\",\"login\":$now}}" \
    --format=json >/dev/null

chown -R www-data:www-data "$root"
touch "$marker"
echo "lab: fixture site-lookalikes applied to $site"
