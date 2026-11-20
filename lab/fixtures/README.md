# Lab fixtures

Synthetic, inert compromises planted on lab hosts by `hosts/common/entrypoint.sh` (per host: `LAB_FIXTURES` in
`docker-compose.yml`). Each is modeled on the Oct 2026 incident
([docs/incidents/2026-10-wordpress-compromise.md](../../docs/incidents/2026-10-wordpress-compromise.md)).
Nothing here runs or reaches the network. `lab-wp1` gets no fixtures: it is the clean host for the
no-false-positive tests.

| Fixture | Host | Planted | Must be reported as (raw fact) |
|---|---|---|---|
| `host-compromise` | lab-wp2 (16.04) | uid-0 account `sysbackup` | `system.uid0_accounts`, `users.accounts` (uid 0) |
| | | `/etc/systemd/system/dbus-socket-helper.service` (ExecStart=/usr/sbin/authd), enabled in `multi-user.target.wants` | `system.unpackaged_units` (with `ExecStart` and `enabled_by`) |
| | | `/usr/sbin/authd`, a do-nothing script with mode 4755 | `system.unpackaged_setid_files` |
| | | `www-data` crontab `*/30 * * * * /dev/shm/.x/checker` | `persistence.web_user_crontabs`, `persistence.cron_entries` |
| | | hidden `/dev/shm/.x/checker` owned by www-data | `persistence.temp_entries` (reasons `hidden`, `web_user`) |
| `sudo-lockout` | lab-locked (24.04) | `chmod 000 /usr/bin/sudo` | `system.sudo_binary` mode `0000`, `sudo_binary_ok: false`; the run reports sudo unavailable |
| `site-compromise` | lab-wp2, gamma.lab.test | web shell `uploads/2026/10/cache.php` (exits first) | `malware.php_in_uploads`, `fingerprint_hits` (obfuscated-loader and input-to-exec fingerprints) |
| | | backdoor `plugins/akismet/class.akismet-widget-cache.php`, mtime copied from `akismet.php` | `malware.fingerprint_hits` (hex-encoded function name, header-secret fingerprints), `wordpress.plugin_checksums.akismet.extra` |
| | | `.user.ini` with `auto_prepend_file` → inert `uploads/wp-cache.php` | `malware.php_directives` (suspicious), `malware.php_in_uploads` |
| | | admin `root` / admin@wordpress.com with user #1's registration date | `wordpress.admins` flags `registered_copied` and the wordpress.com-email and `root`-login account rules |
| | | admins `tempuser_8f3a`, `tempuser_2c91` | `wordpress.admins` flag (the `tempuser*` account rule) |
| | | `revslider` 4.1.4 (header only) | `wordpress.vulnerable_plugins` (the revslider CVE-2014-9734 rule) |
| | | `backup-2026-10.sql` in the web root (40 synthetic customer rows) | `exposure.sensitive_files` with `http_status: 200` |
| | | `uploads/leads/` with PDFs and `Options +Indexes` | `exposure.directory_listings` |
| | | `info.php` calling `phpinfo()` | `exposure.phpinfo_files` with `served: true` |
| `site-lookalikes` | lab-wp1, alpha.lab.test (clean host) | `uploads/mc4wp-debug-log.php`, `uploads/index.php` "Silence is golden", `wp-content/aios/firewall-rules/settings.php`, a custom plugin with `vendor/bin/phpunit`, a harmless `AddType … .php` in `.htaccess`, a media folder without an index, an ordinary `labadmin` login session from 192.0.2.10 (watch pass) | **nothing** reported: the first four are in `malware.suppressed` (rules in `false-positives.yaml`), the directive is not suspicious, the folder is not listable |

The sudo lockout has its own host because the scan can't use read-only sudo there either, which would hide the
other fixtures (e.g. root-only crontabs).

Each fixture also shows up in the diff when the previous snapshot didn't have it
(`worker/tests/pipeline/test_run.py::test_diff_against_a_cleaner_previous_snapshot`).

Not reproducible in the lab: the faked-mtime signal (`malware.timing_outliers`). Site files are installed and the
fixture planted on the same first boot, so every ctime is minutes apart; the planted backdoor is found by
fingerprints and checksums instead, and the timing heuristic is unit-tested with synthetic times.

Precision on the clean host (`worker/tests/lab/test_host_agents.py::test_clean_host_has_no_false_positives`): no
extra uid-0 account, no unpackaged unit (lab-wp1 is usr-merged, and dpkg knows ~300 of its units only under the
other /lib ↔ /usr/lib name), no unpackaged set-id file, no tampered binary, no web-user crontab, no notable temp
file, every cron script and timer owned by a package.

The watch pass (M7) looks at recent logins, so its positives can't be planted at boot: `lab/replay/oct21.sh`
plants an Oct 21-style burst on lab-wp2 with current timestamps (synchronized logins, forged sessions, a login
followed by a plugin upload) and `sh lab/replay/oct21.sh clean` removes the sessions again;
`tests/lab/test_watch_lab.py` plants the same burst through the fix user.
