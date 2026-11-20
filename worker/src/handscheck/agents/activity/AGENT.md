---
name: activity
title: Logins and admin activity
description: >-
  Watch pass (every 15-60 min, rules only): WordPress login sessions on every site, the recent access log, and
  SSH logins from auth.log. Flags forged sessions, synchronized logins across sites, a login followed by a plugin
  upload or file edit, and admins or SSH users logging in from a new IP.
version: 2
scope: host
cadence: { full: daily, watch: true }
rules: []
settings:
  wp_cli_user:
    type: str
    default: www-data
    description: The account wp-cli reads each site's database as (the site files' owner).
  lookback_minutes:
    type: int
    default: 90
    min: 10
    max: 1440
    description: >-
      Only logins and requests this recent count. Longer than the watch interval, so nothing falls in a gap.
  access_log_lines:
    type: int
    default: 5000
    min: 0
    max: 200000
    description: >-
      How many trailing lines of each site's access log to check (0 = skip access logs); at most the last 4 MB
      is read.
  auth_log_path:
    type: str
    default: /var/log/auth.log
    description: Where SSH logins are logged.
  auth_log_lines:
    type: int
    default: 5000
    min: 0
    max: 200000
    description: >-
      How many trailing auth.log lines to check (0 = skip SSH logins); at most the last 4 MB is read.
  forged_min_users:
    type: int
    default: 5
    min: 2
    max: 1000
    description: This many users of one site "logging in" within forged_window_s means forged sessions.
  forged_window_s:
    type: int
    default: 2
    min: 0
    max: 60
    description: Seconds within which the forged-session logins fall.
  sync_window_s:
    type: int
    default: 120
    min: 5
    max: 3600
    description: >-
      Logins of the same account on two or more sites within this many seconds, from an IP new for it, are
      synchronized.
  sync_min_accounts:
    type: int
    default: 3
    min: 2
    max: 100
    description: Or this many accounts logging in across sites from one new IP within sync_window_s.
  upload_window_s:
    type: int
    default: 900
    min: 30
    max: 86400
    description: A plugin upload or file edit this soon after a login from an unknown IP is flagged.
  known_ip_days:
    type: int
    default: 90
    min: 1
    max: 730
    description: An account's IP is remembered as known for this many days after it was last seen.
  trusted_ips:
    type: list
    items: str
    default: []
    description: IPs or CIDR ranges (office, VPN) never reported as new.
---

<!-- handscheck: instructions for Claude are not part of this build -->
