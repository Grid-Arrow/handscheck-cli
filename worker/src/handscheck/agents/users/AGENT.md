---
name: users
title: Users, keys and sudo
description: >-
  Accounts, privileged groups, sudoers rules, every authorized_keys file, and an auth.log summary: SSH logins,
  su/sudo by web users (www-data), failed su, root-TTY sudo.
version: 3
scope: host
cadence: { full: daily, watch: true }
model: claude-opus-5-5
rules: []
settings:
  privileged_groups:
    type: list
    items: str
    default: [sudo, admin, wheel, root]
    description: Groups whose members can become root.
  web_users:
    type: list
    items: str
    default: [www-data, apache, nginx]
    description: Accounts that run web code; su/sudo by them is a strong compromise signal.
  ignore_sudo_users:
    type: list
    items: str
    default: []
    description: Users whose sudo commands are left out of the summary (the scan user is always left out).
  auth_log_path:
    type: str
    default: /var/log/auth.log
    description: The auth log to summarize.
  auth_log_lines:
    type: int
    default: 20000
    min: 0
    max: 500000
    description: >-
      How many trailing auth.log lines to summarize (0 = skip the log). At most the last 4 MB of the log is read
      (sudo logs every command in full, so lines can be long).
  auth_log_hours:
    type: int
    default: 48
    min: 1
    max: 720
    description: Only log lines from this many hours back are summarized.
---

<!-- handscheck: instructions for Claude are not part of this build -->
