---
name: persistence
title: Persistence
description: >-
  Crontabs (especially www-data's), cron script directories, systemd timers, and hidden, web-user-owned or
  executable files in /tmp, /var/tmp and /dev/shm.
version: 4
scope: host
cadence: { full: daily, watch: true }
model: claude-opus-5-5
rules: []
settings:
  web_users:
    type: list
    items: str
    default: [www-data, apache, nginx]
    description: Accounts that run web code; their crontabs and temp files are notable.
  temp_dirs:
    type: list
    items: str
    default: [/tmp, /var/tmp, /dev/shm]
    description: World-writable directories to inspect.
  temp_depth:
    type: int
    default: 3
    min: 1
    max: 6
    description: How deep to look inside each temp directory.
  ignore_temp_names:
    type: list
    items: str
    default:
      [.X11-unix, .ICE-unix, .XIM-unix, .font-unix, .Test-unix, ".X*-lock", "systemd-private-*",
       snap-private-tmp, "tmux-*"]
    description: File or directory names (shell patterns) in temp directories that are always fine.
---

<!-- handscheck: instructions for Claude are not part of this build -->
