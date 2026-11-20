---
name: health
title: Site health
description: >-
  Watch pass (every 15-60 min, rules only): each site's homepage probed from the worker (status, time), plus
  load, memory, swap, php-fpm and web server state, php-fpm pm.max_children warnings, and per-site and
  per-user-agent traffic. Flags sites that are down or much slower than usual two passes in a row, with the
  likely cause, and offers a service restart only when php-fpm saturation or a stopped service explains it.
version: 1
scope: host
cadence: { full: daily, watch: true }
rules: []
settings:
  slow_s:
    type: float
    default: 5.0
    min: 0.5
    max: 60.0
    description: A homepage slower than this many seconds (and slow_factor times its usual) is slow.
  slow_factor:
    type: float
    default: 3.0
    min: 1.0
    max: 50.0
    description: ...and this many times slower than its usual (median of earlier good probes).
  lookback_minutes:
    type: int
    default: 90
    min: 10
    max: 1440
    description: The window for php-fpm warnings and the traffic share.
  access_log_lines:
    type: int
    default: 20000
    min: 0
    max: 200000
    description: How many trailing access-log lines per site to count (at most the last 4 MB is read).
---

<!-- handscheck: instructions for Claude are not part of this build -->
