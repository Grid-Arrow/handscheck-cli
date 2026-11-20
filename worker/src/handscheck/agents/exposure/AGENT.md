---
name: exposure
title: Exposure and hygiene
description: >-
  Per site: database dumps, archives, backups and logs in the web root (and whether they download), phpinfo
  pages, directory listings, XML-RPC, code the web server can write, and PHP/Ubuntu past end of support.
version: 5
scope: site
cadence: { full: daily, watch: false }
model: claude-opus-5-5
rules: [shared:eol.yaml]
settings:
  sensitive_names:
    type: list
    items: str
    default:
      ["*.sql", "*.sql.gz", "*.sql.zip", "*.sql.bz2", "*.dump", "*.bak", "*.old", "*.orig", "*.swp", "*.zip",
       "*.tar", "*.tar.gz", "*.tgz", "*.rar", "*.7z", ".env", "wp-config.php.*", "*.wp-config.php", "*.log"]
    description: File names (shell patterns) that shouldn't sit in a web root.
  sensitive_depth:
    type: int
    default: 3
    min: 1
    max: 8
    description: How deep below the document root to look for them.
  web_users:
    type: list
    items: str
    default: [www-data, apache, nginx]
    description: Accounts the web server runs as.
  http_probes:
    type: bool
    default: true
    description: Confirm exposures with a few GET requests from the worker.
  listing_probe_limit:
    type: int
    default: 25
    min: 0
    max: 200
    description: How many folders without an index file to test for directory listings.
---

<!-- handscheck: instructions for Claude are not part of this build -->
