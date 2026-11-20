---
name: recon
title: Recon
description: >-
  Maps a new server (OS, web server, PHP pools, sites and their owners, log locations) and proposes per-server
  agent settings. A person accepts the proposal; recon never changes anything.
version: 3
scope: host
cadence: { full: daily, watch: false }
model: claude-opus-5-5
effort: medium
max_tool_calls: 12
rules: []
settings: {}
---

<!-- handscheck: instructions for Claude are not part of this build -->
