---
name: investigator
title: Investigator
description: >-
  `hc investigate`: answers one question about a host with read-only commands, using the latest facts and
  open findings as a starting point.
version: 2
scope: host
cadence: { full: daily, watch: false }
model: claude-opus-5-5
effort: high
max_tool_calls: 25
rules: []
settings: {}
---

<!-- handscheck: instructions for Claude are not part of this build -->
