---
name: planner
title: Planner
description: >-
  Before a daily scan with something to follow up (open serious findings, a recent fix, package or site
  changes), decides which agents look deeper this time. Can only add depth; code validates the plan.
version: 1
scope: host
cadence: { full: daily, watch: false }
model: claude-haiku-5-5
effort: low
max_tool_calls: 0
rules: []
settings: {}
---

<!-- handscheck: instructions for Claude are not part of this build -->
