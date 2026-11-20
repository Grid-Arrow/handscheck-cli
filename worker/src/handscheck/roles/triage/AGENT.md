---
name: triage
title: Triage
description: >-
  Decides what happens to verified findings: the final severity, alert now / daily digest / reports only,
  related findings across the organization, and follow-up investigations. Decides; never acts.
version: 1
scope: host
cadence: { full: daily, watch: false }
model: claude-opus-5-5
effort: medium
max_tool_calls: 0
rules: []
settings: {}
---

<!-- handscheck: instructions for Claude are not part of this build -->
