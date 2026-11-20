---
name: verifier
title: Verifier
description: >-
  An independent second opinion on every finding of severity medium or higher before anyone is alerted. Sees
  the claim and its evidence, not the specialist's reasoning; may re-check with read-only commands.
version: 2
scope: host
cadence: { full: daily, watch: false }
model: claude-opus-5-5
effort: high
max_tool_calls: 8
rules: []
settings: {}
---

<!-- handscheck: instructions for Claude are not part of this build -->
