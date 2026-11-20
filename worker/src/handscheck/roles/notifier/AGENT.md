---
name: notifier
title: Notifier
description: >-
  Writes the alert and digest text people receive (email and Slack). Only the words come from Claude; code
  decides who gets what and when, and delivers it.
version: 1
scope: org
cadence: { full: daily, watch: false }
model: claude-opus-5-5
effort: low
max_tool_calls: 0
rules: []
settings: {}
---

<!-- handscheck: instructions for Claude are not part of this build -->
