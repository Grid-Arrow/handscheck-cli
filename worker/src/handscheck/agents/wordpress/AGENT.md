---
name: wordpress
title: WordPress core, plugins and admins
description: >-
  Per WordPress site: core, plugin, theme and mu-plugin versions; administrators (rogue-admin signals); plugins
  on the known-vulnerable list; core and wordpress.org plugin files checked against official checksums.
version: 3
scope: site
cadence: { full: daily, watch: false }
model: claude-opus-5-5
rules: [rules/accounts.yaml, shared:vulnerable-plugins.yaml]
settings:
  read_admins:
    type: bool
    default: true
    description: Read administrators with `wp db query` (fixed SELECT templates) as the site user.
  wp_cli_user:
    type: str
    default: www-data
    description: The user that runs wp-cli (needs read access to wp-config.php; must be allowed by the policy).
  verify_core_checksums:
    type: bool
    default: true
    description: Compare core files with wordpress.org checksums (fetched by the worker, md5sum on the host).
  verify_plugin_checksums:
    type: bool
    default: true
    description: Compare wordpress.org plugins with their official checksums (premium plugins have none).
  checksum_php_only:
    type: bool
    default: true
    description: Only verify .php files (much faster; shells and backdoors are PHP).
---

<!-- handscheck: instructions for Claude are not part of this build -->
