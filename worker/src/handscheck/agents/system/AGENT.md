---
name: system
title: System integrity
description: >-
  Root accounts, systemd units and set-id files not owned by a package, the sudo binary's mode, ld.so.preload,
  modprobe files, package integrity (dpkg --verify), kernel, reboots and pending updates.
version: 3
scope: host
cadence: { full: daily, watch: false }
model: claude-opus-5-5
rules: []
settings:
  ignore_units:
    type: list
    items: str
    default: ["snap-*.mount", "snap.*", "var-snap-*.mount"]
    description: Unit file names (shell patterns) to leave out of the unpackaged-unit list.
  setid_scan:
    type: bool
    default: true
    description: Look for SUID/SGID files on the root filesystem (find / -xdev).
  setid_scan_timeout_s:
    type: int
    default: 180
    min: 10
    max: 1800
    description: Timeout for the SUID/SGID scan, in seconds.
  setid_skip_dirs:
    type: list
    items: str
    default: [/var/lib/containerd, /var/lib/docker, /var/lib/lxc, /var/lib/lxd, /snap]
    description: >-
      Directories the SUID/SGID scan skips: container image layers and snaps hold copies of system binaries
      that aren't the host's (one real host had dozens of copies of su/passwd under containerd snapshots).
  ignore_setid_paths:
    type: list
    items: str
    default: []
    description: SUID/SGID paths (shell patterns) known to be fine on this host, e.g. a vendor tool.
  dpkg_verify:
    type: bool
    default: true
    description: Verify package file checksums (dpkg --verify).
  verify_packages:
    type: list
    items: str
    default:
      [bash, coreutils, cron, dpkg, findutils, iproute2, libc-bin, libpam-modules, login, net-tools,
       openssh-client, openssh-server, passwd, procps, sudo, systemd, util-linux]
    description: >-
      Packages to verify (the ones rootkits and backdoors replace). An empty list verifies every package,
      which can take minutes on a large host.
  dpkg_verify_timeout_s:
    type: int
    default: 300
    min: 10
    max: 3600
    description: Timeout for dpkg --verify, in seconds.
---

<!-- handscheck: instructions for Claude are not part of this build -->
