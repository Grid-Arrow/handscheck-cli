# handscheck CLI

Read-only security checks for Linux web servers, run on the server itself. `hc check --local` looks at the
things attackers change on a compromised WordPress/PHP host: extra uid-0 accounts, unpackaged set-uid binaries,
web-user crontabs, hidden files in `/dev/shm`, PHP in uploads, backdoored plugins, rogue WordPress admins,
known-vulnerable plugins, exposed dumps and directory listings. It keeps a local history and shows what changed
since the last run.

This is the source of the free self-hosted CLI of [handscheck.ai](https://handscheck.ai). It is published so you
can read exactly what runs on your server.

## What it does on your server
- **Read-only.** Every command goes through a fixed allowlist (`worker/src/handscheck/ssh/policy.py`) before it
  runs: no writes, deletes, installs, restarts, or network fetches. Commands are executed directly, never through
  a shell.
- **Not as root.** It runs as a `handscheck` user with no password, no SSH keys and no login shell. A sudoers file
  you can read (`worker/packaging/selfhosted/sudoers-handscheck`) lets it read the files only root can read, and
  nothing that writes.
- **Sends nothing.** The free CLI makes no outbound requests. HTTP probes go only to your own sites on
  127.0.0.1. `--checksums` opts in to fetching WordPress.org checksums.

## Install (Ubuntu 16.04–24.04, amd64 or arm64)
Download the release bundle for your architecture, then read `handscheck/install.sh` and
`handscheck/sudoers-handscheck` before running:

```bash
tar -xzf handscheck-<version>-linux-<arch>.tar.gz
sudo sh handscheck/install.sh          # shows what it will do and asks first
sudo -u handscheck hc check --local
hc --help
```

`sudo sh /opt/handscheck/install.sh --uninstall [--purge]` removes it.

The bundle carries its own Python and the full rule set. This repository has the rule format and one example
rule per file (`worker/rules/`, `worker/src/handscheck/agents/*/rules/`). Prompts for handscheck's Claude
analysis (the paid tiers) are not part of it. Agent definitions (`AGENT.md`) keep their front matter (name,
version, settings schema) and say so in place of the instructions.

## Develop
Everything runs in Docker:

```bash
docker compose run --rm worker pytest                      # unit tests
docker compose up -d lab-db lab-wp1 lab-wp2 lab-locked     # synthetic lab hosts (lab/README.md)
sh lab/smoke.sh
sh worker/packaging/selfhosted/build.sh                    # build the bundle (this repo's example rules)
```

## License
[FSL-1.1-ALv2](LICENSE): use, modify and redistribute for any purpose except a competing product or service. Each
version becomes Apache 2.0 two years after its release.

Report security problems as described in [SECURITY.md](SECURITY.md). This repository is a mirror; see
[CONTRIBUTING.md](CONTRIBUTING.md).
