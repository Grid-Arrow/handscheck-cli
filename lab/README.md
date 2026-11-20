# lab

Docker target hosts for developing and testing checks and agents. Everything here is synthetic. Never point a new
or changed check at a real host until it passes here (CLAUDE.md safety rule 4).

| Service | Image | Sites | SSH from your Mac | HTTP |
|---|---|---|---|---|
| `lab-wp1` | Ubuntu 24.04, Apache, PHP-FPM 8.3, WordPress 6.7. **Clean**: only look-alikes (`site-lookalikes`) | alpha.lab.test, beta.lab.test | `127.0.0.1:2221` | `127.0.0.1:8081` |
| `lab-wp2` | Ubuntu 16.04 (EOL), Apache, PHP-FPM 7.0, WordPress 6.5. Fixtures `host-compromise`, `site-compromise` | gamma.lab.test, delta.lab.test | `127.0.0.1:2222` | `127.0.0.1:8082` |
| `lab-locked` | Ubuntu 24.04 (same image as lab-wp1). Fixture `sudo-lockout` | none | `127.0.0.1:2223` | |
| `lab-db` | MySQL 8.0 (stands in for the shared RDS) | | not exposed | |

Inside the compose network (e.g. from the `worker` container) the hosts are `lab-wp1:22`, `lab-wp2:22` and
`lab-locked:22`.

- Each host has a `handscheck` user with key-only SSH and read-only sudo (`hosts/common/sudoers-handscheck`).
  Public keys in the repo's `.local/keys/*.pub` (git-ignored) are installed at container start.
- WordPress is installed on first boot; site code is owned by `www-data`, like the vulnerable hosts in the
  incident. Apache has directory listings off by default (a site's `.htaccess` can turn them on). The `labadmin` password is in `/root/<site>.admin-password` inside the container.
- No systemd in the containers: services are started by `hosts/common/entrypoint.sh`.

Worker tests against these hosts: `docker compose run --rm worker pytest -m lab` (uses the key from `hc setup` or
`lab/smoke.sh` in `.local/keys/`; CI runs them after the smoke test).

## Self-hosted CLI (Track S1)

`sh lab/selfhosted.sh` builds the self-hosted bundle (`worker/packaging/selfhosted/build.sh`, in Docker; set
`SKIP_BUILD=1` to reuse `worker/dist/`). It runs the bundle's `install.sh` on throwaway containers from both lab
images (fresh user, strict sudoers, check as `handscheck`, upgrade, uninstall), then on lab-wp1 and lab-wp2 (their
own sudoers file is restored afterwards) and runs `sudo -u handscheck hc check --local` there, saving the JSON to
`.local/selfhosted/<host>.json`. `pytest -m lab tests/lab/test_selfhosted_lab.py` then compares
those runs with an SSH scan of the same hosts (same findings; every planted fixture on lab-wp2, none on lab-wp1).
CI runs the script before `pytest -m lab`.

## Fixtures

`fixtures/<name>/apply.sh` plants a synthetic, inert compromise. `hosts/common/entrypoint.sh` applies the folders
listed in a host's `LAB_FIXTURES` (see `docker-compose.yml`) on every start; `lab/fixtures/` is mounted read-only
at `/lab-fixtures`, so editing a fixture needs only `docker compose restart <host>`. lab-wp1 stays clean: it is
the no-false-positive baseline (it carries only legitimate look-alikes). Host fixtures apply on every start; site
fixtures apply once (the web root and database persist), so reset the lab to re-apply them. What each fixture must produce is in [fixtures/README.md](fixtures/README.md) and
enforced by `worker/tests/lab/test_host_agents.py`.

Captured command output from these hosts backs the offline unit tests (`worker/tests/agents/captured/`). After
changing a check's commands or a fixture, re-capture:
`docker compose run --rm worker python -m tests.agents.capture lab-wp1 lab-wp2 lab-locked`.

## Canary (M4)

[canary/expectations.yaml](canary/expectations.yaml) lists what the Claude pipeline must confirm on these hosts
(`expected`), what must never survive verification (`forbidden`: look-alikes, and anything high+ on the clean
lab-wp1), and claims handed straight to the verifier (`verifier_probes`). Both suites call Claude and cost money
(about $1 and $2.50 per run); they skip without `ANTHROPIC_API_KEY`:

```bash
docker compose run --rm worker pytest -m agents    # specialists on the replayed captures → .local/agents-eval.json
docker compose run --rm worker pytest -m canary    # specialists → verifier on the live lab → .local/canary-report.json
```

Reset the lab completely (fresh WordPress installs and database):

```bash
docker compose down lab-wp1 lab-wp2 lab-locked lab-db && docker volume rm handscheck_lab-wp1-www handscheck_lab-wp2-www handscheck_lab-db
```
