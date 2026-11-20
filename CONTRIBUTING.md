# Contributing

This repository is an export of handscheck's private monorepo, synced on each release (`SOURCE` names the
commit). Issues are welcome. Pull requests are welcome too: we port accepted changes into the monorepo by hand,
credit you in the commit, and they come back here with the next sync, so the PR itself is closed rather than
merged.

Before you open one: `docker compose run --rm worker sh -c 'ruff format --check . && ruff check . && mypy &&
pytest'` should pass. Changes to the command policy need a test for both an allowed and a refused form.
