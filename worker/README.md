# handscheck worker

The Python package behind the `hc` CLI (alias `handscheck`): the read-only command policy, the local and SSH
runners, the checks (`src/handscheck/agents/<name>/check.py`), rules, redaction and the contract with the
handscheck control plane. See the [repository README](../README.md).

```bash
docker compose run --rm worker hc --help
```
