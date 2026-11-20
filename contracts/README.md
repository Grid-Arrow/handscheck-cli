# contracts

JSON Schemas for the worker ↔ control plane boundary, generated from the pydantic models in
`worker/src/handscheck/contracts/`. Don't edit `*.schema.json` by hand:

```bash
docker compose run --rm worker hc contracts export
```

`examples/` holds one example per schema (`<schema>.<name>.json`). The worker tests validate them against the
models, and the Laravel contract tests replay them (M5). Examples are synthetic: no real hosts, keys or logs.
