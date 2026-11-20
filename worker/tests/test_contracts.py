import json
from pathlib import Path

import pytest
from pydantic import BaseModel

from handscheck.contracts import Catalog, Job, Result
from handscheck.contracts.export import default_contracts_dir, export_schemas

EXAMPLES = default_contracts_dir() / "examples"
MODELS: dict[str, type[BaseModel]] = {"job": Job, "result": Result, "catalog": Catalog}


def test_committed_schemas_are_fresh() -> None:
    result = export_schemas(default_contracts_dir(), check=True)
    assert result.stale == [], "run `hc contracts export` and commit the result"


def test_export_writes_then_is_fresh(tmp_path: Path) -> None:
    first = export_schemas(tmp_path)
    assert len(first.written) == 3
    assert export_schemas(tmp_path, check=True).stale == []


@pytest.mark.parametrize("path", sorted(EXAMPLES.glob("*.json")), ids=lambda p: p.name)
def test_examples_validate(path: Path) -> None:
    kind = path.name.split(".")[0]
    model = MODELS[kind]
    model.model_validate(json.loads(path.read_text()))


def test_every_schema_has_an_example() -> None:
    kinds = {p.name.split(".")[0] for p in EXAMPLES.glob("*.json")}
    assert kinds == set(MODELS)


def test_job_private_key_is_not_printed() -> None:
    job = Job.model_validate(json.loads((EXAMPLES / "job.scan.json").read_text()))
    assert "EXAMPLE-NOT-A-REAL-KEY" not in repr(job)
