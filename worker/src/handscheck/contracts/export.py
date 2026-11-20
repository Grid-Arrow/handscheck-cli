"""Write (or check) contracts/*.schema.json from the pydantic models."""

import json
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel

from handscheck.contracts.models import Catalog, Job, Result

SCHEMAS: dict[str, type[BaseModel]] = {
    "job": Job,
    "result": Result,
    "catalog": Catalog,
}


def render_schema(model: type[BaseModel]) -> str:
    schema = model.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    return json.dumps(schema, indent=2, sort_keys=True) + "\n"


@dataclass
class ExportResult:
    written: list[Path]
    stale: list[Path]


def export_schemas(out_dir: Path, *, check: bool = False) -> ExportResult:
    """Write every schema to out_dir. With check=True, write nothing and report stale or missing files."""
    written: list[Path] = []
    stale: list[Path] = []
    for name, model in SCHEMAS.items():
        path = out_dir / f"{name}.schema.json"
        content = render_schema(model)
        current = path.read_text() if path.exists() else None
        if current == content:
            continue
        if check:
            stale.append(path)
        else:
            out_dir.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            written.append(path)
    return ExportResult(written=written, stale=stale)


def default_contracts_dir() -> Path:
    """The repo's contracts/ directory (worker/src/handscheck/contracts → repo root)."""
    return Path(__file__).resolve().parents[4] / "contracts"
