#!/usr/bin/env python3
"""Maintain the versioned report schemas (#200, docs/schemas.md).

    python scripts/schemas.py write    # regenerate schemas/attackmap-report.schema.json
    python scripts/schemas.py freeze   # snapshot every schema at its current version

`freeze` runs when a schema version is bumped (and at release); it refuses to
overwrite a snapshot that differs, since a released version is immutable.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attackmap.schemas import report_schema, schema_versions  # noqa: E402

SCHEMAS = ROOT / "schemas"


def _dump(data: dict) -> str:
    return json.dumps(data, indent=2) + "\n"


def write() -> None:
    (SCHEMAS / "attackmap-report.schema.json").write_text(_dump(report_schema()), encoding="utf-8")


def freeze() -> int:
    for name, version in schema_versions().items():
        current = (SCHEMAS / f"{name}.schema.json").read_text(encoding="utf-8")
        target = SCHEMAS / "frozen" / name / f"{version}.json"
        if target.exists() and target.read_text(encoding="utf-8") != current:
            print(f"{name} {version} is frozen with different content: bump its version", file=sys.stderr)
            return 1
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(current, encoding="utf-8")
        print(f"{name} {version}")
    return 0


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) == 2 else ""
    if command == "write":
        write()
    elif command == "freeze":
        sys.exit(freeze())
    else:
        sys.exit(__doc__)
