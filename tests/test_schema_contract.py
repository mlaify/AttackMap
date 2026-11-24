"""Versioned report schemas and their compatibility guarantee (#200)."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from attackmap.schemas import breaking_changes, report_schema, schema_versions

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _major(version: str) -> str:
    return version.split(".", 1)[0]


def test_report_schema_file_is_generated_from_the_models() -> None:
    assert _load(SCHEMAS / "attackmap-report.schema.json") == report_schema(), (
        "the report models changed: run `python scripts/schemas.py write`, then bump "
        "REPORT_SCHEMA_VERSION and `python scripts/schemas.py freeze` (docs/schemas.md)"
    )


@pytest.mark.parametrize("name", sorted(schema_versions()))
def test_current_version_is_frozen_and_unchanged(name: str) -> None:
    version = schema_versions()[name]
    frozen = SCHEMAS / "frozen" / name / f"{version}.json"
    assert frozen.exists(), f"{name} {version} isn't frozen: run `python scripts/schemas.py freeze`"
    assert _load(SCHEMAS / f"{name}.schema.json") == _load(frozen), (
        f"{name} changed without a version bump: bump it ({version}) and freeze"
    )


@pytest.mark.parametrize("name", sorted(schema_versions()))
def test_no_breaking_change_within_a_major_version(name: str) -> None:
    current = _load(SCHEMAS / f"{name}.schema.json")
    major = _major(schema_versions()[name])
    for snapshot in sorted((SCHEMAS / "frozen" / name).glob("*.json")):
        if _major(snapshot.stem) == major:
            assert breaking_changes(_load(snapshot), current) == [], f"breaking vs {name} {snapshot.stem}"


def test_breaking_changes_detects_removals_and_narrowing() -> None:
    old = {
        "type": "object",
        "properties": {
            "a": {"type": "string"},
            "b": {"type": ["string", "null"]},
            "c": {"enum": ["x", "y"]},
            "d": {"type": "array", "items": {"$ref": "#/$defs/D"}},
        },
        "$defs": {"D": {"type": "object", "properties": {"k": {"type": "integer"}}}},
    }
    added = json.loads(json.dumps(old))
    added["properties"]["e"] = {"type": "boolean"}
    added["properties"]["c"]["enum"].append("z")
    assert breaking_changes(old, added) == []

    broken = json.loads(json.dumps(old))
    del broken["properties"]["a"]
    broken["properties"]["b"]["type"] = "string"
    broken["properties"]["c"]["enum"] = ["x"]
    broken["$defs"]["D"]["properties"]["k"]["type"] = "string"
    assert breaking_changes(old, broken) == [
        "$.a: removed",
        "$.b: type ['null', 'string'] -> ['string']",
        "$.c: enum values removed ['y']",
        "$.d[].k: type ['integer'] -> ['string']",
    ]


def test_a_real_report_validates_against_its_schema(tmp_path: Path) -> None:
    from attackmap.cli import app
    from typer.testing import CliRunner

    (tmp_path / "repo").mkdir()
    (tmp_path / "repo" / "app.py").write_text(
        "from flask import Flask, request\nimport sqlite3\napp = Flask(__name__)\n"
        "@app.route('/search')\ndef search():\n"
        "    return sqlite3.connect('d').execute('SELECT * FROM t WHERE n = ' + request.args['q']).fetchall()\n"
    )
    result = CliRunner().invoke(app, ["analyze", str(tmp_path / "repo"), "--output", str(tmp_path / "out")])
    assert result.exit_code == 0, result.output
    report = _load(tmp_path / "out" / "attackmap-report.json")
    assert report["schema_version"] == schema_versions()["attackmap-report"]
    jsonschema.validate(report, report_schema())
    jsonschema.validate(report["defensive_review_json"], _load(SCHEMAS / "defensive-review.schema.json"))
