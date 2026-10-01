"""SARIF result identity, locations and schema validity (#230)."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from attackmap.fingerprint import assign_fingerprints
from attackmap.models import AttackPath, Finding, FindingLocation
from attackmap.recon_to_analysis import translate_recon
from attackmap.sarif import build_sarif
from attackmap.scanner import scan_repo

SCHEMA = json.loads((Path(__file__).parent / "fixtures" / "sarif" / "sarif-schema-2.1.0.json").read_text(encoding="utf-8"))
SECRET = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


def _validate(sarif: dict) -> None:
    jsonschema.Draft4Validator(SCHEMA).validate(sarif)


def _repo(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, body in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(body, encoding="utf-8")
    return tmp_path


APP = (
    "from flask import Flask, request\nimport subprocess, requests\n\napp = Flask(__name__)\n\n"
    '@app.route("/run", methods=["POST"])\ndef run():\n'
    '    subprocess.run("x " + request.form["f"], shell=True)\n'
    '    return requests.get(request.args["u"], verify=False).text\n'
)


def _sarif(repo: Path) -> dict:
    analysis = translate_recon(scan_repo(repo))
    return build_sarif(analysis.findings, analysis.attack_paths)


def test_real_scan_validates_against_the_official_schema(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "r", {"app.py": APP, "cfg.py": f'TOKEN = "{SECRET}"\n', "Dockerfile": "FROM python:3.12\n"})
    _validate(_sarif(repo))


def test_one_result_per_instance_with_stable_partial_fingerprint(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "r", {"a.py": f'A = "{SECRET}"\n', "b.py": f'B = "{SECRET}"\n'})
    results = [r for r in _sarif(repo)["runs"][0]["results"] if r["ruleId"] == "hardcoded-secret"]
    assert len(results) == 2
    assert all(len(r["locations"]) == 1 for r in results)
    fps = {r["partialFingerprints"]["attackmapInstance/v1"] for r in results}
    assert len(fps) == 2
    assert all("|" not in fp and len(fp) == 32 for fp in fps)  # a hash, never evidence text


def test_partial_fingerprint_survives_new_sibling_and_line_drift(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "r", {"a.py": f'A = "{SECRET}"\n'})
    before = {r["partialFingerprints"]["attackmapInstance/v1"] for r in _sarif(repo)["runs"][0]["results"] if r["ruleId"] == "hardcoded-secret"}
    (repo / "a.py").write_text(f'"""doc"""\n\n\nA = "{SECRET}"\n', encoding="utf-8")
    (repo / "b.py").write_text(f'B = "{SECRET}"\n', encoding="utf-8")
    after = {r["partialFingerprints"]["attackmapInstance/v1"] for r in _sarif(repo)["runs"][0]["results"] if r["ruleId"] == "hardcoded-secret"}
    assert before <= after and len(after) == 2


def test_no_fabricated_line_and_relative_uri_base(tmp_path: Path) -> None:
    finding = Finding(title="t", severity="low", mitigation="m", locations=[FindingLocation(file="Dockerfile")])
    assign_fingerprints([finding], tmp_path)
    result = build_sarif([finding])["runs"][0]["results"][0]
    physical = result["locations"][0]["physicalLocation"]
    assert "region" not in physical
    assert physical["artifactLocation"] == {"uri": "Dockerfile", "uriBaseId": "%SRCROOT%"}


@pytest.mark.parametrize(
    ("path", "uri"),
    [("app/(auth)/page.tsx", "app/(auth)/page.tsx"), ("src\\win\\x.py", "src/win/x.py"), ("dir with space/a b.py", "dir%20with%20space/a%20b.py"), ("pkg/@scope/i.ts", "pkg/@scope/i.ts")],
)
def test_uris_are_forward_slashed_and_percent_encoded(path: str, uri: str) -> None:
    finding = Finding(title="t", severity="low", mitigation="m", locations=[FindingLocation(file=path, line=3)])
    loc = build_sarif([finding])["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == uri and loc["region"] == {"startLine": 3}


def test_evidence_goes_to_properties_and_attack_path_steps_have_no_fake_location() -> None:
    finding = Finding(title="t", severity="high", mitigation="m", evidence=["route POST /x in app.py"])
    path = AttackPath(name="p", steps=["Entry: POST /x", "Sink: shell"], impact="i")
    sarif = build_sarif([finding], [path])
    result = sarif["runs"][0]["results"][0]
    assert result["properties"]["evidence"] == ["route POST /x in app.py"]
    flow_locs = sarif["runs"][0]["properties"]["attackPaths"][0]["threadFlows"][0]["locations"]
    assert all("physicalLocation" not in fl["location"] for fl in flow_locs)
    _validate(sarif)
