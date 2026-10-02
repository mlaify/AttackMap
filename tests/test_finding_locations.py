"""Structured finding locations (#214) and the shared evidence-path parser (#213)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from attackmap.cli import app
from attackmap.models import Finding, FindingLocation
from attackmap.recon_to_analysis import translate_recon
from attackmap.sarif import _finding_locations, _locations_from_evidence, build_sarif
from attackmap.scanner import scan_repo
from attackmap.srcpaths import evidence_locations
from attackmap.suppress import _evidence_paths

runner = CliRunner()


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("POST /x in src/App.tsx", [("src/App.tsx", None)]),
        ("API_KEY in web/app.jsx:42", [("web/app.jsx", 42)]),
        ("secret in config/app.json", [("config/app.json", None)]),
        ("x at lib/util.hpp:7", [("lib/util.hpp", 7)]),
        ("x in a/b.cjs and c/d.mjs:3", [("a/b.cjs", None), ("c/d.mjs", 3)]),
        ("GET /x in app/(auth)/login/page.tsx", [("app/(auth)/login/page.tsx", None)]),
        ("x in packages/@acme/api/index.ts", [("packages/@acme/api/index.ts", None)]),
        ("root user in Dockerfile", [("Dockerfile", None)]),
        (".github/workflows/ci.yml:12 — uses: actions/checkout@main", [(".github/workflows/ci.yml", 12)]),
        ("POST /u/{id} [src/api/[id]/route.ts:9] — dev", [("src/api/[id]/route.ts", 9)]),
        ("see https://example.com/a.py", []),
        ("version v1.2 in use", []),
    ],
)
def test_evidence_locations(text: str, expected: list) -> None:
    assert evidence_locations([text]) == expected


def test_sarif_keeps_full_extension_and_line() -> None:
    loc = _locations_from_evidence(["API_KEY in web/app.jsx:42"])[0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "web/app.jsx"
    assert loc["region"]["startLine"] == 42


def test_structured_locations_win_over_evidence() -> None:
    finding = Finding(
        title="t", severity="low", mitigation="m", evidence=["see other.py:1"],
        locations=[FindingLocation(file="real/x.py", line=7)],
    )
    assert [l["physicalLocation"]["artifactLocation"]["uri"] for l in _finding_locations(finding)] == ["real/x.py"]
    assert _evidence_paths(finding) == ["real/x.py"]


def _repo(tmp_path: Path, files: dict[str, str]) -> Path:
    repo = tmp_path / "repo"
    for rel, body in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(body, encoding="utf-8")
    return repo


_CLASSES = {
    "src/client.py": "import requests\n\ndef f(u):\n    return requests.get(u, verify=False)\n",
    "src/crypto.py": "import hashlib\n\ndef h(password):\n    return hashlib.md5(password.encode()).hexdigest()\n",
    ".github/workflows/ci.yml": "on: pull_request\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@main\npermissions: {}\n",
}


def test_every_core_finding_carries_locations(tmp_path: Path) -> None:
    scan = scan_repo(_repo(tmp_path, _CLASSES))
    findings = translate_recon(scan).findings
    located = {f.title: f.locations for f in findings}
    assert all(f.locations for f in findings if "limited attack surface" not in f.title), [
        f.title for f in findings if not f.locations
    ]
    files = {loc.file for locs in located.values() for loc in locs}
    assert {"src/client.py", "src/crypto.py", ".github/workflows/ci.yml"} <= files


def test_sarif_has_file_and_line_for_weakness_classes(tmp_path: Path) -> None:
    findings = translate_recon(scan_repo(_repo(tmp_path, _CLASSES))).findings
    sarif = build_sarif(findings, [])
    by_uri = {
        loc["physicalLocation"]["artifactLocation"]["uri"]: loc["physicalLocation"]["region"]["startLine"]
        for r in sarif["runs"][0]["results"]
        for loc in r.get("locations", [])
    }
    assert by_uri.get("src/client.py") == 4
    assert by_uri.get("src/crypto.py") == 4
    assert by_uri.get(".github/workflows/ci.yml") == 6


def test_locations_are_not_capped_like_evidence(tmp_path: Path) -> None:
    files = {f"src/m{i}.py": "import hashlib\nhashlib.md5(password.encode())\n" for i in range(14)}
    findings = translate_recon(scan_repo(_repo(tmp_path, files))).findings
    md5 = next(f for f in findings if any(l.file.startswith("src/m") for l in f.locations))
    assert len(md5.locations) == 14 and len(md5.evidence) <= 11


def test_inline_ignore_suppresses_verify_false_finding(tmp_path: Path) -> None:
    repo = _repo(tmp_path, {
        "src/client.py": "import requests\n\ndef f(u):\n"
        "    return requests.get(u, verify=False)  # attackmap:ignore[tls-certificate-hostname-verification-disabled] internal CA\n",
    })
    out = tmp_path / "out"
    result = runner.invoke(app, ["analyze", str(repo), "-o", str(out), "--format", "json"])
    assert result.exit_code == 0, result.output
    report = json.loads((out / "attackmap-report.json").read_text(encoding="utf-8"))
    assert not any("TLS" in f["title"] for f in report["findings"])
    assert any("TLS" in f["title"] for f in report["suppressed_findings"])


def test_inline_ignore_works_in_tsx_files(tmp_path: Path) -> None:
    key = "sk_" + "live_" + "a1B2c3D4e5F6g7H8i9J0k1L2"
    repo = _repo(tmp_path, {"src/Widget.tsx": f'const API_SECRET = "{key}"; // attackmap:ignore test key\n'})
    out = tmp_path / "out"
    result = runner.invoke(app, ["analyze", str(repo), "-o", str(out), "--format", "json"])
    assert result.exit_code == 0, result.output
    report = json.loads((out / "attackmap-report.json").read_text(encoding="utf-8"))
    assert not any("secret" in f["title"].lower() for f in report["findings"])
    assert any("secret" in f["title"].lower() for f in report["suppressed_findings"])


def test_line_number_matches_naive_count() -> None:
    import random

    from attackmap.srcpaths import line_number

    rng = random.Random(218)
    text = "".join(rng.choice("ab\n") for _ in range(5000))
    for offset in [0, 1, 2, 100, 2500, 4999, 5000, -3]:
        expected = 1 if offset <= 0 else text.count("\n", 0, offset) + 1
        assert line_number(text, offset) == expected
