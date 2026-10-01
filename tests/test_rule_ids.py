"""Stable rule ids (#223)."""

from __future__ import annotations

import json
import re
from pathlib import Path

from typer.testing import CliRunner

from attackmap import suppress
from attackmap.cli import app
from attackmap.models import Finding, finding_rule_id, title_slug
from attackmap.recon_to_analysis import translate_recon
from attackmap.sarif import build_sarif
from attackmap.scanner import scan_repo
from attackmap.suppress import Suppression, SuppressionSet, apply_suppressions
from attackmap.threat_model import rule_catalog

runner = CliRunner()
RULE_IDS = {r for r, _, _ in rule_catalog()}


def _findings(tmp_path: Path) -> list[Finding]:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    key = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    (repo / "src" / "app.py").write_text(
        "import requests, hashlib\n"
        f'TOKEN = "{key}"\n'
        "def f(u, password):\n"
        "    hashlib.md5(password.encode())\n"
        "    return requests.get(u, verify=False)\n",
        encoding="utf-8",
    )
    return translate_recon(scan_repo(repo)).findings


def test_catalog_ids_are_unique_and_slug_shaped() -> None:
    ids = [r for r, _, _ in rule_catalog()]
    assert len(ids) == len(set(ids))
    assert all(re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", r) for r in ids)


def test_every_core_finding_has_a_catalogued_rule_id(tmp_path: Path) -> None:
    findings = _findings(tmp_path)
    assert findings and all(f.rule_id for f in findings)
    assert {f.rule_id for f in findings} <= RULE_IDS
    assert {"hardcoded-secret", "insecure-tls", "weak-password-hash"} <= {f.rule_id for f in findings}


def test_sarif_rule_id_is_the_stable_id(tmp_path: Path) -> None:
    findings = _findings(tmp_path)
    run = build_sarif(findings, [])["runs"][0]
    assert {r["ruleId"] for r in run["results"]} == {f.rule_id for f in findings}
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} >= {f.rule_id for f in findings}


def test_rule_id_survives_a_title_rewording() -> None:
    a = Finding(title="Old wording", severity="high", mitigation="m", rule_id="hardcoded-secret")
    b = Finding(title="New wording", severity="high", mitigation="m", rule_id="hardcoded-secret")
    assert finding_rule_id(a) == finding_rule_id(b) == "hardcoded-secret"
    assert finding_rule_id(Finding(title="No Id", severity="low", mitigation="m")) == "no-id"


def test_suppress_by_rule_id_and_legacy_title_slug_with_warning(tmp_path: Path) -> None:
    finding = next(f for f in _findings(tmp_path) if f.rule_id == "hardcoded-secret")
    by_id = apply_suppressions([finding], SuppressionSet([Suppression(reason="r", rule="hardcoded-secret")]))
    assert by_id.suppressed and not by_id.notices

    legacy = title_slug(finding.title)
    by_slug = apply_suppressions([finding], SuppressionSet([Suppression(reason="r", rule=legacy)]))
    assert by_slug.suppressed
    assert any("legacy" in n and "hardcoded-secret" in n for n in by_slug.notices)


def test_unused_entries_are_reported(tmp_path: Path) -> None:
    findings = _findings(tmp_path)
    sups = [Suppression(reason="r", rule="no-such-rule"), Suppression(reason="r", path="vendor/**")]
    outcome = apply_suppressions(findings, SuppressionSet(sups))
    assert len([n for n in outcome.notices if "matched no findings" in n]) == 2


def test_documented_examples_use_real_rule_ids() -> None:
    doc = suppress.__doc__ or ""
    documented = set(re.findall(r"rule:\s*([a-z0-9-]+)", doc)) | set(re.findall(r"attackmap:ignore\[([a-z0-9-]+)\]", doc))
    assert documented and documented <= RULE_IDS


def test_rules_command_lists_catalog() -> None:
    result = runner.invoke(app, ["rules", "--json"])
    assert result.exit_code == 0, result.output
    assert {r["rule_id"] for r in json.loads(result.output)} == RULE_IDS
    plain = runner.invoke(app, ["rules"])
    assert "hardcoded-secret" in plain.output and "insecure-tls" in plain.output
