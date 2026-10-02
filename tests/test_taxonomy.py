"""Per-rule taxonomy registry (#250): CWE / OWASP / ASVS / ATT&CK by rule id."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from attackmap import taxonomy
from attackmap.attack_taxonomy import annotate_findings, techniques_for_finding
from attackmap.detection_opportunities import generate_detection_opportunities
from attackmap.diff import FindingSnapshot
from attackmap.models import Finding, Insight
from attackmap.recon_to_analysis import translate_recon
from attackmap.report import render_pr_comment
from attackmap.review_json import build_defensive_review_json
from attackmap.sarif import build_sarif
from attackmap.scanner import scan_repo
from attackmap.taxonomy import RULE_TAXONOMY, RuleTaxonomy, taxonomy_for, validate_entry
from attackmap.threat_model import rule_catalog

ROOT = Path(__file__).resolve().parents[1]
SARIF_SCHEMA = json.loads((ROOT / "tests" / "fixtures" / "sarif" / "sarif-schema-2.1.0.json").read_text(encoding="utf-8"))
REVIEW_SCHEMA = json.loads((ROOT / "schemas" / "defensive-review.schema.json").read_text(encoding="utf-8"))
CATALOG = sorted({r for r, _, _ in rule_catalog()})


@pytest.mark.parametrize("rule_id", CATALOG)
def test_every_catalogued_rule_has_cwe_and_owasp(rule_id: str) -> None:
    """A new rule must be registered in `attackmap/taxonomy.py` — see the
    module docstring for how. Only no-weakness rules may be exempt."""
    if rule_id in taxonomy.INFORMATIONAL_RULES:
        assert taxonomy_for(rule_id) is None
        return
    entry = taxonomy_for(rule_id)
    assert entry is not None, f"{rule_id!r} has no taxonomy entry: add it to RULE_TAXONOMY in src/attackmap/taxonomy.py"
    assert validate_entry(entry) == [], f"{rule_id!r}: {validate_entry(entry)}"


def test_registry_has_no_entries_for_unknown_rules() -> None:
    """Catches typos: every registered id is a catalogued rule."""
    assert set(RULE_TAXONOMY) <= set(CATALOG)


def test_informational_rules_are_catalogued() -> None:
    assert taxonomy.INFORMATIONAL_RULES <= set(CATALOG)


def test_catalogs_are_well_formed() -> None:
    assert all(name for name in taxonomy.CWE_NAMES.values())
    for tid, (name, tactic) in taxonomy.ATTACK_TECHNIQUES.items():
        assert name and tactic
        if "." in tid:
            assert ": " in name  # "Parent: Sub-technique"


def test_speculative_rules_inherit_their_base_entry() -> None:
    assert taxonomy_for("speculative-ssrf") is taxonomy_for("ssrf")
    assert taxonomy_for("speculative-no-such-rule") is None
    assert taxonomy_for(None) is None


def test_register_validates_ids() -> None:
    with pytest.raises(ValueError, match="no CWE"):
        taxonomy.register("plugin-rule", RuleTaxonomy(cwe=(), owasp=("A01:2021",)))
    with pytest.raises(ValueError, match="A11:2021"):
        taxonomy.register("plugin-rule", RuleTaxonomy(cwe=(918,), owasp=("A11:2021",)))
    try:
        taxonomy.register("plugin-rule", RuleTaxonomy(cwe=(918,), owasp=("A10:2021",)))
        finding = Finding(title="t", severity="low", mitigation="m", rule_id="plugin-rule")
        assert finding.taxonomy is not None and finding.taxonomy.cwe == ["CWE-918"]
    finally:
        RULE_TAXONOMY.pop("plugin-rule", None)


# ---------- findings carry the ids ----------


def _scan_findings(tmp_path: Path) -> list[Finding]:
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


def test_every_core_finding_carries_cwe_and_owasp(tmp_path: Path) -> None:
    findings = _scan_findings(tmp_path)
    assert findings
    for f in findings:
        if f.rule_id in taxonomy.INFORMATIONAL_RULES:
            continue
        assert f.taxonomy is not None, f.rule_id
        assert f.taxonomy.cwe and f.taxonomy.owasp
    secret = next(f for f in findings if f.rule_id == "hardcoded-secret")
    assert secret.taxonomy.cwe == ["CWE-798"]
    assert [t.technique_id for t in secret.attack_techniques] == ["T1552.001"]


def test_taxonomy_round_trips_through_json() -> None:
    f = Finding(title="SSRF", severity="medium", mitigation="m", rule_id="ssrf")
    dumped = f.model_dump()
    assert dumped["taxonomy"] == {
        "cwe": ["CWE-918"],
        "owasp": ["A10:2021", "API7:2023"],
        "asvs": ["V5.2.6", "V12.6.1"],
        "attack": ["T1190", "T1552.005"],
    }
    assert Finding.model_validate(dumped).taxonomy == f.taxonomy


def test_unregistered_rule_gets_no_taxonomy() -> None:
    f = Finding(title="Plugin thing", severity="low", mitigation="m", rule_id="plugin-only")
    assert f.taxonomy is None


# ---------- ATT&CK: rule id, not substring matching ----------


def test_evidence_text_never_drives_attack_mapping() -> None:
    """'monkey' / 'executive' / cursor.execute in evidence used to map to
    T1552 / T1059 by substring."""
    f = Finding(
        title="Unusual handler",
        severity="low",
        mitigation="m",
        evidence=["monkey patching in app.py:3", "executive dashboard", "cursor.execute(q)", "author field"],
    )
    ids = {t.technique_id for t in techniques_for_finding(f)}
    assert not ids & {"T1552", "T1528", "T1059", "T1078", "T1110"}
    assert annotate_findings([f])[0].attack_techniques == []


def test_title_fallback_is_whole_word() -> None:
    def ids(title: str) -> set[str]:
        return {t.technique_id for t in techniques_for_finding(Finding(title=title, severity="low", mitigation="m"))}

    assert not ids("Monkey keyboard author executive")
    assert {"T1552", "T1528"} <= ids("API key in config")
    assert "T1078" in ids("Admin panel without login")


def test_registered_rule_uses_registry_techniques_not_title() -> None:
    f = Finding(title="Admin secret token webhook", severity="high", mitigation="m", rule_id="ssrf")
    assert [t.technique_id for t in techniques_for_finding(f)] == ["T1190", "T1552.005"]


# ---------- detection opportunities link by rule id ----------


def _insight(kind: str) -> Insight:
    return Insight(
        id=f"insight:{kind}", kind=kind, title=kind, narrative="n", severity="medium", confidence="medium"
    )


def test_detection_opportunities_link_findings_by_rule_id() -> None:
    from attackmap.attack_taxonomy import annotate_insights

    insights = annotate_insights([_insight("shared_secret_blast_radius")])
    by_rule = Finding(title="Reworded secret finding", severity="high", mitigation="m", rule_id="hardcoded-secret")
    # Shares title words with the opportunity but has no rule id: not linked.
    by_title = Finding(title="Detect signing-key drift across services", severity="low", mitigation="m")
    (opp,) = generate_detection_opportunities(insights, [by_rule, by_title])
    assert opp.related_rule_ids == ["hardcoded-secret"]
    assert opp.related_finding_titles == ["Reworded secret finding"]


# ---------- outputs ----------


def test_sarif_has_cwe_taxonomy_tags_and_validates() -> None:
    findings = [
        Finding(title="SSRF", severity="medium", mitigation="m", rule_id="ssrf"),
        Finding(title="Plugin finding", severity="low", mitigation="m", rule_id="plugin-only"),
    ]
    sarif = build_sarif(findings, [])
    jsonschema.Draft4Validator(SARIF_SCHEMA).validate(sarif)
    run = sarif["runs"][0]
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    ssrf = rules["ssrf"]
    assert "external/cwe/cwe-918" in ssrf["properties"]["tags"]
    assert ssrf["properties"]["owasp"] == ["A10:2021", "API7:2023"]
    assert ssrf["properties"]["security-severity"]
    assert ssrf["helpUri"] == "https://cwe.mitre.org/data/definitions/918.html"
    assert ssrf["relationships"][0]["target"] == {"id": "918", "toolComponent": {"name": "CWE"}}
    assert "relationships" not in rules["plugin-only"]
    (cwe,) = run["taxonomies"]
    assert cwe["name"] == "CWE" and [t["id"] for t in cwe["taxa"]] == ["918"]
    assert run["tool"]["driver"]["supportedTaxonomies"] == [{"name": "CWE"}]


def test_cwe_tags_are_zero_padded_like_codeql() -> None:
    sarif = build_sarif([Finding(title="Cmd", severity="high", mitigation="m", rule_id="subprocess-shell")], [])
    tags = sarif["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]
    assert "external/cwe/cwe-078" in tags


def test_real_scan_sarif_validates(tmp_path: Path) -> None:
    sarif = build_sarif(_scan_findings(tmp_path), [])
    jsonschema.Draft4Validator(SARIF_SCHEMA).validate(sarif)
    assert sarif["runs"][0]["taxonomies"][0]["taxa"]


def test_defensive_review_json_carries_taxonomy(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "app.py").write_text('TOKEN = "ghp_' + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8" + '"\n', encoding="utf-8")
    scan = scan_repo(repo)
    result = translate_recon(scan)
    payload = build_defensive_review_json(scan, result.attack_surfaces, result.findings, result.attack_paths)
    jsonschema.Draft202012Validator(REVIEW_SCHEMA).validate(payload)
    weakness = next(w for w in payload["weaknesses_risk_hotspots"]["weaknesses"] if w["rule_id"] == "hardcoded-secret")
    assert weakness["taxonomy"]["cwe"] == ["CWE-798"]


def test_pr_comment_labels_new_findings_with_taxonomy() -> None:
    snap = FindingSnapshot.from_finding(Finding(title="SSRF", severity="medium", mitigation="m", rule_id="ssrf"))

    class _Diff:
        new = [snap]
        resolved: list = []
        has_new_high = False

    text = render_pr_comment([], _Diff())
    assert "SSRF (CWE-918 · A10:2021 · API7:2023)" in text


def test_workflow_cwe_tags_come_from_the_registry_once() -> None:
    from attackmap.models import ScanResult, WorkflowIssue
    from attackmap.threat_model import generate_findings

    scan = ScanResult(
        root="/",
        workflow_issues=[WorkflowIssue(kind="script_injection", file=".github/workflows/ci.yml", line=3, severity="high")],
    )
    finding = next(f for f in generate_findings(scan) if f.rule_id == "script-injection")
    assert [t for t in finding.tags if t.startswith("external/cwe/")] == ["external/cwe/cwe-078", "external/cwe/cwe-094"]
    rule = build_sarif([finding], [])["runs"][0]["tool"]["driver"]["rules"][0]
    cwe_tags = [t for t in rule["properties"]["tags"] if t.startswith("external/cwe/")]
    assert cwe_tags == ["external/cwe/cwe-078", "external/cwe/cwe-094"]
