"""Tests for SARIF report emission (#42)."""

from __future__ import annotations

import json

from attackmap.models import AttackPath, Finding
from attackmap.sarif import SARIF_VERSION, build_sarif


# ---------------------------------------------------------------------------
# Top-level shape
# ---------------------------------------------------------------------------


def test_empty_findings_still_produce_valid_sarif_envelope() -> None:
    """SARIF requires the runs[] structure even with zero results —
    a downstream ingestion pipeline shouldn't have to special-case
    empty scans."""
    sarif = build_sarif([])
    assert sarif["version"] == SARIF_VERSION
    assert sarif["$schema"].endswith("sarif-schema-2.1.0.json")
    assert isinstance(sarif["runs"], list) and len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "AttackMap"
    assert run["tool"]["driver"]["version"]  # non-empty
    assert run["tool"]["driver"]["rules"] == []
    assert run["results"] == []


def test_sarif_is_json_serializable() -> None:
    """Every value in the SARIF dict must be plain-JSON serializable —
    downstream consumers write it to disk and forward it via HTTP."""
    sarif = build_sarif(
        [Finding(title="A finding", severity="high", mitigation="Fix it.", confidence="high")]
    )
    # Round-trip via json.dumps to prove no lingering non-JSON types.
    dumped = json.dumps(sarif)
    parsed = json.loads(dumped)
    assert parsed == sarif


# ---------------------------------------------------------------------------
# Severity + score mapping
# ---------------------------------------------------------------------------


def test_severity_maps_to_sarif_level() -> None:
    """SARIF level: high -> error, medium -> warning, low -> note."""
    findings = [
        Finding(title="H", severity="high", mitigation="m", confidence="high"),
        Finding(title="M", severity="medium", mitigation="m", confidence="high"),
        Finding(title="L", severity="low", mitigation="m", confidence="high"),
    ]
    sarif = build_sarif(findings)
    levels = {r["ruleId"]: r["level"] for r in sarif["runs"][0]["results"]}
    assert levels["h"] == "error"
    assert levels["m"] == "warning"
    assert levels["l"] == "note"


def test_result_carries_finding_score_as_sarif_rank() -> None:
    """`Finding.score` (0-100) → SARIF `properties.rank` (0-100).
    Higher = triage first, same direction on both sides."""
    findings = [
        Finding(title="X", severity="high", mitigation="m", confidence="high", tags=[], score=88)
    ]
    sarif = build_sarif(findings)
    result = sarif["runs"][0]["results"][0]
    assert result["properties"]["rank"] == 88.0


def test_security_severity_maps_confidence_and_severity_to_0_10_scale() -> None:
    """SARIF `security-severity` is a 0.0-10.0 string; used by GitHub
    Code Scanning to bucket findings into Critical/High/Medium/Low."""
    hi_hi = Finding(title="A", severity="high", mitigation="m", confidence="high")
    med_lo = Finding(title="B", severity="medium", mitigation="m", confidence="low")
    lo_lo = Finding(title="C", severity="low", mitigation="m", confidence="low")
    sarif = build_sarif([hi_hi, med_lo, lo_lo])
    by_rule = {r["ruleId"]: r["properties"]["security-severity"] for r in sarif["runs"][0]["results"]}
    assert float(by_rule["a"]) > float(by_rule["b"]) > float(by_rule["c"])
    # Values are formatted as 0.0-10.0
    for value in by_rule.values():
        assert 0.0 <= float(value) <= 10.0


# ---------------------------------------------------------------------------
# Tags flow through
# ---------------------------------------------------------------------------


def test_finding_tags_appear_on_both_rule_and_result() -> None:
    finding = Finding(
        title="Hard-coded secret",
        severity="high",
        mitigation="Rotate + remove.",
        confidence="high",
        tags=["secret-exposure", "hardcoded-literal", "data-risk"],
    )
    sarif = build_sarif([finding])
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    result = sarif["runs"][0]["results"][0]
    assert set(rule["properties"]["tags"]) == set(finding.tags)
    assert set(result["properties"]["tags"]) == set(finding.tags)


# ---------------------------------------------------------------------------
# Rule dedup
# ---------------------------------------------------------------------------


def test_two_findings_with_the_same_title_share_one_rule() -> None:
    """Two hard-coded-secret findings on different files should share
    one rule id in tool.driver.rules — the rule taxonomy is stable
    across the run."""
    findings = [
        Finding(
            title="Hard-coded secret literals were found",
            severity="high",
            mitigation="m",
            confidence="high",
            evidence=["AKIA…MPLE in app.py"],
        ),
        Finding(
            title="Hard-coded secret literals were found",
            severity="high",
            mitigation="m",
            confidence="high",
            evidence=["ghp_…6789 in config.py"],
        ),
    ]
    sarif = build_sarif(findings)
    assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 1
    assert len(sarif["runs"][0]["results"]) == 2


# ---------------------------------------------------------------------------
# Locations extracted from evidence
# ---------------------------------------------------------------------------


def test_locations_extracted_from_evidence_strings() -> None:
    finding = Finding(
        title="X",
        severity="high",
        mitigation="m",
        confidence="high",
        evidence=[
            "POST /webhook/stripe in app.py; auth signals: bearer",
            "external call: https://api.example.com in api/routes.py",
        ],
    )
    sarif = build_sarif([finding])
    locations = sarif["runs"][0]["results"][0].get("locations", [])
    uris = {loc["physicalLocation"]["artifactLocation"]["uri"] for loc in locations}
    assert "app.py" in uris
    assert "api/routes.py" in uris


def test_findings_without_extractable_locations_omit_the_field() -> None:
    """SARIF allows results without locations. Don't fabricate them."""
    finding = Finding(
        title="A repo-wide observation",
        severity="low",
        mitigation="m",
        confidence="low",
        evidence=["Repository looked mostly static."],
    )
    sarif = build_sarif([finding])
    result = sarif["runs"][0]["results"][0]
    assert "locations" not in result


# ---------------------------------------------------------------------------
# Attack paths surface at the run properties level
# ---------------------------------------------------------------------------


def test_attack_paths_render_as_codeflows_under_run_properties() -> None:
    paths = [
        AttackPath(
            name="External event spoofing into internal state change",
            steps=["Entry: POST /webhook", "Weak point: no signature", "Impact: state change"],
            impact="Unauthorized state changes.",
        )
    ]
    sarif = build_sarif([], attack_paths=paths)
    run_props = sarif["runs"][0].get("properties", {})
    flows = run_props.get("attackPaths", [])
    assert len(flows) == 1
    flow = flows[0]
    assert "External event spoofing" in flow["message"]["text"]
    thread = flow["threadFlows"][0]
    assert len(thread["locations"]) == 3
    step_messages = [loc["location"]["message"]["text"] for loc in thread["locations"]]
    assert step_messages[0].startswith("Entry:")


def test_no_attack_paths_means_no_run_properties_key() -> None:
    sarif = build_sarif([])
    assert "properties" not in sarif["runs"][0] or "attackPaths" not in sarif["runs"][0].get("properties", {})


# ---------------------------------------------------------------------------
# Slugify guard against exotic titles
# ---------------------------------------------------------------------------


def test_rule_id_slugified_from_finding_title() -> None:
    finding = Finding(
        title="Public webhook endpoint may trust attacker-controlled events!",
        severity="high",
        mitigation="m",
        confidence="high",
    )
    sarif = build_sarif([finding])
    rule_id = sarif["runs"][0]["results"][0]["ruleId"]
    # Lowercase, hyphenated, no spaces or exotic chars.
    assert rule_id == "public-webhook-endpoint-may-trust-attacker-controlled-events"
