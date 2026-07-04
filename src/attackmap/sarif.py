"""SARIF 2.1.0 report emission.

Turns AttackMap `Finding` records into a SARIF log that GitHub Code
Scanning (and other SARIF consumers — VS Code, Sonatype IQ, etc.)
ingest natively. Every field the finding model carries maps to a SARIF
property; nothing new is computed here — it's a serialization layer.

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import re
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from .models import AttackPath, Finding


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)
TOOL_INFO_URI = "https://github.com/mlaify/AttackMap"


# ---------------------------------------------------------------------------
# Severity + score mappings
# ---------------------------------------------------------------------------


def _sarif_level(severity: str) -> str:
    """SARIF `level` is one of `error`, `warning`, `note`, `none`."""
    return {"high": "error", "medium": "warning", "low": "note"}.get(severity, "warning")


def _security_severity(severity: str, confidence: str) -> str:
    """SARIF `securitySeverity` is a 0.0-10.0 string, mirroring CVSS.

    We derive it heuristically from `Finding.severity × Finding.confidence`
    so consumers that filter by CVSS band (a common GitHub Code Scanning
    workflow) get a reasonable ordering out of the box.
    """
    weights = {"high": 9.0, "medium": 6.0, "low": 3.0}
    multiplier = {"high": 1.0, "medium": 0.75, "low": 0.5}.get(confidence, 0.75)
    value = weights.get(severity, 6.0) * multiplier
    # Clamp to SARIF's 0.0-10.0 range and 1-decimal precision.
    return f"{min(10.0, max(0.0, value)):.1f}"


def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug or "finding"


# Regex to lift `file` and `line` from evidence strings like
# `"POST /webhook/x in app.py; auth signals: ..."` (surface_evidence
# format) or `"API_KEY in config.py"` (secret_hint format). Best-effort:
# a location is optional per SARIF spec.
_LOCATION_FROM_EVIDENCE = re.compile(
    r"(?:in|at)\s+`?([\w./_\\-]+\.(?:py|js|jsx|ts|tsx|mjs|cjs|go|rs|php|java|kt|cs|cpp|c|h|hpp|yml|yaml|json|toml|env|sh|dockerfile))`?(?::(\d+))?",
    re.IGNORECASE,
)


def _locations_from_evidence(evidence: list[str]) -> list[dict[str, Any]]:
    seen: set[tuple[str, int | None]] = set()
    locations: list[dict[str, Any]] = []
    for line in evidence:
        for match in _LOCATION_FROM_EVIDENCE.finditer(line):
            file_path = match.group(1)
            raw_line = match.group(2)
            line_num = int(raw_line) if raw_line else None
            key = (file_path, line_num)
            if key in seen:
                continue
            seen.add(key)
            region = {"startLine": line_num} if line_num is not None else {"startLine": 1}
            locations.append(
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_path},
                        "region": region,
                    }
                }
            )
    return locations


# ---------------------------------------------------------------------------
# SARIF construction
# ---------------------------------------------------------------------------


def _tool_version() -> str:
    try:
        return version("attackmap")
    except PackageNotFoundError:
        return "0.0.0-dev"


def _build_rules(findings: list[Finding]) -> list[dict[str, Any]]:
    """One SARIF rule per unique finding title. Consumers use rule ids
    to filter, ignore, or roll up findings; sharing the rule across
    identical-title findings keeps the taxonomy stable."""
    rules_by_id: dict[str, dict[str, Any]] = {}
    for finding in findings:
        rule_id = _slugify(finding.title)
        if rule_id in rules_by_id:
            continue
        rules_by_id[rule_id] = {
            "id": rule_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.title},
            "help": {"text": finding.mitigation, "markdown": finding.mitigation},
            "defaultConfiguration": {"level": _sarif_level(finding.severity)},
            "properties": {
                "tags": list(finding.tags),
                "security-severity": _security_severity(finding.severity, finding.confidence),
            },
        }
    return list(rules_by_id.values())


def _build_results(findings: list[Finding]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for finding in findings:
        rule_id = _slugify(finding.title)
        locations = _locations_from_evidence(finding.evidence)
        properties: dict[str, Any] = {
            "tags": list(finding.tags),
            "security-severity": _security_severity(finding.severity, finding.confidence),
            "confidence": finding.confidence,
        }
        if finding.score is not None:
            # SARIF `rank` is 0-100, higher = more important — same
            # direction as `score` from #4.
            properties["rank"] = float(finding.score)
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _sarif_level(finding.severity),
            "message": {
                "text": finding.title,
                "markdown": f"**{finding.title}**\n\n{finding.mitigation}",
            },
            "properties": properties,
        }
        # If we found citable file locations, attach them; otherwise SARIF
        # allows results without locations (they surface repo-wide).
        if locations:
            result["locations"] = locations
        # Evidence goes to a partial-fingerprints-style secondary spot
        # so the raw citation text isn't lost.
        if finding.evidence:
            result["partialFingerprints"] = {
                "attackmap/evidence": "|".join(finding.evidence[:8]),
            }
        results.append(result)
    return results


def _build_code_flows_from_attack_paths(
    attack_paths: list[AttackPath],
) -> list[dict[str, Any]]:
    """Turn each attack path into a SARIF `codeFlow`. This gives the
    narrative a first-class home separate from findings — SARIF viewers
    render codeFlows as expandable step lists.

    Codeflows aren't attached to a specific result here (attack paths
    are repo-scoped, not per-finding); consumers that want them
    inline can traverse the tool.driver.properties.attackPaths link.
    """
    flows: list[dict[str, Any]] = []
    for path in attack_paths:
        thread_flow_locations = [
            {
                "location": {
                    "message": {"text": step},
                    "physicalLocation": {
                        "artifactLocation": {"uri": ""},
                        "region": {"startLine": 1},
                    },
                }
            }
            for step in path.steps
        ]
        flows.append(
            {
                "message": {"text": f"{path.name}: {path.impact}"},
                "threadFlows": [{"locations": thread_flow_locations}],
            }
        )
    return flows


def build_sarif(
    findings: list[Finding],
    attack_paths: list[AttackPath] | None = None,
) -> dict[str, Any]:
    """Serialize `findings` (+ optional `attack_paths`) as a SARIF 2.1.0
    log dict. Caller is responsible for writing it to disk."""
    rules = _build_rules(findings)
    results = _build_results(findings)

    driver: dict[str, Any] = {
        "name": "AttackMap",
        "version": _tool_version(),
        "informationUri": TOOL_INFO_URI,
        "rules": rules,
    }
    run: dict[str, Any] = {
        "tool": {"driver": driver},
        "results": results,
    }
    if attack_paths:
        # Attach codeflows at the run level via a properties bag. SARIF
        # allows tool-defined properties here; consumers who care about
        # attack paths can traverse `run.properties.attackPaths`.
        run["properties"] = {
            "attackPaths": _build_code_flows_from_attack_paths(attack_paths),
        }
    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [run],
    }


__all__ = ["build_sarif", "SARIF_VERSION"]
