"""SARIF 2.1.0 report emission.

Turns AttackMap `Finding` records into a SARIF log that GitHub Code
Scanning (and other SARIF consumers — VS Code, Sonatype IQ, etc.)
ingest natively. Every field the finding model carries maps to a SARIF
property; nothing new is computed here — it's a serialization layer.

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import quote
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from .srcpaths import evidence_locations
from .md import md_text
from .models import AttackPath, Finding, TaintFlowStep, finding_rule_id
from .taxonomy import CWE_NAMES, cwe_tag, cwe_url, taxonomy_for


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


SRCROOT = "%SRCROOT%"


def _sarif_uri(file_path: str) -> str:
    """Repo-relative, forward-slashed, percent-encoded artifact URI (#230)."""
    return quote(file_path.replace("\\", "/").lstrip("/"), safe="/@()[]+~-._")


def _sarif_location(file_path: str, line_num: int | None) -> dict[str, Any]:
    physical: dict[str, Any] = {"artifactLocation": {"uri": _sarif_uri(file_path), "uriBaseId": SRCROOT}}
    # No fabricated `startLine: 1` (#230): a location without a known line is
    # a file-level location with no region.
    if line_num is not None and line_num >= 1:
        physical["region"] = {"startLine": line_num}
    return {"physicalLocation": physical}


def _instances(finding: Finding) -> list[tuple[str, int | None, str | None]]:
    """``(file, line, fingerprint)`` per instance: structured locations first
    (with their #222 fingerprints), else the files cited in evidence."""
    if finding.locations:
        pairs = [(loc.file, loc.line, loc.fingerprint) for loc in finding.locations]
    else:
        pairs = [(f, l, None) for f, l in evidence_locations(finding.evidence)]
    seen: set[tuple[str, int | None]] = set()
    out: list[tuple[str, int | None, str | None]] = []
    for file, line, fp in pairs:
        key = (file.replace("\\", "/"), line)
        if key not in seen:
            seen.add(key)
            out.append((key[0], line, fp))
    return out


def _finding_locations(finding: Finding) -> list[dict[str, Any]]:
    return [_sarif_location(file, line) for file, line, _ in _instances(finding)]


def _locations_from_evidence(evidence: list[str]) -> list[dict[str, Any]]:
    return [_sarif_location(path, line) for path, line in evidence_locations(evidence)]


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
        rule_id = finding_rule_id(finding)
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
        _add_rule_taxonomy(rules_by_id[rule_id], rule_id)
    return list(rules_by_id.values())


CWE_TAXONOMY = "CWE"


def _add_rule_taxonomy(rule: dict[str, Any], rule_id: str) -> None:
    """CWE tags, helpUri, CWE relationships and the OWASP/ASVS/ATT&CK ids
    from the taxonomy registry (#250). Unregistered rules are left as is."""
    entry = taxonomy_for(rule_id)
    if entry is None:
        return
    props = rule["properties"]
    # Detectors may already tag the CWE (workflow findings do); keep one copy.
    props["tags"] = list(dict.fromkeys([*props["tags"], *(cwe_tag(c) for c in entry.cwe)]))
    props["cwe"] = entry.cwe_ids
    props["owasp"] = list(entry.owasp)
    if entry.asvs:
        props["asvs"] = list(entry.asvs)
    if entry.attack:
        props["attack"] = list(entry.attack)
    rule["helpUri"] = cwe_url(entry.cwe[0])
    rule["relationships"] = [
        {"target": {"id": str(c), "toolComponent": {"name": CWE_TAXONOMY}}, "kinds": ["superset"]}
        for c in entry.cwe
    ]


def _cwe_taxonomy(rules: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The run's CWE `taxonomies` entry: one taxon per CWE a rule cites."""
    ids = sorted(
        {int(rel["target"]["id"]) for rule in rules for rel in rule.get("relationships", [])}
    )
    if not ids:
        return None
    return {
        "name": CWE_TAXONOMY,
        "organization": "MITRE",
        "informationUri": "https://cwe.mitre.org/",
        "shortDescription": {"text": "The MITRE Common Weakness Enumeration"},
        "taxa": [
            {
                "id": str(c),
                "name": CWE_NAMES.get(c, f"CWE-{c}"),
                "shortDescription": {"text": CWE_NAMES.get(c, f"CWE-{c}")},
                "helpUri": cwe_url(c),
            }
            for c in ids
        ],
    }


def _stable_hash(*parts: object) -> str:
    return hashlib.sha256("\x1f".join(str(p) for p in parts).encode("utf-8")).hexdigest()[:32]


def _code_flow(steps: list[TaintFlowStep]) -> dict[str, Any]:
    """A traced source→sink flow (#239) as a SARIF ``codeFlow``: one
    threadFlow whose locations are the source, each propagation /
    sanitizer / guard step, and the sink."""
    locations = []
    for step in steps:
        loc = _sarif_location(step.file, step.line)
        loc["message"] = {"text": f"{step.kind}: {step.evidence_text or ''}".rstrip(": ")}
        locations.append({"location": loc, "kinds": [step.kind]})
    source = steps[0] if steps else None
    text = f"{source.evidence_text} flows to the sink" if source and source.evidence_text else "taint flow"
    return {"message": {"text": text}, "threadFlows": [{"locations": locations}]}


def _flows_by_sink(finding: Finding) -> dict[tuple[str, int | None], list[dict[str, Any]]]:
    out: dict[tuple[str, int | None], list[dict[str, Any]]] = {}
    for steps in finding.code_flows:
        if not steps:
            continue
        sink = steps[-1]
        out.setdefault((sink.file.replace("\\", "/"), sink.line), []).append(_code_flow(steps))
    return out


def _build_result(finding: Finding, *, suppression_reason: str | None = None) -> list[dict[str, Any]]:
    """One SARIF result per finding instance (#230).

    Each result carries a single primary location and a partial fingerprint
    derived from (rule id, instance fingerprint) — never evidence text — so
    Code Scanning keeps alert identity (and dismissals) stable when another
    instance appears or a snippet changes. Evidence lives in properties.
    """
    rule_id = finding_rule_id(finding)
    properties: dict[str, Any] = {
        "tags": list(finding.tags),
        "security-severity": _security_severity(finding.severity, finding.confidence),
        "confidence": finding.confidence,
    }
    if finding.score is not None:
        # SARIF `rank` is 0-100, higher = more important — same
        # direction as `score` from #4.
        properties["rank"] = float(finding.score)
    if finding.evidence:
        properties["evidence"] = list(finding.evidence[:8])

    def result(location: dict[str, Any] | None, fingerprint: str) -> dict[str, Any]:
        r: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _sarif_level(finding.severity),
            "message": {
                "text": finding.title,
                "markdown": f"**{md_text(finding.title)}**\n\n{finding.mitigation}",
            },
            "partialFingerprints": {"attackmapInstance/v1": fingerprint},
            "properties": properties,
        }
        if location is not None:
            r["locations"] = [location]
        # Suppressed findings stay in the log (not dropped) but carry a SARIF
        # `suppressions` array so viewers / GitHub Code Scanning show them as
        # suppressed rather than active (#144).
        if suppression_reason is not None:
            r["suppressions"] = [
                {"kind": "external", "justification": suppression_reason or "suppressed by AttackMap"}
            ]
        return r

    instances = _instances(finding)
    if not instances:
        # Repo-level finding (no citable file): identity is the rule + title.
        return [result(None, _stable_hash(rule_id, finding.title))]
    results = [
        result(_sarif_location(file, line), _stable_hash(rule_id, fp or f"{file}:{line}"))
        for file, line, fp in instances
    ]
    # Traced taint flows (#239) ride on the result at their sink location.
    flows = _flows_by_sink(finding)
    if flows:
        for r, (file, line, _) in zip(results, instances):
            matched = flows.pop((file, line), None)
            if matched:
                r["codeFlows"] = matched
    return results


def _build_results(findings: list[Finding]) -> list[dict[str, Any]]:
    return [r for finding in findings for r in _build_result(finding)]


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
        # Steps are narrative, not code positions: a message-only location
        # (no fabricated empty URI / line 1, #230).
        thread_flow_locations = [{"location": {"message": {"text": step}}} for step in path.steps]
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
    *,
    suppressed: list[tuple[Finding, str]] | None = None,
) -> dict[str, Any]:
    """Serialize `findings` (+ optional `attack_paths`) as a SARIF 2.1.0
    log dict. Caller is responsible for writing it to disk.

    `suppressed` is a list of ``(finding, justification)`` pairs (#144):
    they are emitted as results carrying a SARIF ``suppressions`` array so
    consumers show them as suppressed rather than active.
    """
    suppressed = suppressed or []
    # Rules taxonomy must cover suppressed findings too, so their ruleId
    # resolves in viewers.
    rules = _build_rules(findings + [f for f, _ in suppressed])
    results = _build_results(findings)
    for f, reason in suppressed:
        results.extend(_build_result(f, suppression_reason=reason))

    driver: dict[str, Any] = {
        "name": "AttackMap",
        "version": _tool_version(),
        "informationUri": TOOL_INFO_URI,
        "rules": rules,
    }
    cwe_taxonomy = _cwe_taxonomy(rules)
    if cwe_taxonomy is not None:
        driver["supportedTaxonomies"] = [{"name": CWE_TAXONOMY}]
    run: dict[str, Any] = {
        "tool": {"driver": driver},
        # Artifact URIs are relative to the scanned repo root; the absolute
        # local path is deliberately not embedded.
        "originalUriBaseIds": {SRCROOT: {"description": {"text": "Root of the scanned repository."}}},
        "results": results,
    }
    if cwe_taxonomy is not None:
        run["taxonomies"] = [cwe_taxonomy]
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
