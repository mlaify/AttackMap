from __future__ import annotations

import json
from dataclasses import dataclass

from .models import AttackPath, AttackSurface, Finding, ScanResult
from .security_overlay import build_security_overlay

LOW_QUALITY_SEGMENTS = ("/tests/", "/__tests__/", "/fixtures/", "/mocks/", "/examples/")


SYSTEM_PROMPT_TEMPLATE = """You are AttackMap Review Analyst, a defensive security reviewer.

Operating rules:
- Be evidence-first. Every claim must map to provided evidence.
- Do not invent findings, routes, services, data stores, trust boundaries, or mitigations.
- Distinguish observed vs inferred signals clearly.
- Keep output defensive and remediation-oriented. Do not provide offensive exploitation instructions.
- If evidence is weak or partial, say so directly.

The evidence pack now includes five layers you must reason over:
- `assets` — value-at-risk inventory (with criticality)
- `controls` — defensive controls observed AND expected-but-absent
- `notable_observations` — pre-computed cross-cutting insights connecting assets, controls, surfaces, and chains
- `attack_techniques_observed` — MITRE ATT&CK technique mappings for findings and insights
- `detection_opportunities` — defender-facing detection-engineering hints (Sigma/KQL-style rule sketches)

When writing the review, lead with the highest-severity notable_observations and connect them to specific assets, controls, and ATT&CK techniques. Tell the story — do not just enumerate findings. Explicitly call out where a defense gap meets a critical asset, and reference the relevant ATT&CK technique(s) and any detection opportunity that would catch the same condition at runtime.

Output sections (in order):
1. System Overview
2. Notable Observations (top 3, each as a 2–4 sentence story citing surface/finding/asset/control IDs and the ATT&CK technique it maps to)
3. Asset and Control Map (which crown jewels exist, what protects them, what is missing)
4. Detection Opportunities (top 3 — for each, name the runtime signal that would catch the static finding)
5. Strengths
6. Weaknesses / Risk Hotspots
7. Key Evidence Chains
8. Prioritized Recommendations
9. Analyst Confidence and Limitations

Formatting constraints:
- Use concise, human-readable language for engineers and defenders.
- For each weakness and recommendation, include why it is prioritized.
- Cite evidence IDs from the provided evidence pack where practical (surface:N, finding:N, path:N, asset:*, control:*, insight:*).
"""


USER_PROMPT_TEMPLATE = """Generate a grounded defensive review for this repository.

Requirements:
- Use only the evidence pack below.
- Mark each major statement as OBSERVED or INFERRED.
- Prioritize by practical defensive risk reduction.
- Include explicit trust-boundary commentary where evidence supports it.
- Call out source-quality caveats (tests/fixtures/examples) when relevant.

Repository context:
{repo_context}

Evidence pack (JSON):
{evidence_json}
"""


@dataclass(frozen=True)
class RenderedReviewPrompt:
    system: str
    user: str
    evidence_json: str


def _is_low_quality_source(path_or_text: str) -> bool:
    normalized = path_or_text.replace("\\", "/").lower()
    return any(segment in f"/{normalized}/" for segment in LOW_QUALITY_SEGMENTS)


def _is_protocol_derived_surface(surface: AttackSurface) -> bool:
    file_lower = surface.file.lower()
    route_lower = surface.route.lower()
    return "lexicon" in file_lower or "/xrpc/" in route_lower or "atproto_" in " ".join(surface.auth_signals).lower()


def _surface_evidence_class(surface: AttackSurface) -> str:
    if _is_low_quality_source(surface.file):
        return "low_quality"
    if _is_protocol_derived_surface(surface):
        return "inferred_protocol"
    if surface.exposure == "public":
        return "observed_runtime_public"
    if surface.exposure == "internal":
        return "observed_runtime_internal"
    return "inferred"


def _repo_context(scan: ScanResult) -> str:
    language_text = ", ".join(scan.languages) if scan.languages else "unknown"
    datastore_text = ", ".join(sorted({db.kind for db in scan.databases})) if scan.databases else "none"
    return (
        f"root={scan.root}; files_scanned={scan.files_scanned}; "
        f"languages={language_text}; routes={len(scan.routes)}; "
        f"external_calls={len(scan.external_calls)}; datastores={datastore_text}; "
        f"auth_hints={len(scan.auth_hints)}; secret_hints={len(scan.secret_hints)}"
    )


def _evidence_pack(
    scan: ScanResult,
    attack_surfaces: list[AttackSurface],
    findings: list[Finding],
    attack_paths: list[AttackPath],
) -> dict:
    surfaces_payload = [
        {
            "id": f"surface:{idx + 1}",
            "method": surface.method,
            "route": surface.route,
            "file": surface.file,
            "category": surface.category,
            "exposure": surface.exposure,
            "risk": surface.risk,
            "evidence_class": _surface_evidence_class(surface),
            "auth_signals": surface.auth_signals,
            "data_store_interaction": surface.data_store_interaction,
            "outbound_integration": surface.outbound_integration,
            "rationale": surface.rationale,
        }
        for idx, surface in enumerate(attack_surfaces[:50])
    ]

    findings_payload = [
        {
            "id": f"finding:{idx + 1}",
            "title": finding.title,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "evidence": finding.evidence[:10],
            "mitigation": finding.mitigation,
        }
        for idx, finding in enumerate(findings[:30])
    ]

    attack_paths_payload = [
        {
            "id": f"path:{idx + 1}",
            "name": path.name,
            "steps": path.steps[:8],
            "impact": path.impact,
        }
        for idx, path in enumerate(attack_paths[:10])
    ]

    evidence_counts = {
        "observed_runtime_public": sum(1 for item in surfaces_payload if item["evidence_class"] == "observed_runtime_public"),
        "observed_runtime_internal": sum(1 for item in surfaces_payload if item["evidence_class"] == "observed_runtime_internal"),
        "inferred_protocol": sum(1 for item in surfaces_payload if item["evidence_class"] == "inferred_protocol"),
        "low_quality": sum(1 for item in surfaces_payload if item["evidence_class"] == "low_quality"),
    }

    overlay = build_security_overlay(scan, attack_surfaces, findings, attack_paths)
    assets_payload = [asset.model_dump() for asset in overlay.assets]
    controls_payload = [control.model_dump() for control in overlay.controls]
    insights_payload = [insight.model_dump() for insight in overlay.insights]
    detection_payload = [opp.model_dump() for opp in overlay.detection_opportunities]

    techniques_observed: dict[str, dict] = {}
    for insight in overlay.insights:
        for tech in insight.attack_techniques:
            techniques_observed.setdefault(tech.technique_id, tech.model_dump())
    for finding in overlay.findings:
        for tech in finding.attack_techniques:
            techniques_observed.setdefault(tech.technique_id, tech.model_dump())
    techniques_payload = sorted(techniques_observed.values(), key=lambda t: t["technique_id"])

    return {
        "scan_summary": {
            "root": scan.root,
            "files_scanned": scan.files_scanned,
            "languages": scan.languages,
            "route_count": len(scan.routes),
            "external_call_count": len(scan.external_calls),
            "database_count": len(scan.databases),
            "auth_hint_count": len(scan.auth_hints),
            "secret_hint_count": len(scan.secret_hints),
            "asset_count": len(assets_payload),
            "control_count_present": sum(1 for c in controls_payload if c["strength"] != "absent"),
            "control_count_absent": sum(1 for c in controls_payload if c["strength"] == "absent"),
            "notable_observation_count": len(insights_payload),
            "detection_opportunity_count": len(detection_payload),
            "attack_techniques_observed_count": len(techniques_payload),
        },
        "evidence_counts": evidence_counts,
        "attack_surfaces": surfaces_payload,
        "findings": findings_payload,
        "attack_paths": attack_paths_payload,
        "assets": assets_payload,
        "controls": controls_payload,
        "notable_observations": insights_payload,
        "detection_opportunities": detection_payload,
        "attack_techniques_observed": techniques_payload,
    }


def render_system_prompt() -> str:
    return SYSTEM_PROMPT_TEMPLATE.strip()


def render_user_prompt(
    scan: ScanResult,
    attack_surfaces: list[AttackSurface],
    findings: list[Finding],
    attack_paths: list[AttackPath],
) -> str:
    evidence_payload = _evidence_pack(scan, attack_surfaces, findings, attack_paths)
    evidence_json = json.dumps(evidence_payload, indent=2, sort_keys=True)
    return USER_PROMPT_TEMPLATE.format(repo_context=_repo_context(scan), evidence_json=evidence_json).strip()


def render_review_prompts(
    scan: ScanResult,
    attack_surfaces: list[AttackSurface],
    findings: list[Finding],
    attack_paths: list[AttackPath],
) -> RenderedReviewPrompt:
    evidence_payload = _evidence_pack(scan, attack_surfaces, findings, attack_paths)
    evidence_json = json.dumps(evidence_payload, indent=2, sort_keys=True)
    return RenderedReviewPrompt(
        system=render_system_prompt(),
        user=USER_PROMPT_TEMPLATE.format(repo_context=_repo_context(scan), evidence_json=evidence_json).strip(),
        evidence_json=evidence_json,
    )
