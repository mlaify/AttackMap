from __future__ import annotations

from dataclasses import dataclass

from .asset_model import detect_assets
from .attack_taxonomy import annotate_findings, annotate_insights
from .control_model import detect_controls
from .detection_opportunities import generate_detection_opportunities
from .insights import generate_insights
from .models import (
    Asset,
    AttackPath,
    AttackSurface,
    Control,
    DetectionOpportunity,
    Finding,
    Insight,
    ScanResult,
)


@dataclass(frozen=True)
class SecurityOverlay:
    """Cross-cutting security view layered on top of raw scan signals.

    Bundles:
      * the asset inventory (`assets`),
      * the defensive control map (`controls`, present + absent),
      * the set of cross-cutting insights connecting them (`insights`),
      * defender-facing detection-engineering hints (`detection_opportunities`),
      * findings with ATT&CK technique mappings layered in (`findings`).

    Computed once per analyze run and consumed by the JSON report, the
    markdown review, and the LLM prompt pack.
    """

    assets: list[Asset]
    controls: list[Control]
    insights: list[Insight]
    detection_opportunities: list[DetectionOpportunity]
    findings: list[Finding]


def build_security_overlay(
    scan: ScanResult,
    attack_surfaces: list[AttackSurface],
    findings: list[Finding],
    attack_paths: list[AttackPath],
) -> SecurityOverlay:
    assets = detect_assets(scan)
    controls = detect_controls(scan, attack_surfaces, assets)
    raw_insights = generate_insights(
        scan,
        attack_surfaces,
        [finding.title for finding in findings],
        attack_paths,
        assets,
        controls,
    )
    insights = annotate_insights(raw_insights)
    annotated_findings = annotate_findings(findings)
    detection_opportunities = generate_detection_opportunities(insights, annotated_findings)
    return SecurityOverlay(
        assets=assets,
        controls=controls,
        insights=insights,
        detection_opportunities=detection_opportunities,
        findings=annotated_findings,
    )
