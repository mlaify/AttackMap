from __future__ import annotations

import re

from .models import AttackPath, AttackSurface, Finding, ScanResult

LOW_QUALITY_SEGMENTS = ("/tests/", "/__tests__/", "/fixtures/", "/mocks/", "/examples/")


def _severity_rank(value: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(value, 3)


def _surface_risk_rank(value: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(value, 3)


def _confidence_rank(value: str) -> float:
    return {"high": 3.0, "medium": 2.0, "low": 1.0}.get(value, 1.0)


def _extract_numeric_confidence(text: str) -> float | None:
    match = re.search(r"confidence=([0-9]+(?:\.[0-9]+)?)", text.lower())
    if match is None:
        return None
    try:
        return float(match.group(1))
    except ValueError:
        return None


def _contains_any(text: str, keywords: tuple[str, ...]) -> bool:
    lowered = text.lower()
    return any(keyword in lowered for keyword in keywords)


def _is_low_quality_source(path_or_text: str) -> bool:
    normalized = path_or_text.replace("\\", "/").lower()
    return any(segment in f"/{normalized}/" for segment in LOW_QUALITY_SEGMENTS)


def _is_protocol_derived_surface(surface: AttackSurface) -> bool:
    file_lower = surface.file.lower()
    route_lower = surface.route.lower()
    return "lexicon" in file_lower or "/xrpc/" in route_lower or "atproto_" in " ".join(surface.auth_signals).lower()


def _entrypoint_counts(attack_surfaces: list[AttackSurface]) -> tuple[int, int, int, int]:
    observed_runtime_public = 0
    protocol_derived = 0
    internal_only = 0
    low_quality = 0
    for surface in attack_surfaces:
        if _is_low_quality_source(surface.file):
            low_quality += 1
            continue
        if surface.exposure == "internal":
            internal_only += 1
            continue
        if _is_protocol_derived_surface(surface):
            protocol_derived += 1
            continue
        if surface.exposure == "public":
            observed_runtime_public += 1
    return observed_runtime_public, protocol_derived, internal_only, low_quality


def _surface_provenance(surface: AttackSurface) -> str:
    if _is_low_quality_source(surface.file):
        return "low_quality"
    if _is_protocol_derived_surface(surface):
        return "protocol_derived"
    if surface.exposure == "public":
        return "observed_runtime"
    return "other"


def _provenance_breakdown(surfaces: list[AttackSurface]) -> str:
    if not surfaces:
        return "observed_runtime=0%, protocol_derived=0%, low_quality=0%"
    counts = {"observed_runtime": 0, "protocol_derived": 0, "low_quality": 0}
    for surface in surfaces:
        key = _surface_provenance(surface)
        if key in counts:
            counts[key] += 1
    total = max(len(surfaces), 1)
    observed_pct = round((counts["observed_runtime"] / total) * 100)
    protocol_pct = round((counts["protocol_derived"] / total) * 100)
    low_quality_pct = round((counts["low_quality"] / total) * 100)
    return (
        f"observed_runtime={observed_pct}%, "
        f"protocol_derived={protocol_pct}%, "
        f"low_quality={low_quality_pct}%"
    )


def _provenance_counts(surfaces: list[AttackSurface]) -> dict[str, int]:
    counts = {"observed_runtime": 0, "protocol_derived": 0, "low_quality": 0}
    for surface in surfaces:
        key = _surface_provenance(surface)
        if key in counts:
            counts[key] += 1
    return counts


def _recommendation_basis_label(surfaces: list[AttackSurface]) -> str:
    counts = _provenance_counts(surfaces)
    total = max(sum(counts.values()), 1)
    observed_pct = (counts["observed_runtime"] / total) * 100
    protocol_pct = (counts["protocol_derived"] / total) * 100
    low_quality_pct = (counts["low_quality"] / total) * 100
    if observed_pct >= 50:
        return "observed"
    if protocol_pct >= 50:
        return "inferred-protocol"
    if low_quality_pct >= 50:
        return "low-quality-evidence"
    return "mixed-evidence"


def _top_score_reasons(factors: dict[str, float], top_n: int = 3) -> str:
    ranked = sorted(factors.items(), key=lambda item: item[1], reverse=True)
    top = [f"{name}={value:.1f}" for name, value in ranked[:top_n] if value > 0]
    return ", ".join(top)


def _surface_priority(surface: AttackSurface) -> tuple[float, dict[str, float]]:
    exposure_score = {"public": 3.0, "unknown": 2.0, "internal": 1.0}.get(surface.exposure, 1.0)
    privilege_score = {
        "admin": 3.0,
        "auth": 3.0,
        "webhook": 2.0,
        "upload": 2.0,
        "public_api": 1.5,
        "internal": 1.0,
        "health": 0.5,
    }.get(surface.category, 1.0)
    reachability_score = 2.0 if surface.exposure == "public" else 1.0
    trust_boundary_score = (2.0 if surface.data_store_interaction else 0.0) + (2.0 if surface.outbound_integration else 0.0)
    chain_depth_score = 1.0 + (1.0 if surface.data_store_interaction and surface.outbound_integration else 0.0)
    confidence_score = 2.0 if surface.auth_signals else 1.0
    weighted = {
        "exposure": 2.0 * exposure_score,
        "privilege": 2.0 * privilege_score,
        "reachability": 1.5 * reachability_score,
        "trust_boundary": 1.5 * trust_boundary_score,
        "chain_depth": 1.0 * chain_depth_score,
        "confidence": 1.0 * confidence_score,
    }
    if _is_low_quality_source(surface.file):
        weighted["source_quality_penalty"] = -8.0
    return round(sum(weighted.values()), 2), weighted


def _path_priority(path: AttackPath) -> tuple[float, dict[str, float]]:
    text = f"{path.name} {path.impact} {' '.join(path.steps)}"
    exposure_score = 3.0 if _contains_any(text, ("attacker reaches", "public", "/xrpc/")) else 2.0
    privilege_score = 1.0 + (
        2.0
        if _contains_any(text, ("admin", "privileged", "authorization", "authz", "token", "identity"))
        else 0.5
    )
    reachability_score = 2.0 if any(step.lower().startswith("entry:") for step in path.steps) else 1.0
    trust_boundary_score = 1.0 + sum(
        1.0
        for step in path.steps
        if _contains_any(step, ("propagation", "service", "edge", "external", "config risk", "sink"))
    )
    chain_depth_score = max(1.0, min(len(path.steps), 8) / 2.0)
    evidence_text = " ".join(path.steps)
    numeric_confidence = _extract_numeric_confidence(evidence_text)
    confidence_score = 1.5 + (numeric_confidence if numeric_confidence is not None else 0.5)
    weighted = {
        "exposure": 2.0 * exposure_score,
        "privilege": 2.0 * privilege_score,
        "reachability": 1.5 * reachability_score,
        "trust_boundary": 2.0 * trust_boundary_score,
        "chain_depth": 1.2 * chain_depth_score,
        "confidence": 1.5 * confidence_score,
    }
    if _is_low_quality_source(text):
        weighted["source_quality_penalty"] = -10.0
    return round(sum(weighted.values()), 2), weighted


def _related_surfaces_for_finding(finding: Finding, attack_surfaces: list[AttackSurface]) -> list[AttackSurface]:
    combined = f"{finding.title} {' '.join(finding.evidence)}".lower()
    related = [
        surface
        for surface in attack_surfaces
        if surface.route.lower() in combined
        or surface.file.lower() in combined
        or surface.category.lower() in combined
    ]
    return related or attack_surfaces


def _related_paths_for_finding(finding: Finding, attack_paths: list[AttackPath], surfaces: list[AttackSurface]) -> list[AttackPath]:
    if not attack_paths:
        return []
    combined = f"{finding.title} {' '.join(finding.evidence)}".lower()
    surface_tokens = [surface.route.lower() for surface in surfaces if surface.route]
    related = [
        path
        for path in attack_paths
        if path.name.lower() in combined
        or any(step.lower() in combined for step in path.steps[:2])
        or any(token in " ".join(path.steps).lower() for token in surface_tokens)
    ]
    return related or attack_paths


def _finding_priority(finding: Finding, attack_surfaces: list[AttackSurface], attack_paths: list[AttackPath]) -> tuple[float, dict[str, float]]:
    surfaces = _related_surfaces_for_finding(finding, attack_surfaces)
    paths = _related_paths_for_finding(finding, attack_paths, surfaces)

    exposure_score = max((3.0 if surface.exposure == "public" else 1.0 for surface in surfaces), default=1.0)
    privilege_score = max(
        (
            3.0
            if surface.category in {"admin", "auth"}
            else 2.0
            if surface.category in {"webhook", "upload"}
            else 1.0
            for surface in surfaces
        ),
        default=1.0,
    )
    if _contains_any(finding.title, ("privilege", "admin", "auth", "token", "identity")):
        privilege_score = max(privilege_score, 2.5)
    reachability_score = max((2.0 if surface.exposure == "public" else 1.0 for surface in surfaces), default=1.0)
    trust_boundary_score = max(
        (
            (2.0 if surface.data_store_interaction else 0.0) + (2.0 if surface.outbound_integration else 0.0)
            for surface in surfaces
        ),
        default=1.0,
    )
    chain_depth_score = max((min(len(path.steps), 8) / 2.0 for path in paths), default=1.0)
    numeric_confidence = max(
        (
            value
            for value in (_extract_numeric_confidence(item) for item in finding.evidence)
            if value is not None
        ),
        default=None,
    )
    confidence_score = _confidence_rank(finding.confidence) + (numeric_confidence if numeric_confidence is not None else 0.0)

    weighted = {
        "exposure": 2.0 * exposure_score,
        "privilege": 2.0 * privilege_score,
        "reachability": 1.5 * reachability_score,
        "trust_boundary": 2.0 * trust_boundary_score,
        "chain_depth": 1.2 * chain_depth_score,
        "confidence": 1.5 * confidence_score,
    }
    evidence_blob = f"{finding.title} {' '.join(finding.evidence)}"
    if _is_low_quality_source(evidence_blob) and all(_is_low_quality_source(surface.file) for surface in surfaces):
        weighted["source_quality_penalty"] = -10.0
    return round(sum(weighted.values()), 2), weighted


def _overview_line(scan: ScanResult) -> str:
    repo_type = "web/service-facing" if scan.routes else "non-web"
    return (
        f"- AttackMap reviewed a {repo_type} codebase with {len(scan.routes)} inferred entry point"
        f"{'s' if len(scan.routes) != 1 else ''} across {scan.files_scanned} scanned files."
    )


def _strengths(scan: ScanResult, attack_surfaces: list[AttackSurface]) -> list[str]:
    items: list[tuple[float, str]] = []
    auth_hints = sorted({hint.hint for hint in scan.auth_hints})
    secure_surfaces = [surface for surface in attack_surfaces if surface.auth_signals]
    internal_surfaces = [surface for surface in attack_surfaces if surface.exposure == "internal"]
    low_risk_surfaces = [surface for surface in attack_surfaces if surface.risk == "low"]

    if auth_hints:
        items.append(
            (
                9.0 + min(len(auth_hints), 5),
                f"- Authentication/identity indicators are present in code signals ({', '.join(auth_hints[:6])}).",
            )
        )
    if secure_surfaces:
        items.append(
            (
                8.0 + min(len(secure_surfaces), 5),
                f"- {len(secure_surfaces)} route(s) include nearby auth indicators, which may support defensive enforcement if validated at runtime.",
            )
        )
    if internal_surfaces:
        items.append((7.0, f"- {len(internal_surfaces)} route(s) were inferred as internal-only, reducing direct internet exposure if correctly segmented."))
    if low_risk_surfaces:
        items.append((6.0, f"- {len(low_risk_surfaces)} route(s) were classified as low-risk operational surfaces."))
    if scan.secret_hints:
        items.append((6.5, "- Secret usage appears environment-driven rather than hardcoded literals."))
    else:
        items.append((5.0, "- No obvious secret-like environment references were detected in executable paths."))
    if not items:
        return ["- No strong defensive indicators were detected heuristically; manual review is still recommended."]
    return [line for _, line in sorted(items, key=lambda item: item[0], reverse=True)[:4]]


def _weaknesses(attack_surfaces: list[AttackSurface], findings: list[Finding], attack_paths: list[AttackPath]) -> list[str]:
    items: list[str] = []
    finding_scores = sorted(
        (
            (_finding_priority(finding, attack_surfaces, attack_paths), finding)
            for finding in findings
        ),
        key=lambda item: (item[0][0], -_severity_rank(item[1].severity)),
        reverse=True,
    )
    for (score, factors), finding in finding_scores[:3]:
        related_surfaces = _related_surfaces_for_finding(finding, attack_surfaces)
        items.append(f"- [{finding.severity.upper()} | score {score:.1f}] {finding.title}")
        items.append(f"- Reason: {_top_score_reasons(factors, top_n=3)}")
        items.append(f"- Provenance: {_provenance_breakdown(related_surfaces)}")

    hotspot_scores = sorted(
        (
            (_surface_priority(surface), surface)
            for surface in attack_surfaces
        ),
        key=lambda item: (item[0][0], -_surface_risk_rank(item[1].risk), item[1].route),
        reverse=True,
    )
    for (score, factors), surface in hotspot_scores[:2]:
        items.append(
            f"- Hotspot [score {score:.1f}]: {surface.method} {surface.route} ({surface.file}) -> {surface.category} / {surface.risk}"
        )
        items.append(f"- Reason: {_top_score_reasons(factors, top_n=2)}")
        items.append(f"- Provenance: {_provenance_breakdown([surface])}")
    return items[:12]


def _evidence_chains(attack_paths: list[AttackPath]) -> list[str]:
    if not attack_paths:
        return ["- No explicit attack path was generated from current signals."]
    lines: list[str] = []
    scored_paths = sorted(
        ((_path_priority(path), path) for path in attack_paths),
        key=lambda item: item[0][0],
        reverse=True,
    )
    for (score, factors), path in scored_paths[:3]:
        lines.append(f"- [score {score:.1f}] {path.name}: {path.impact}")
        lines.append(f"- Reason: {_top_score_reasons(factors, top_n=3)}")
        if path.steps:
            lines.append(f"- Key step: {path.steps[0]}")
    return lines


def _recommendations(findings: list[Finding], attack_paths: list[AttackPath], attack_surfaces: list[AttackSurface]) -> list[str]:
    recommendations: list[str] = []
    low_quality_recommendations: list[str] = []
    scored_findings = sorted(
        (
            (_finding_priority(finding, attack_surfaces, attack_paths), finding)
            for finding in findings
        ),
        key=lambda item: item[0][0],
        reverse=True,
    )
    for (_score, _factors), finding in scored_findings:
        if not finding.mitigation:
            continue
        related_surfaces = _related_surfaces_for_finding(finding, attack_surfaces)
        basis = _recommendation_basis_label(related_surfaces)
        line = f"- [{basis}] {finding.mitigation}"
        if basis == "low-quality-evidence":
            if line not in low_quality_recommendations:
                low_quality_recommendations.append(line)
            continue
        if line not in recommendations:
            recommendations.append(line)
        if len(recommendations) >= 4:
            break

    for line in low_quality_recommendations:
        if len(recommendations) >= 4:
            break
        if line not in recommendations:
            recommendations.append(line)

    high_scored_path = max((_path_priority(path)[0] for path in attack_paths), default=0.0)
    if attack_paths and len(recommendations) < 5 and high_scored_path >= 22.0:
        recommendations.append(
            "- Validate every trust boundary hop in attack paths with explicit authn/authz and least-privilege service credentials."
        )

    if len(recommendations) < 5:
        recommendations.append(
            "- Add targeted tests for highest-risk routes and service edges to prevent regressions in boundary enforcement."
        )
    return recommendations[:5]


def render_defensive_review(
    scan: ScanResult,
    attack_surfaces: list[AttackSurface],
    findings: list[Finding],
    attack_paths: list[AttackPath],
) -> str:
    observed_runtime_public, protocol_derived, internal_only, low_quality = _entrypoint_counts(attack_surfaces)
    lines = [
        "# Defensive Review",
        "",
        "## System Overview",
        _overview_line(scan),
        f"- Raw inferred entry points: {len(scan.routes)}",
        f"- Observed runtime/public surfaces: {observed_runtime_public}",
        f"- Protocol/lexicon-derived surfaces (inferred): {protocol_derived}",
        f"- Internal-only surfaces: {internal_only}",
        f"- Test/example/mocked surfaces (down-weighted): {low_quality}",
        f"- Languages: {', '.join(scan.languages) if scan.languages else 'none'}",
        f"- Datastores: {', '.join(sorted({db.kind for db in scan.databases})) if scan.databases else 'none'}",
        f"- External dependencies observed: {len(scan.external_calls)}",
        "",
        "## Strengths",
        *_strengths(scan, attack_surfaces),
        "",
        "## Weaknesses / Risk Hotspots",
        *_weaknesses(attack_surfaces, findings, attack_paths),
        "",
        "## Key Evidence Chains",
        *_evidence_chains(attack_paths),
        "",
        "## Recommendations",
        *_recommendations(findings, attack_paths, attack_surfaces),
        "",
        "## Analyst Notes",
        "- This defensive review is heuristic and intended as an engineering triage starting point.",
        "- Validate top risks with repository-specific architecture context and runtime controls.",
    ]
    return "\n".join(lines)
