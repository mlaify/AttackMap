from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass

from .models import (
    Asset,
    AttackPath,
    AttackSurface,
    Control,
    ControlKind,
    Insight,
    InsightKind,
    ScanResult,
)

LOW_QUALITY_SEGMENTS = ("/tests/", "/__tests__/", "/fixtures/", "/mocks/", "/examples/", "/test_", "/_test.")


def _is_low_quality(path: str) -> bool:
    normalized = ("/" + path.replace("\\", "/").lower() + "/")
    return any(segment in normalized for segment in LOW_QUALITY_SEGMENTS)


@dataclass(frozen=True)
class _DetectorContext:
    scan: ScanResult
    attack_surfaces: list[AttackSurface]
    findings_titles: list[str]
    attack_paths: list[AttackPath]
    assets: list[Asset]
    controls: list[Control]
    present_controls_by_kind: dict[ControlKind, list[Control]]
    absent_controls_by_kind: dict[ControlKind, list[Control]]


def _module_of(file_path: str) -> str:
    parts = file_path.replace("\\", "/").split("/")
    if len(parts) >= 2:
        return "/".join(parts[:-1])
    return parts[0] if parts else file_path


def _surface_loc(surface: AttackSurface) -> str:
    """`file:line` for a surface if line known, else `file`."""
    return f"{surface.file}:{surface.line}" if surface.line is not None else surface.file


def _hint_loc(file_path: str, line: int | None) -> str:
    return f"{file_path}:{line}" if line is not None else file_path


def _build_context(
    scan: ScanResult,
    attack_surfaces: list[AttackSurface],
    findings_titles: list[str],
    attack_paths: list[AttackPath],
    assets: list[Asset],
    controls: list[Control],
) -> _DetectorContext:
    present: dict[ControlKind, list[Control]] = defaultdict(list)
    absent: dict[ControlKind, list[Control]] = defaultdict(list)
    for control in controls:
        if control.strength == "absent":
            absent[control.kind].append(control)
        else:
            present[control.kind].append(control)
    return _DetectorContext(
        scan=scan,
        attack_surfaces=attack_surfaces,
        findings_titles=findings_titles,
        attack_paths=attack_paths,
        assets=assets,
        controls=controls,
        present_controls_by_kind=dict(present),
        absent_controls_by_kind=dict(absent),
    )


def _detect_shared_secret_blast_radius(ctx: _DetectorContext) -> list[Insight]:
    """Same secret name referenced across many files/modules — single compromise = wide blast."""
    locations_by_secret: dict[str, list[tuple[str, int | None]]] = defaultdict(list)
    files_by_secret: dict[str, set[str]] = defaultdict(set)
    for hint in ctx.scan.secret_hints:
        if _is_low_quality(hint.file):
            continue
        locations_by_secret[hint.name].append((hint.file, hint.line))
        files_by_secret[hint.name].add(hint.file)

    insights: list[Insight] = []
    for secret_name, locations in locations_by_secret.items():
        files = files_by_secret[secret_name]
        modules = {_module_of(file_path) for file_path in files}
        if len(modules) < 3:
            continue
        sensitive_match = any(
            keyword in secret_name.lower()
            for keyword in ("jwt", "session", "auth", "signing", "private", "master", "encryption", "stripe", "webhook")
        )
        severity = "high" if sensitive_match else "medium"
        confidence = "high" if len(modules) >= 4 else "medium"
        related_assets = [asset.id for asset in ctx.assets if any(loc in files for loc in asset.locations)]
        evidence_locations = sorted({_hint_loc(file_path, line) for file_path, line in locations})[:8]
        insights.append(
            Insight(
                id=f"insight:shared-secret:{secret_name.lower()}",
                kind="shared_secret_blast_radius",
                title=f"Shared secret `{secret_name}` referenced in {len(modules)} modules",
                narrative=(
                    f"`{secret_name}` is referenced from {len(modules)} distinct modules "
                    f"({len(files)} files). A single compromise of this credential affects every "
                    "module that consumes it; rotation requires a coordinated multi-service deploy. "
                    "If this is a signing key for inter-service trust, the blast radius extends to all "
                    "trust relationships derived from it."
                ),
                severity=severity,  # type: ignore[arg-type]
                confidence=confidence,  # type: ignore[arg-type]
                evidence=[f"{secret_name} ({location})" for location in evidence_locations],
                related_assets=related_assets,
                suggested_action=(
                    "Scope this secret per service (separate signing keys per trust boundary), or "
                    "centralize verification through a single owning service that the others call."
                ),
            )
        )
    return insights


def _detect_sensitive_asset_reachability(ctx: _DetectorContext) -> list[Insight]:
    """Public surface that touches a critical asset's location with no auth signals on the path."""
    insights: list[Insight] = []
    sensitive_kinds = {"credentials", "session", "user_pii", "payment"}
    sensitive_assets = [a for a in ctx.assets if a.criticality in {"critical", "high"} or a.kind in sensitive_kinds]
    if not sensitive_assets:
        return insights

    for asset in sensitive_assets:
        asset_modules = {_module_of(loc) for loc in asset.locations if loc}
        if not asset_modules:
            continue
        risky_surfaces: list[AttackSurface] = []
        for surface in ctx.attack_surfaces:
            if surface.exposure != "public":
                continue
            if _module_of(surface.file) not in asset_modules and surface.file not in asset.locations:
                continue
            if surface.auth_signals:
                continue
            risky_surfaces.append(surface)

        if not risky_surfaces:
            continue

        evidence = [
            f"{s.method} {s.route} ({_surface_loc(s)}) — exposure=public, auth_signals=none"
            for s in risky_surfaces[:5]
        ]
        insights.append(
            Insight(
                id=f"insight:asset-reachable:{asset.id}",
                kind="sensitive_asset_reachability",
                title=f"Public route reaches {asset.name} without observed auth",
                narrative=(
                    f"{asset.name} (criticality={asset.criticality}) lives in modules "
                    f"that are reachable from {len(risky_surfaces)} public route(s) with no "
                    "observed authentication signals on the surface. This means an unauthenticated "
                    "attacker can directly invoke handlers in the same module as a high-value asset "
                    "without traversing an explicit auth boundary."
                ),
                severity="critical" if asset.criticality == "critical" else "high",  # type: ignore[arg-type]
                confidence="medium",
                evidence=evidence,
                related_assets=[asset.id],
                related_routes=[s.route for s in risky_surfaces[:5]],
                suggested_action=(
                    "Add an explicit authentication guard at the route boundary or relocate the "
                    "handler out of the asset's module so the trust boundary is visible in code."
                ),
            )
        )
    return insights


def _detect_defense_gap_in_chain(ctx: _DetectorContext) -> list[Insight]:
    """An attack path traverses to a sink without observable auth/validation/rate-limit signals."""
    insights: list[Insight] = []
    if not ctx.attack_paths:
        return insights

    has_auth = bool(ctx.present_controls_by_kind.get("authentication"))
    has_validation = bool(ctx.present_controls_by_kind.get("input_validation"))
    has_rate_limit = bool(ctx.present_controls_by_kind.get("rate_limiting"))

    for idx, path in enumerate(ctx.attack_paths[:8]):
        joined = " ".join(path.steps).lower()
        terminates_at_data = any(token in joined for token in ("database", "datastore", "data_store", "db:", "kind="))
        if not terminates_at_data:
            continue
        missing: list[str] = []
        if not has_auth:
            missing.append("authentication")
        if not has_validation:
            missing.append("input_validation")
        if not has_rate_limit:
            missing.append("rate_limiting")
        if not missing:
            continue
        severity = "high" if "authentication" in missing else "medium"
        insights.append(
            Insight(
                id=f"insight:defense-gap:{idx + 1}",
                kind="defense_gap_in_chain",
                title=f"Chain `{path.name}` reaches a data store with no {', '.join(missing)} signals along the way",
                narrative=(
                    f"The inferred path `{path.name}` ({path.impact}) terminates at a data store "
                    "but the codebase has no observable signals for "
                    f"{', '.join(missing)} along this path. That means a request landing on the "
                    "entry surface can be carried through to the sink without any of those defenses "
                    "being applied — at least, none that the heuristic scanner can see."
                ),
                severity=severity,  # type: ignore[arg-type]
                confidence="medium",
                evidence=[f"path step: {step}" for step in path.steps[:6]],
                suggested_action=(
                    f"Add explicit middleware for {', '.join(missing)} on the entry route, or "
                    "document where these controls live so they show up to static analysis."
                ),
            )
        )
    return insights


def _detect_control_strength_mismatch(ctx: _DetectorContext) -> list[Insight]:
    """Critical asset present but only weak/absent controls observed for a relevant kind."""
    insights: list[Insight] = []
    sensitive_assets = [a for a in ctx.assets if a.criticality in {"critical", "high"}]
    if not sensitive_assets:
        return insights

    expected_kinds_by_asset: dict[str, list[ControlKind]] = {
        "credentials": ["authentication", "encryption_at_rest", "audit_logging"],
        "session": ["authentication", "rate_limiting", "encryption_in_transit"],
        "user_pii": ["authentication", "authorization", "audit_logging"],
        "payment": ["authentication", "authorization", "audit_logging", "encryption_at_rest"],
        "internal_secret": ["secret_management", "audit_logging"],
    }

    for asset in sensitive_assets:
        expected = expected_kinds_by_asset.get(asset.kind)
        if not expected:
            continue
        gaps: list[str] = []
        for kind in expected:
            present = ctx.present_controls_by_kind.get(kind, [])
            absent = ctx.absent_controls_by_kind.get(kind, [])
            if not present:
                gaps.append(f"{kind} (absent)")
                continue
            if all(c.strength == "weak" for c in present):
                gaps.append(f"{kind} (weak only)")
        if not gaps:
            continue
        insights.append(
            Insight(
                id=f"insight:strength-mismatch:{asset.id}",
                kind="control_strength_mismatch",
                title=f"{asset.name} has gaps in expected controls: {', '.join(gaps)}",
                narrative=(
                    f"{asset.name} is criticality={asset.criticality}, which would normally warrant "
                    f"strong controls of kind: {', '.join(expected)}. The scan observed gaps in: "
                    f"{', '.join(gaps)}. These may exist but are not detectable from code signals — "
                    "either way, the absence in static evidence is itself worth confirming."
                ),
                severity="high" if asset.criticality == "critical" else "medium",  # type: ignore[arg-type]
                confidence="medium",
                evidence=[f"asset:{asset.id} → expected:{kind}" for kind in expected],
                related_assets=[asset.id],
                suggested_action=(
                    "Either add the missing controls or annotate the code path where they live so "
                    "subsequent scans can pick them up."
                ),
            )
        )
    return insights


def _detect_asymmetric_protection(ctx: _DetectorContext) -> list[Insight]:
    """Same route path with different methods having different auth signals."""
    insights: list[Insight] = []
    by_route: dict[str, list[AttackSurface]] = defaultdict(list)
    for surface in ctx.attack_surfaces:
        by_route[surface.route].append(surface)

    for route, surfaces in by_route.items():
        if len(surfaces) < 2:
            continue
        protected = [s for s in surfaces if s.auth_signals]
        unprotected = [s for s in surfaces if not s.auth_signals]
        if not protected or not unprotected:
            continue
        insights.append(
            Insight(
                id=f"insight:asymmetric:{route}",
                kind="asymmetric_protection",
                title=f"Route `{route}` is protected on some methods but not others",
                narrative=(
                    f"`{route}` has {len(protected)} method(s) with auth signals "
                    f"({', '.join(sorted({s.method for s in protected}))}) and "
                    f"{len(unprotected)} method(s) without "
                    f"({', '.join(sorted({s.method for s in unprotected}))}). Asymmetric protection "
                    "is a common source of authorization bypass — an attacker can often achieve the "
                    "same effect through the unprotected verb (e.g., reading via GET what is write-protected on POST)."
                ),
                severity="medium",
                confidence="medium",
                evidence=[
                    f"protected: {s.method} {s.route} ({_surface_loc(s)})" for s in protected[:3]
                ] + [
                    f"unprotected: {s.method} {s.route} ({_surface_loc(s)})" for s in unprotected[:3]
                ],
                related_routes=[route],
                suggested_action="Confirm the unprotected verbs intentionally avoid auth or apply the same guard.",
            )
        )
    return insights


def _detect_audit_gap(ctx: _DetectorContext) -> list[Insight]:
    """Sensitive asset detected but no audit_logging control observed in any module touching it."""
    insights: list[Insight] = []
    if ctx.present_controls_by_kind.get("audit_logging"):
        return insights
    sensitive = [a for a in ctx.assets if a.criticality in {"critical", "high"} or a.kind in {"payment", "credentials", "user_pii"}]
    if not sensitive:
        return insights
    insights.append(
        Insight(
            id="insight:audit-gap:global",
            kind="audit_gap",
            title="Sensitive assets present, no audit-logging signals detected",
            narrative=(
                f"{len(sensitive)} sensitive asset(s) were identified — "
                f"{', '.join(sorted({a.name for a in sensitive}))[:160]} — "
                "but no audit-logging signals were detected anywhere in the scan. "
                "Without audit trails for sensitive-asset access, post-incident forensics "
                "and detection-engineering are constrained."
            ),
            severity="medium",
            confidence="medium",
            evidence=[f"asset:{a.id} ({a.criticality})" for a in sensitive[:6]],
            related_assets=[a.id for a in sensitive],
            suggested_action=(
                "Add structured audit logging at handlers that touch sensitive assets; "
                "include actor, action, asset id, and outcome."
            ),
        )
    )
    return insights


def _detect_single_point_of_failure(ctx: _DetectorContext) -> list[Insight]:
    """A single auth-related secret underpins the only authentication observed."""
    auth_controls = ctx.present_controls_by_kind.get("authentication", [])
    if not auth_controls:
        return []
    auth_secret_candidates = [
        h.name for h in ctx.scan.secret_hints
        if not _is_low_quality(h.file)
        and any(t in h.name.lower() for t in ("jwt", "session", "auth_secret", "signing", "cookie"))
    ]
    if len(set(auth_secret_candidates)) != 1:
        return []
    only_secret = auth_secret_candidates[0]
    return [
        Insight(
            id=f"insight:spof:{only_secret.lower()}",
            kind="single_point_of_failure",
            title=f"Authentication appears to depend on a single secret: `{only_secret}`",
            narrative=(
                f"The scan found a single auth-related secret name (`{only_secret}`) and one or more "
                "authentication controls. If this secret is the sole input to verifying user identity, "
                "its compromise revokes the security of every authenticated surface in the system."
            ),
            severity="high",
            confidence="medium",
            evidence=[f"secret:{only_secret}"],
            suggested_action=(
                "Introduce key rotation, layered verification (e.g., MFA), or per-tenant signing "
                "so a single secret leak does not compromise the whole authentication boundary."
            ),
        )
    ]


_ADMIN_ROUTE_TOKENS: tuple[str, ...] = (
    "/admin",
    "/manage",
    "/root",
    "/superuser",
    "/sudo",
    "/su/",
    "/role",
    "/roles",
    "/permission",
    "/permissions",
    "/grant",
    "/revoke",
    "/impersonate",
    "/owner",
    "/owners",
    "/membership",
)


_STATE_CHANGING_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _detect_admin_action_without_auth(ctx: _DetectorContext) -> list[Insight]:
    """Public, state-changing admin/role/permission routes with no auth signals on the surface."""
    insights: list[Insight] = []
    risky_surfaces: list[AttackSurface] = []
    for surface in ctx.attack_surfaces:
        if surface.exposure != "public":
            continue
        if surface.method.upper() not in _STATE_CHANGING_METHODS and surface.category != "admin":
            continue
        if surface.auth_signals:
            continue
        path_lower = surface.route.lower()
        is_admin_route = surface.category == "admin" or any(token in path_lower for token in _ADMIN_ROUTE_TOKENS)
        if not is_admin_route:
            continue
        risky_surfaces.append(surface)

    if not risky_surfaces:
        return insights

    evidence = [
        f"{s.method} {s.route} ({_surface_loc(s)}) — exposure=public, auth_signals=none"
        for s in risky_surfaces[:6]
    ]
    insights.append(
        Insight(
            id="insight:admin-without-auth",
            kind="admin_action_without_auth",
            title=f"{len(risky_surfaces)} admin/role-mutation route(s) reachable without observed auth",
            narrative=(
                f"{len(risky_surfaces)} public route(s) match administrative or "
                "role/permission-mutation patterns and carry no authentication signals on "
                "the surface. Privilege-mutation flows are an outsized target — an "
                "attacker who reaches them can grant themselves access to the rest of "
                "the system, so the absence of an explicit auth boundary here is a "
                "high-priority confirmation item."
            ),
            severity="critical",
            confidence="medium",
            evidence=evidence,
            related_routes=[s.route for s in risky_surfaces[:6]],
            suggested_action=(
                "Add an explicit authentication and authorization guard at the route "
                "boundary for every admin/role/permission endpoint, and verify the guard "
                "is exercised in tests."
            ),
        )
    )
    return insights


_GLOBAL_CONTROL_KINDS_TO_AUDIT: tuple[ControlKind, ...] = (
    "authentication",
    "csrf_protection",
    "rate_limiting",
)


_BYPASS_PRONE_ROUTE_TOKENS: tuple[str, ...] = (
    "/webhook",
    "/callback",
    "/health",
    "/healthz",
    "/ping",
    "/metrics",
    "/internal",
    "/_internal",
    "/debug",
)


def _detect_control_bypass(ctx: _DetectorContext) -> list[Insight]:
    """A control is broadly observed (multi-module) but specific routes' files have no evidence of it."""
    insights: list[Insight] = []
    for kind in _GLOBAL_CONTROL_KINDS_TO_AUDIT:
        controls = [c for c in ctx.present_controls_by_kind.get(kind, []) if c.placements]
        if not controls:
            continue
        placement_files: set[str] = set()
        for control in controls:
            placement_files.update(control.placements)
        if len(placement_files) < 2:
            continue
        bypass_surfaces: list[AttackSurface] = []
        for surface in ctx.attack_surfaces:
            if surface.exposure != "public":
                continue
            path_lower = surface.route.lower()
            if not any(token in path_lower for token in _BYPASS_PRONE_ROUTE_TOKENS):
                continue
            if surface.file in placement_files:
                continue
            bypass_surfaces.append(surface)
        if not bypass_surfaces:
            continue
        evidence = [
            f"{s.method} {s.route} ({_surface_loc(s)}) — no `{kind}` evidence in this file"
            for s in bypass_surfaces[:5]
        ]
        insights.append(
            Insight(
                id=f"insight:control-bypass:{kind}",
                kind="control_bypass",
                title=f"`{kind}` is observed broadly but {len(bypass_surfaces)} route(s) appear to bypass it",
                narrative=(
                    f"`{kind}` controls are present in {len(placement_files)} files, suggesting it's "
                    "applied as a global middleware. However, the listed routes — webhooks, health/metrics "
                    "endpoints, or internal handlers — live in files where no evidence of that control "
                    "appears. These are common deliberate bypass points; confirm each is intentional, "
                    "and consider whether the bypass is the right call (webhook signatures vs. CSRF, "
                    "for instance, can both be required)."
                ),
                severity="medium",
                confidence="medium",
                evidence=evidence,
                related_controls=[c.id for c in controls],
                related_routes=[s.route for s in bypass_surfaces[:5]],
                suggested_action=(
                    "For each bypass route, document the rationale (signed webhook, internal-only, etc.) "
                    "and ensure the bypass surface enforces an alternative control (HMAC verification, "
                    "mTLS, network ACL)."
                ),
            )
        )
    return insights


_INTERNAL_FILE_TOKENS: tuple[str, ...] = ("/internal/", "/private/", "/admin_internal/", "_internal_", "/intranet/")


def _detect_trust_boundary_violation(ctx: _DetectorContext) -> list[Insight]:
    """A handler whose file path advertises 'internal' is exposed via a public surface."""
    violations: list[AttackSurface] = []
    for surface in ctx.attack_surfaces:
        if surface.exposure != "public":
            continue
        normalized = "/" + surface.file.replace("\\", "/").lower() + "/"
        if not any(token in normalized for token in _INTERNAL_FILE_TOKENS):
            continue
        violations.append(surface)

    if not violations:
        return []

    evidence = [
        f"{s.method} {s.route} ({_surface_loc(s)}) — file path marked internal but exposure=public"
        for s in violations[:5]
    ]
    return [
        Insight(
            id="insight:trust-boundary-violation",
            kind="trust_boundary_violation",
            title=f"{len(violations)} handler(s) tagged internal-only by file path are publicly exposed",
            narrative=(
                "The listed handlers live in modules whose file path indicates they were intended "
                "for internal-only use, yet they appear in the public attack surface. Trust-boundary "
                "violations like these often arise from a router accidentally including an internal "
                "module, or from a directory rename that left the original visibility implicit. "
                "Either remove the public route or rename the module to reflect the actual exposure."
            ),
            severity="high",
            confidence="medium",
            evidence=evidence,
            related_routes=[s.route for s in violations[:5]],
            suggested_action=(
                "For each violation, decide: relocate the handler out of the internal module, or "
                "remove the public route registration that exposes it."
            ),
        )
    ]


_BENIGN_ROUTE_TOKENS: tuple[str, ...] = (
    "/health",
    "/healthz",
    "/ping",
    "/status",
    "/metrics",
    "/version",
    "/_static/",
    "/assets/",
    "/favicon",
    "/robots.txt",
    "/.well-known/",
    "/public/",
)


def _detect_stale_or_contradictory_signal(ctx: _DetectorContext) -> list[Insight]:
    """Auth signals appear on routes that are obviously public/benign — false-positive guardrail."""
    contradictions: list[AttackSurface] = []
    for surface in ctx.attack_surfaces:
        if not surface.auth_signals:
            continue
        path_lower = surface.route.lower()
        if not any(token in path_lower for token in _BENIGN_ROUTE_TOKENS):
            continue
        contradictions.append(surface)

    if not contradictions:
        return []

    evidence = [
        f"{s.method} {s.route} ({_surface_loc(s)}) — auth_signals present but route looks benign/public: "
        + ", ".join(s.auth_signals[:3])
        for s in contradictions[:5]
    ]
    return [
        Insight(
            id="insight:stale-signal",
            kind="stale_or_contradictory_signal",
            title=f"{len(contradictions)} obviously-benign route(s) carry auth signals — likely scanner false positives",
            narrative=(
                "Health, metrics, static-asset, and well-known paths normally do not require "
                "authentication. The scanner attached auth signals to these routes anyway, which "
                "usually means the auth marker is at file scope (e.g., a global middleware import) "
                "rather than route-specific. Treat the auth annotation on these surfaces with "
                "skepticism when reading the rest of the report."
            ),
            severity="informational",
            confidence="medium",
            evidence=evidence,
            related_routes=[s.route for s in contradictions[:5]],
            suggested_action=(
                "If the auth markers really should not apply to these routes, add per-route metadata "
                "the scanner can read (e.g., a `@public` decorator or a routes manifest) so future "
                "scans don't double-count file-scope signals."
            ),
        )
    ]


_DETECTORS: tuple[Callable[[_DetectorContext], list[Insight]], ...] = (
    _detect_shared_secret_blast_radius,
    _detect_sensitive_asset_reachability,
    _detect_defense_gap_in_chain,
    _detect_control_strength_mismatch,
    _detect_asymmetric_protection,
    _detect_audit_gap,
    _detect_single_point_of_failure,
    _detect_admin_action_without_auth,
    _detect_control_bypass,
    _detect_trust_boundary_violation,
    _detect_stale_or_contradictory_signal,
)


def generate_insights(
    scan: ScanResult,
    attack_surfaces: list[AttackSurface],
    findings_titles: list[str],
    attack_paths: list[AttackPath],
    assets: list[Asset],
    controls: list[Control],
) -> list[Insight]:
    """Produce cross-cutting insights from scan + assets + controls + chains.

    These are designed to surface non-obvious, story-bearing observations that
    connect signals into a defensive narrative — not duplicate per-finding output.
    """
    ctx = _build_context(scan, attack_surfaces, findings_titles, attack_paths, assets, controls)
    seen_ids: set[str] = set()
    insights: list[Insight] = []
    for detector in _DETECTORS:
        for insight in detector(ctx):
            if insight.id in seen_ids:
                continue
            seen_ids.add(insight.id)
            insights.append(insight)

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    confidence_rank = {"high": 0, "medium": 1, "low": 2}
    insights.sort(
        key=lambda i: (
            severity_rank.get(i.severity, 9),
            confidence_rank.get(i.confidence, 9),
            i.kind,
            i.id,
        )
    )
    return insights


__all__ = ["generate_insights"]
