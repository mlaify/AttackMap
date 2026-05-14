"""Tests for threat-intel outputs: ATT&CK mapping, detection opportunities, and the
three insight detectors added in this layer (control_bypass, trust_boundary_violation,
stale_or_contradictory_signal)."""

from attackmap.attack_taxonomy import (
    annotate_findings,
    annotate_insights,
    techniques_for_finding,
    techniques_for_insight,
)
from attackmap.detection_opportunities import generate_detection_opportunities
from attackmap.models import (
    AttackSurface,
    AuthHint,
    DatabaseHint,
    Finding,
    FrameworkHint,
    Insight,
    Route,
    ScanResult,
    SecretHint,
)
from attackmap.security_overlay import build_security_overlay


def _scan_with(**overrides) -> ScanResult:
    base = {"root": ".", "languages": ["python"], "files_scanned": 5}
    base.update(overrides)
    return ScanResult(**base)


def _insight(kind: str, **kwargs) -> Insight:
    base = {
        "id": f"insight:test:{kind}",
        "kind": kind,
        "title": f"test {kind}",
        "narrative": "narrative",
        "severity": "medium",
        "confidence": "medium",
    }
    base.update(kwargs)
    return Insight(**base)


# ---------- ATT&CK mapping ----------


def test_techniques_for_insight_returns_expected_techniques_per_kind() -> None:
    expected = {
        "shared_secret_blast_radius": "T1552",
        "sensitive_asset_reachability": "T1190",
        "admin_action_without_auth": "T1078",
        "audit_gap": "T1562",
        "trust_boundary_violation": "T1199",
        "asymmetric_protection": "T1190",
        "control_strength_mismatch": "T1110",
        "single_point_of_failure": "T1552",
        "control_bypass": "T1562",
        "defense_gap_in_chain": "T1190",
    }
    for kind, expected_tid in expected.items():
        techniques = techniques_for_insight(_insight(kind))
        assert techniques, f"expected ATT&CK techniques for kind={kind}"
        assert any(t.technique_id == expected_tid for t in techniques), (
            f"expected {expected_tid} in techniques for kind={kind}"
        )


def test_stale_signal_kind_emits_no_techniques() -> None:
    # Stale signals are a hygiene flag — not an attacker behavior.
    assert techniques_for_insight(_insight("stale_or_contradictory_signal")) == []


def test_techniques_for_finding_matches_keyword_in_title() -> None:
    finding = Finding(
        title="Public webhook endpoint may trust attacker-controlled events",
        severity="high",
        evidence=["POST /webhook/stripe in app.py"],
        mitigation="Verify HMAC.",
        confidence="high",
    )
    techniques = techniques_for_finding(finding)
    ids = {t.technique_id for t in techniques}
    assert "T1190" in ids  # webhook → public-facing app
    assert "T1199" in ids  # webhook → trusted relationship


def test_annotate_insights_preserves_existing_attack_techniques() -> None:
    insight = _insight("audit_gap")
    annotated_once = annotate_insights([insight])
    assert annotated_once[0].attack_techniques  # populated
    annotated_twice = annotate_insights(annotated_once)
    assert annotated_twice[0].attack_techniques == annotated_once[0].attack_techniques


def test_annotate_findings_attaches_techniques_in_place() -> None:
    findings = [
        Finding(
            title="Admin action exposed without auth",
            severity="high",
            evidence=[],
            mitigation="add auth",
            confidence="medium",
        )
    ]
    annotated = annotate_findings(findings)
    assert annotated[0].attack_techniques
    assert any(t.technique_id == "T1078" for t in annotated[0].attack_techniques)


# ---------- Detection opportunities ----------


def test_detection_opportunities_emits_one_per_insight_kind() -> None:
    insights = annotate_insights([
        _insight("admin_action_without_auth", related_routes=["/admin/users"]),
        _insight("audit_gap"),
        _insight("shared_secret_blast_radius"),
    ])

    opportunities = generate_detection_opportunities(insights, [])
    kinds_covered = {opp.id for opp in opportunities}
    assert any("admin_action_without_auth" in oid for oid in kinds_covered)
    assert any("audit_gap" in oid for oid in kinds_covered)
    assert any("shared_secret_blast_radius" in oid for oid in kinds_covered)


def test_detection_opportunities_carry_attack_techniques() -> None:
    insights = annotate_insights([
        _insight("admin_action_without_auth", related_routes=["/admin/role"])
    ])
    opportunities = generate_detection_opportunities(insights, [])
    assert opportunities[0].attack_techniques
    assert any(t.technique_id == "T1078" for t in opportunities[0].attack_techniques)


def test_detection_opportunities_skip_insight_kinds_without_generators() -> None:
    # stale_or_contradictory_signal has a generator; the function shouldn't crash on duplicates either.
    insights = annotate_insights([
        _insight("audit_gap"),
        _insight("audit_gap", id="insight:test:audit_gap_2"),
    ])
    opportunities = generate_detection_opportunities(insights, [])
    audit_opps = [o for o in opportunities if "audit_gap" in o.id]
    assert len(audit_opps) == 1  # dedup by kind


# ---------- Three new insight detectors ----------


def test_control_bypass_insight_fires_on_webhook_route_when_csrf_widely_observed() -> None:
    scan = _scan_with(
        routes=[
            Route(path="/api/users", method="POST", file="app/api/users.py"),
            Route(path="/api/orders", method="POST", file="app/api/orders.py"),
            Route(path="/webhook/stripe", method="POST", file="app/webhooks/stripe.py"),
        ],
        framework_hints=[
            FrameworkHint(hint="csurf", file="app/api/users.py"),
            FrameworkHint(hint="csurf", file="app/api/orders.py"),
            FrameworkHint(hint="csurf", file="app/middleware.py"),
        ],
    )
    surfaces = [
        AttackSurface(
            route="/api/users", method="POST", file="app/api/users.py",
            category="public_api", exposure="public", risk="medium",
        ),
        AttackSurface(
            route="/api/orders", method="POST", file="app/api/orders.py",
            category="public_api", exposure="public", risk="medium",
        ),
        AttackSurface(
            route="/webhook/stripe", method="POST", file="app/webhooks/stripe.py",
            category="webhook", exposure="public", risk="high",
        ),
    ]
    overlay = build_security_overlay(scan, surfaces, [], [])

    bypass_insights = [i for i in overlay.insights if i.kind == "control_bypass"]
    assert bypass_insights, "expected control_bypass insight for the webhook route"
    assert any("csrf_protection" in i.id for i in bypass_insights)


def test_trust_boundary_violation_fires_on_internal_path_with_public_exposure() -> None:
    scan = _scan_with(
        routes=[Route(path="/api/data", method="GET", file="services/internal/handler.py")],
    )
    surfaces = [
        AttackSurface(
            route="/api/data",
            method="GET",
            file="services/internal/handler.py",
            category="public_api",
            exposure="public",
            risk="medium",
        )
    ]
    overlay = build_security_overlay(scan, surfaces, [], [])

    assert any(i.kind == "trust_boundary_violation" for i in overlay.insights)


def test_stale_or_contradictory_signal_fires_on_health_with_auth() -> None:
    scan = _scan_with(
        routes=[Route(path="/health", method="GET", file="app/health.py")],
        auth_hints=[AuthHint(hint="requireAuth", file="app/health.py")],
    )
    surfaces = [
        AttackSurface(
            route="/health",
            method="GET",
            file="app/health.py",
            category="health",
            exposure="public",
            risk="low",
            auth_signals=["requireAuth"],
        )
    ]
    overlay = build_security_overlay(scan, surfaces, [], [])

    stale = [i for i in overlay.insights if i.kind == "stale_or_contradictory_signal"]
    assert stale, "expected stale_or_contradictory_signal insight on /health with auth"
    assert stale[0].severity == "informational"


def test_overlay_findings_get_attack_techniques_attached() -> None:
    scan = _scan_with(
        routes=[Route(path="/webhook/stripe", method="POST", file="app/webhooks.py")],
        secret_hints=[SecretHint(name="STRIPE_WEBHOOK_SECRET", file="app/webhooks.py")],
    )
    surfaces = [
        AttackSurface(
            route="/webhook/stripe", method="POST", file="app/webhooks.py",
            category="webhook", exposure="public", risk="high",
        )
    ]
    findings = [
        Finding(
            title="Public webhook endpoint may trust attacker-controlled events",
            severity="high",
            evidence=["POST /webhook/stripe in app/webhooks.py"],
            mitigation="Verify webhook signature.",
            confidence="high",
        )
    ]

    overlay = build_security_overlay(scan, surfaces, findings, [])

    assert overlay.findings[0].attack_techniques
    assert any(t.technique_id == "T1190" for t in overlay.findings[0].attack_techniques)


def test_overlay_exposes_detection_opportunities() -> None:
    scan = _scan_with(
        routes=[Route(path="/admin/users/<id>/role", method="POST", file="app/admin.py")],
        databases=[DatabaseHint(kind="postgres", file="app/db.py")],
    )
    surfaces = [
        AttackSurface(
            route="/admin/users/<id>/role",
            method="POST",
            file="app/admin.py",
            category="admin",
            exposure="public",
            risk="high",
        )
    ]
    overlay = build_security_overlay(scan, surfaces, [], [])

    assert overlay.detection_opportunities, "expected at least one detection opportunity"
    assert any("admin" in opp.id for opp in overlay.detection_opportunities)
