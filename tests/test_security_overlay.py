from attackmap.asset_model import detect_assets
from attackmap.control_model import detect_controls
from attackmap.insights import generate_insights
from attackmap.models import (
    AttackPath,
    AttackSurface,
    AuthHint,
    DatabaseHint,
    Finding,
    FrameworkHint,
    Route,
    ScanResult,
    SecretHint,
)
from attackmap.security_overlay import build_security_overlay


def _scan_with(**overrides) -> ScanResult:
    base = {
        "root": ".",
        "languages": ["python"],
        "files_scanned": 10,
    }
    base.update(overrides)
    return ScanResult(**base)


# Asset detector


def test_detect_assets_identifies_session_asset_from_jwt_secret() -> None:
    scan = _scan_with(
        secret_hints=[SecretHint(name="JWT_SECRET", file="services/auth/config.py")],
    )

    assets = detect_assets(scan)
    kinds = {a.kind for a in assets}

    assert "session" in kinds
    session_asset = next(a for a in assets if a.kind == "session")
    assert session_asset.criticality == "critical"
    assert "JWT_SECRET" in " ".join(session_asset.evidence)


def test_detect_assets_identifies_payment_asset_from_route() -> None:
    scan = _scan_with(
        routes=[Route(path="/checkout/charge", method="POST", file="app/billing/handlers.py")],
    )

    assets = detect_assets(scan)
    kinds = {a.kind for a in assets}

    assert "payment" in kinds


def test_detect_assets_falls_back_to_business_data_when_only_databases() -> None:
    scan = _scan_with(databases=[DatabaseHint(kind="postgres", file="services/data/db.py")])

    assets = detect_assets(scan)

    assert any(a.kind == "business_data" for a in assets)


def test_detect_assets_returns_empty_on_uninteresting_scan() -> None:
    scan = _scan_with()
    assert detect_assets(scan) == []


# Control detector


def test_detect_controls_finds_bcrypt_as_strong_hashing() -> None:
    scan = _scan_with(
        auth_hints=[AuthHint(hint="bcrypt.hash", file="services/auth/password.py")],
    )

    controls = detect_controls(scan, [], [])

    assert any(c.kind == "authentication" and c.strength == "strong" for c in controls)


def test_detect_controls_flags_absent_rate_limiting_on_public_route() -> None:
    scan = _scan_with(
        routes=[Route(path="/api/login", method="POST", file="app/auth.py")],
    )
    surfaces = [
        AttackSurface(
            route="/api/login",
            method="POST",
            file="app/auth.py",
            category="auth",
            exposure="public",
            risk="high",
        )
    ]
    assets = detect_assets(scan)

    controls = detect_controls(scan, surfaces, assets)

    absent_kinds = {c.kind for c in controls if c.strength == "absent"}
    assert "rate_limiting" in absent_kinds
    assert "authentication" in absent_kinds


def test_detect_controls_does_not_emit_absent_rate_limiting_when_present() -> None:
    scan = _scan_with(
        routes=[Route(path="/api/users", method="GET", file="app/users.py")],
        framework_hints=[FrameworkHint(hint="express-rate-limit", file="app/middleware.js")],
    )
    surfaces = [
        AttackSurface(
            route="/api/users",
            method="GET",
            file="app/users.py",
            category="public_api",
            exposure="public",
            risk="medium",
        )
    ]

    controls = detect_controls(scan, surfaces, [])

    rate_limit_controls = [c for c in controls if c.kind == "rate_limiting"]
    assert any(c.strength != "absent" for c in rate_limit_controls)
    assert all(c.strength != "absent" for c in rate_limit_controls)


# Insight engine


def test_insights_emit_shared_secret_blast_radius() -> None:
    scan = _scan_with(
        secret_hints=[
            SecretHint(name="JWT_SECRET", file="services/auth/config.py"),
            SecretHint(name="JWT_SECRET", file="services/api/config.py"),
            SecretHint(name="JWT_SECRET", file="services/billing/config.py"),
            SecretHint(name="JWT_SECRET", file="services/notification/config.py"),
        ],
    )
    overlay = build_security_overlay(scan, [], [], [])

    kinds = {i.kind for i in overlay.insights}
    assert "shared_secret_blast_radius" in kinds
    blast = next(i for i in overlay.insights if i.kind == "shared_secret_blast_radius")
    assert blast.severity in {"high", "critical"}
    assert "JWT_SECRET" in blast.title


def test_insights_emit_sensitive_asset_reachability_when_public_route_no_auth() -> None:
    scan = _scan_with(
        routes=[Route(path="/users/me", method="GET", file="app/users/handler.py")],
        secret_hints=[SecretHint(name="JWT_SECRET", file="app/users/handler.py")],
    )
    surfaces = [
        AttackSurface(
            route="/users/me",
            method="GET",
            file="app/users/handler.py",
            category="public_api",
            exposure="public",
            risk="medium",
            auth_signals=[],
        )
    ]
    overlay = build_security_overlay(scan, surfaces, [], [])

    assert any(i.kind == "sensitive_asset_reachability" for i in overlay.insights)


def test_insights_emit_asymmetric_protection_when_methods_differ() -> None:
    scan = _scan_with(
        routes=[
            Route(path="/api/items", method="GET", file="app/items.py"),
            Route(path="/api/items", method="POST", file="app/items.py"),
        ],
    )
    surfaces = [
        AttackSurface(
            route="/api/items",
            method="GET",
            file="app/items.py",
            category="public_api",
            exposure="public",
            risk="low",
            auth_signals=[],
        ),
        AttackSurface(
            route="/api/items",
            method="POST",
            file="app/items.py",
            category="public_api",
            exposure="public",
            risk="medium",
            auth_signals=["requireAuth"],
        ),
    ]
    overlay = build_security_overlay(scan, surfaces, [], [])

    asymmetric = [i for i in overlay.insights if i.kind == "asymmetric_protection"]
    assert asymmetric
    assert "GET" in asymmetric[0].narrative or "POST" in asymmetric[0].narrative


def test_insights_emit_admin_action_without_auth_for_public_admin_post() -> None:
    scan = _scan_with(
        routes=[Route(path="/admin/users/<id>/role", method="POST", file="app/admin.py")],
    )
    surfaces = [
        AttackSurface(
            route="/admin/users/<id>/role",
            method="POST",
            file="app/admin.py",
            category="admin",
            exposure="public",
            risk="high",
            auth_signals=[],
        )
    ]
    overlay = build_security_overlay(scan, surfaces, [], [])

    admin_insights = [i for i in overlay.insights if i.kind == "admin_action_without_auth"]
    assert admin_insights, "expected admin_action_without_auth insight"
    assert admin_insights[0].severity == "critical"


def test_insights_skip_admin_action_without_auth_when_auth_signals_present() -> None:
    scan = _scan_with(
        routes=[Route(path="/admin/users/<id>/role", method="POST", file="app/admin.py")],
    )
    surfaces = [
        AttackSurface(
            route="/admin/users/<id>/role",
            method="POST",
            file="app/admin.py",
            category="admin",
            exposure="public",
            risk="high",
            auth_signals=["requireAuth"],
        )
    ]
    overlay = build_security_overlay(scan, surfaces, [], [])

    assert not any(i.kind == "admin_action_without_auth" for i in overlay.insights)


def test_insights_emit_audit_gap_for_sensitive_asset_without_audit_logging() -> None:
    scan = _scan_with(
        routes=[Route(path="/payment/charge", method="POST", file="app/billing/charge.py")],
    )
    overlay = build_security_overlay(scan, [], [], [])

    assert any(i.kind == "audit_gap" for i in overlay.insights)


def test_insights_emit_defense_gap_in_chain_when_path_terminates_at_db_with_no_controls() -> None:
    scan = _scan_with(
        routes=[Route(path="/api/data", method="POST", file="app/handler.py")],
        databases=[DatabaseHint(kind="postgres", file="app/db.py")],
    )
    surfaces = [
        AttackSurface(
            route="/api/data",
            method="POST",
            file="app/handler.py",
            category="public_api",
            exposure="public",
            risk="medium",
        )
    ]
    paths = [
        AttackPath(
            name="public-to-db",
            steps=["entry: POST /api/data", "service: handler", "datastore: postgres"],
            impact="data tampering",
        )
    ]

    overlay = build_security_overlay(scan, surfaces, [], paths)
    assert any(i.kind == "defense_gap_in_chain" for i in overlay.insights)


def test_insights_are_severity_sorted() -> None:
    scan = _scan_with(
        secret_hints=[
            SecretHint(name="JWT_SECRET", file=f"services/svc{i}/config.py") for i in range(5)
        ],
        routes=[Route(path="/users", method="GET", file="services/svc0/users.py")],
    )
    surfaces = [
        AttackSurface(
            route="/users",
            method="GET",
            file="services/svc0/users.py",
            category="public_api",
            exposure="public",
            risk="medium",
            auth_signals=[],
        )
    ]
    overlay = build_security_overlay(scan, surfaces, [], [])
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    severities = [severity_rank[i.severity] for i in overlay.insights]
    assert severities == sorted(severities)


# End-to-end overlay


def test_overlay_returns_assets_controls_insights_consistently() -> None:
    scan = _scan_with(
        routes=[Route(path="/login", method="POST", file="app/auth.py")],
        auth_hints=[AuthHint(hint="bcrypt.hash", file="app/auth.py")],
        secret_hints=[SecretHint(name="JWT_SECRET", file="app/auth.py")],
    )
    surfaces = [
        AttackSurface(
            route="/login",
            method="POST",
            file="app/auth.py",
            category="auth",
            exposure="public",
            risk="high",
            auth_signals=["bcrypt.hash"],
        )
    ]
    findings = [
        Finding(
            title="Login route present",
            severity="medium",
            evidence=["POST /login"],
            mitigation="Confirm rate limiting and lockout policy.",
            confidence="medium",
        )
    ]

    overlay = build_security_overlay(scan, surfaces, findings, [])

    assert any(a.kind == "session" for a in overlay.assets)
    assert any(c.kind == "authentication" and c.strength == "strong" for c in overlay.controls)
    insight_kinds = {i.kind for i in overlay.insights}
    assert insight_kinds.issubset({
        "shared_secret_blast_radius",
        "sensitive_asset_reachability",
        "control_bypass",
        "defense_gap_in_chain",
        "asymmetric_protection",
        "trust_boundary_violation",
        "audit_gap",
        "control_strength_mismatch",
        "single_point_of_failure",
        "stale_or_contradictory_signal",
        "admin_action_without_auth",
    })
