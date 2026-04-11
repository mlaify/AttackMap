from attackmap.defensive_review import render_defensive_review
from attackmap.models import AttackPath, AttackSurface, AuthHint, Finding, Route, ScanResult


def test_render_defensive_review_contains_expected_sections() -> None:
    scan = ScanResult(
        root=".",
        languages=["typescript"],
        routes=[Route(path="/xrpc/com.atproto.server.createSession", method="ANY", file="packages/pds/src/api.ts")],
        auth_hints=[AuthHint(hint="atproto_namespace:com.atproto", file="packages/pds/src/api.ts")],
        files_scanned=4,
    )
    surfaces = [
        AttackSurface(
            route="/xrpc/com.atproto.server.createSession",
            method="ANY",
            file="packages/pds/src/api.ts",
            category="public_api",
            exposure="public",
            risk="medium",
            auth_signals=["atproto_namespace:com.atproto"],
            data_store_interaction=False,
            outbound_integration=True,
        )
    ]
    findings = [
        Finding(
            title="AT Protocol XRPC surface chains into a downstream trust boundary",
            severity="medium",
            mitigation="Enforce namespace-specific authz on XRPC handlers.",
            evidence=["route ANY /xrpc/com.atproto.server.createSession"],
        )
    ]
    attack_paths = [
        AttackPath(
            name="AT Protocol namespace trust-chain abuse",
            steps=["Entry: Attacker reaches /xrpc endpoint"],
            impact="A protocol namespace can be abused across service boundaries.",
        )
    ]

    review = render_defensive_review(scan, surfaces, findings, attack_paths)

    assert "# Defensive Review" in review
    assert "## System Overview" in review
    assert "## Strengths" in review
    assert "## Weaknesses / Risk Hotspots" in review
    assert "## Key Evidence Chains" in review
    assert "## Recommendations" in review
    assert "AT Protocol namespace trust-chain abuse" in review
    assert "Reason:" in review


def test_defensive_review_prioritizes_weaknesses_hotspots_and_recommendations() -> None:
    scan = ScanResult(
        root=".",
        languages=["typescript"],
        routes=[
            Route(path="/admin/reindex", method="POST", file="services/api/src/admin.ts"),
            Route(path="/health", method="GET", file="services/api/src/health.ts"),
        ],
        files_scanned=8,
    )
    surfaces = [
        AttackSurface(
            route="/admin/reindex",
            method="POST",
            file="services/api/src/admin.ts",
            category="admin",
            exposure="public",
            risk="high",
            auth_signals=["jwt"],
            data_store_interaction=True,
            outbound_integration=True,
        ),
        AttackSurface(
            route="/health",
            method="GET",
            file="services/api/src/health.ts",
            category="health",
            exposure="internal",
            risk="low",
            auth_signals=[],
            data_store_interaction=False,
            outbound_integration=False,
        ),
    ]
    findings = [
        Finding(
            title="Minor hygiene note",
            severity="medium",
            mitigation="Add docs.",
            confidence="low",
            evidence=["no major risk signal"],
        ),
        Finding(
            title="Privileged admin chain can reach data sink",
            severity="medium",
            mitigation="Require explicit admin authorization at each hop.",
            confidence="high",
            evidence=["confidence=0.91", "route POST /admin/reindex in services/api/src/admin.ts"],
        ),
    ]
    attack_paths = [
        AttackPath(
            name="Administrative service trust-chain abuse",
            steps=[
                "Entry: Attacker reaches POST /admin/reindex in services/api/src/admin.ts",
                "Propagation: Service edge reaches worker",
                "Sink: Database write path reached",
                "Evidence: confidence=0.91; edge api->worker",
            ],
            impact="Privileged request can trigger downstream database mutation.",
        ),
        AttackPath(name="Shallow health probe", steps=["Entry: /health"], impact="Limited operational insight."),
    ]

    review = render_defensive_review(scan, surfaces, findings, attack_paths)

    high_finding_idx = review.index("Privileged admin chain can reach data sink")
    low_finding_idx = review.index("Minor hygiene note")
    admin_hotspot_idx = review.index("/admin/reindex")
    health_hotspot_idx = review.index("/health")
    high_mitigation_idx = review.index("Require explicit admin authorization at each hop.")
    low_mitigation_idx = review.index("Add docs.")

    assert high_finding_idx < low_finding_idx
    assert admin_hotspot_idx < health_hotspot_idx
    assert high_mitigation_idx < low_mitigation_idx
    assert review.count("Reason:") >= 2
