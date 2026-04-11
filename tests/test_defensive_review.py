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
    assert "Provenance:" in review


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


def test_defensive_review_classifies_entrypoints_and_downweights_test_sources() -> None:
    scan = ScanResult(
        root=".",
        languages=["typescript"],
        routes=[
            Route(path="/xrpc/com.atproto.server.createSession", method="ANY", file="lexicons/com/atproto/server/createSession.json"),
            Route(path="/admin", method="POST", file="services/api/src/admin.ts"),
            Route(path="/health", method="GET", file="services/api/src/health.ts"),
            Route(path="/debug/test-route", method="GET", file="tests/api/debug.test.ts"),
        ],
        files_scanned=10,
    )
    surfaces = [
        AttackSurface(
            route="/xrpc/com.atproto.server.createSession",
            method="ANY",
            file="lexicons/com/atproto/server/createSession.json",
            category="public_api",
            exposure="public",
            risk="medium",
            auth_signals=["atproto_namespace:com.atproto"],
            outbound_integration=True,
        ),
        AttackSurface(
            route="/admin",
            method="POST",
            file="services/api/src/admin.ts",
            category="admin",
            exposure="public",
            risk="high",
            auth_signals=["jwt"],
            data_store_interaction=True,
        ),
        AttackSurface(
            route="/health",
            method="GET",
            file="services/api/src/health.ts",
            category="health",
            exposure="internal",
            risk="low",
        ),
        AttackSurface(
            route="/debug/test-route",
            method="GET",
            file="tests/api/debug.test.ts",
            category="public_api",
            exposure="public",
            risk="medium",
            outbound_integration=True,
        ),
    ]
    findings = [
        Finding(
            title="Runtime admin weakness",
            severity="medium",
            mitigation="Harden admin auth.",
            confidence="high",
            evidence=["route POST /admin in services/api/src/admin.ts"],
        ),
        Finding(
            title="Test-only weakness",
            severity="high",
            mitigation="Fix test fixture.",
            confidence="high",
            evidence=["route GET /debug/test-route in tests/api/debug.test.ts"],
        ),
    ]
    attack_paths = [AttackPath(name="Admin path", steps=["Entry: /admin"], impact="Privileged effect")]

    review = render_defensive_review(scan, surfaces, findings, attack_paths)

    assert "- Observed runtime/public surfaces: 1" in review
    assert "- Protocol/lexicon-derived surfaces (inferred): 1" in review
    assert "- Internal-only surfaces: 1" in review
    assert "- Test/example/mocked surfaces (down-weighted): 1" in review
    assert review.index("Runtime admin weakness") < review.index("Test-only weakness")
    assert "Provenance: observed_runtime=100%, protocol_derived=0%, low_quality=0%" in review
    assert "Provenance: observed_runtime=0%, protocol_derived=0%, low_quality=100%" in review


def test_recommendations_prefer_observed_evidence_over_low_quality_only_sources() -> None:
    scan = ScanResult(
        root=".",
        languages=["typescript"],
        routes=[Route(path="/admin", method="POST", file="services/api/src/admin.ts")],
        files_scanned=4,
    )
    surfaces = [
        AttackSurface(
            route="/admin",
            method="POST",
            file="services/api/src/admin.ts",
            category="admin",
            exposure="public",
            risk="high",
            auth_signals=["jwt"],
        ),
        AttackSurface(
            route="/debug/test-route",
            method="GET",
            file="tests/api/debug.test.ts",
            category="public_api",
            exposure="public",
            risk="medium",
        ),
    ]
    findings = [
        Finding(
            title="Observed runtime admin issue",
            severity="medium",
            mitigation="Enforce admin policy checks.",
            confidence="high",
            evidence=["route POST /admin in services/api/src/admin.ts"],
        ),
        Finding(
            title="Fixture-only issue",
            severity="high",
            mitigation="Fix fixture route handling.",
            confidence="high",
            evidence=["route GET /debug/test-route in tests/api/debug.test.ts"],
        ),
    ]
    attack_paths = [AttackPath(name="Admin path", steps=["Entry: /admin"], impact="Privileged effect")]

    review = render_defensive_review(scan, surfaces, findings, attack_paths)

    assert "[observed] Enforce admin policy checks." in review
    assert "[low-quality-evidence] Fix fixture route handling." in review
    assert review.index("[observed] Enforce admin policy checks.") < review.index(
        "[low-quality-evidence] Fix fixture route handling."
    )
