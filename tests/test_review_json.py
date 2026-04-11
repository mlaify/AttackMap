from attackmap.models import AttackPath, AttackSurface, Finding, Route, ScanResult
from attackmap.review_json import SCHEMA_VERSION, build_defensive_review_json


def test_defensive_review_json_contains_stable_top_level_sections() -> None:
    scan = ScanResult(
        root=".",
        languages=["python"],
        routes=[Route(path="/webhook/stripe", method="POST", file="app.py")],
        files_scanned=3,
    )
    surfaces = [
        AttackSurface(
            route="/webhook/stripe",
            method="POST",
            file="app.py",
            category="webhook",
            exposure="public",
            risk="high",
            outbound_integration=True,
        )
    ]
    findings = [
        Finding(
            title="Public webhook endpoint may trust attacker-controlled events",
            severity="high",
            evidence=["POST /webhook/stripe in app.py"],
            mitigation="Require signature verification on webhook payloads.",
            confidence="high",
        )
    ]
    paths = [AttackPath(name="Webhook chain", steps=["Entry: POST /webhook/stripe"], impact="State manipulation")]

    payload = build_defensive_review_json(scan, surfaces, findings, paths)

    assert payload["schema_version"] == SCHEMA_VERSION
    assert "target_metadata" in payload
    assert "system_overview" in payload
    assert "attack_surface" in payload
    assert "strengths" in payload
    assert "weaknesses_risk_hotspots" in payload
    assert "evidence_chains" in payload
    assert "recommendations" in payload
    assert "raw_structured_signals" in payload
    assert "limitations_meta" in payload


def test_defensive_review_json_distinguishes_observed_vs_inferred_classes() -> None:
    scan = ScanResult(
        root=".",
        languages=["typescript"],
        routes=[
            Route(path="/admin", method="POST", file="services/api/src/admin.ts"),
            Route(path="/xrpc/com.atproto.server.createSession", method="ANY", file="lexicons/com/atproto/server/createSession.json"),
            Route(path="/debug", method="GET", file="tests/api/debug.test.ts"),
        ],
        files_scanned=10,
    )
    surfaces = [
        AttackSurface(
            route="/admin",
            method="POST",
            file="services/api/src/admin.ts",
            category="admin",
            exposure="public",
            risk="high",
        ),
        AttackSurface(
            route="/xrpc/com.atproto.server.createSession",
            method="ANY",
            file="lexicons/com/atproto/server/createSession.json",
            category="public_api",
            exposure="public",
            risk="medium",
            auth_signals=["atproto_namespace:com.atproto"],
        ),
        AttackSurface(
            route="/debug",
            method="GET",
            file="tests/api/debug.test.ts",
            category="public_api",
            exposure="public",
            risk="low",
        ),
    ]

    payload = build_defensive_review_json(scan, surfaces, [], [])
    counts = payload["attack_surface"]["evidence_class_counts"]

    assert counts["observed_runtime_public"] == 1
    assert counts["inferred_protocol"] == 1
    assert counts["low_quality"] == 1
