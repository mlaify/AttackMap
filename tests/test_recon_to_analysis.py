from attackmap.models import AuthHint, DatabaseHint, ExternalCall, Route, ScanResult
from attackmap.recon_to_analysis import to_attack_paths, to_attack_surface, to_findings, translate_recon


def test_translate_recon_produces_surface_findings_and_paths() -> None:
    scan = ScanResult(
        root=".",
        routes=[Route(path="/webhook/stripe", method="POST", file="api/webhooks.py")],
        external_calls=[ExternalCall(target="https://api.stripe.com/v1/events", file="api/webhooks.py")],
        databases=[DatabaseHint(kind="postgresql", file="db/client.py")],
        files_scanned=3,
        languages=["python"],
    )

    outputs = translate_recon(scan)

    assert outputs.attack_surfaces
    assert outputs.findings
    assert outputs.attack_paths
    assert any(surface.category == "webhook" for surface in outputs.attack_surfaces)
    assert any("webhook" in finding.title.lower() for finding in outputs.findings)


def test_translation_helpers_are_consistent_with_full_translation() -> None:
    scan = ScanResult(
        root=".",
        routes=[Route(path="/admin/reindex", method="POST", file="app/admin.py")],
        files_scanned=1,
        languages=["python"],
    )

    attack_surfaces = to_attack_surface(scan)
    findings = to_findings(scan, attack_surfaces)
    attack_paths = to_attack_paths(scan)
    outputs = translate_recon(scan)

    assert [surface.model_dump() for surface in attack_surfaces] == [
        surface.model_dump() for surface in outputs.attack_surfaces
    ]
    assert [finding.model_dump() for finding in findings] == [finding.model_dump() for finding in outputs.findings]
    assert [path.model_dump() for path in attack_paths] == [path.model_dump() for path in outputs.attack_paths]


def test_translate_recon_empty_scan_stays_conservative() -> None:
    scan = ScanResult(root=".", files_scanned=0, languages=[])
    outputs = translate_recon(scan)

    assert outputs.attack_surfaces == []
    assert outputs.attack_paths == []
    assert len(outputs.findings) == 1
    assert outputs.findings[0].severity == "low"
    assert "limited attack surface" in outputs.findings[0].title.lower()


def test_translation_filters_overloaded_non_auth_hints_for_findings() -> None:
    scan = ScanResult(
        root=".",
        routes=[Route(path="/login", method="POST", file="services/api/src/server.ts")],
        auth_hints=[AuthHint(hint="service_name:api", file="services/api/src/server.ts")],
    )

    findings = to_findings(scan)

    assert any(
        finding.title == "Authentication routes were detected without strong nearby auth controls"
        for finding in findings
    )


def test_translate_recon_preserves_chain_hints_for_attack_paths() -> None:
    scan = ScanResult(
        root=".",
        routes=[Route(path="/xrpc/ping", method="GET", file="services/api/src/server.ts")],
        auth_hints=[
            AuthHint(hint="service_name:api", file="services/api/src/server.ts"),
            AuthHint(hint="service_name:worker", file="services/worker/src/worker.ts"),
            AuthHint(hint="edge:api->worker", file="services/api/src/server.ts"),
        ],
        databases=[DatabaseHint(kind="postgresql", file="services/worker/src/worker.ts")],
    )

    outputs = translate_recon(scan)

    assert any(path.name == "Distributed service trust-chain abuse" for path in outputs.attack_paths)
