from attackmap.models import AuthHint, DatabaseHint, ExternalCall, Route, ScanResult
from attackmap.threat_model import generate_attack_paths, generate_findings


def test_webhook_route_generates_high_severity_finding() -> None:
    scan = ScanResult(
        root=".",
        routes=[Route(path="/webhook/stripe", method="POST", file="api.py")],
        databases=[DatabaseHint(kind="postgresql", file="db.py")],
        external_calls=[ExternalCall(target="https://api.example.com/process", file="api.py")],
    )

    findings = generate_findings(scan)
    attack_paths = generate_attack_paths(scan)

    assert any(f.title == "Public webhook endpoint may trust attacker-controlled events" for f in findings)
    assert any(p.name == "External event spoofing into internal state change" for p in attack_paths)
    assert len(attack_paths) == 1
    assert any(step.startswith("Entry:") for path in attack_paths for step in path.steps)


def test_framework_chain_linker_generates_evidence_backed_attack_path() -> None:
    scan = ScanResult(
        root=".",
        routes=[Route(path="/admin", method="ANY", file="module/Application/config/module.config.php")],
        auth_hints=[
            AuthHint(hint="controller:Application\\Controller\\AdminController", file="module/Application/config/module.config.php"),
            AuthHint(hint="service:Application\\Service\\AdminService", file="module/Application/src/Service/AdminService.php"),
            AuthHint(hint="omeka_extension:service_manager", file="module/Application/config/module.config.php"),
        ],
        databases=[DatabaseHint(kind="sql", file="module/Application/src/Service/AdminService.php")],
        external_calls=[ExternalCall(target="https://collector.example.net/ingest", file="module/Application/src/Service/AdminService.php")],
    )

    findings = generate_findings(scan)
    attack_paths = generate_attack_paths(scan)

    assert any(f.title == "Framework route-to-service chain reaches a sensitive sink" for f in findings)
    assert len(attack_paths) == 1
    assert attack_paths[0].name == "Framework route-to-sink attack chain"
    assert any(step.startswith("Evidence: confidence=") for step in attack_paths[0].steps)
