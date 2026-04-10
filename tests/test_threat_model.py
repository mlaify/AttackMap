from attackmap.models import DatabaseHint, ExternalCall, Route, ScanResult
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
