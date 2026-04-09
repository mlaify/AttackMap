from attackmap.models import Route, ScanResult
from attackmap.threat_model import generate_attack_paths, generate_findings


def test_webhook_route_generates_high_severity_finding() -> None:
    scan = ScanResult(
        root=".",
        routes=[Route(path="/webhook/stripe", method="POST", file="api.py")],
    )

    findings = generate_findings(scan)
    attack_paths = generate_attack_paths(scan)

    assert any(f.title == "Webhook endpoints detected" for f in findings)
    assert any(p.name == "Webhook abuse to backend action" for p in attack_paths)
