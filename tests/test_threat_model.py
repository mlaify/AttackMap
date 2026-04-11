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


def test_service_chain_linker_generates_distributed_attack_path() -> None:
    scan = ScanResult(
        root=".",
        routes=[Route(path="/xrpc/ping", method="GET", file="services/api/src/server.ts")],
        auth_hints=[
            AuthHint(hint="service_name:api", file="services/api/src/server.ts"),
            AuthHint(hint="service_role:api", file="services/api/src/server.ts"),
            AuthHint(hint="service_name:worker", file="services/worker/src/worker.ts"),
            AuthHint(hint="service_role:worker", file="services/worker/src/worker.ts"),
            AuthHint(hint="edge:api->worker", file="services/api/src/server.ts"),
        ],
        databases=[DatabaseHint(kind="postgresql", file="services/worker/src/worker.ts")],
        external_calls=[ExternalCall(target="env://FEEDGEN_URL", file="services/api/src/server.ts")],
    )

    findings = generate_findings(scan)
    attack_paths = generate_attack_paths(scan)

    assert any(f.title == "Inter-service trust chain reaches a sensitive downstream sink" for f in findings)
    assert len(attack_paths) == 1
    assert attack_paths[0].name == "Distributed service trust-chain abuse"
    assert any(step.startswith("Propagation:") for step in attack_paths[0].steps)
    assert any(step.startswith("Config risk:") for step in attack_paths[0].steps)
    assert any(step.startswith("Evidence: confidence=") for step in attack_paths[0].steps)


def test_atproto_chain_linker_generates_namespace_aware_attack_path() -> None:
    scan = ScanResult(
        root=".",
        routes=[Route(path="/xrpc/com.atproto.server.createSession", method="ANY", file="packages/pds/src/api.ts")],
        auth_hints=[
            AuthHint(hint="service_name:pds", file="packages/pds/src/api.ts"),
            AuthHint(hint="service_name:relay", file="services/relay/src/store.ts"),
            AuthHint(hint="edge:pds->relay", file="packages/pds/src/api.ts"),
            AuthHint(hint="atproto_namespace:com.atproto", file="packages/pds/src/api.ts"),
            AuthHint(hint="atproto_protocol:xrpc", file="packages/pds/src/api.ts"),
            AuthHint(hint="atproto_lexicon:com.atproto.server.createSession", file="lexicons/com/atproto/server/createSession.json"),
            AuthHint(hint="atproto_service_note:pds", file="packages/pds/src/api.ts"),
            AuthHint(hint="atproto_service_edge:relay", file="packages/pds/src/api.ts"),
        ],
        databases=[DatabaseHint(kind="postgresql", file="services/relay/src/store.ts")],
        external_calls=[ExternalCall(target="env://RELAY_URL", file="packages/pds/src/api.ts")],
    )

    findings = generate_findings(scan)
    attack_paths = generate_attack_paths(scan)

    assert any(f.title == "AT Protocol XRPC surface chains into a downstream trust boundary" for f in findings)
    assert len(attack_paths) == 1
    assert attack_paths[0].name == "AT Protocol namespace trust-chain abuse"
    assert any(step.startswith("Namespace:") for step in attack_paths[0].steps)
    assert any(step.startswith("Propagation:") for step in attack_paths[0].steps)
    assert any(step.startswith("Config risk:") for step in attack_paths[0].steps)
