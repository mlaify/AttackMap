from attackmap.models import AttackSurface, AuthHint, DatabaseHint, EdgeHint, ExternalCall, ProtocolHint, Route, ScanResult, ServiceHint
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


def test_webhook_finding_requires_stronger_runtime_evidence() -> None:
    scan = ScanResult(
        root=".",
        routes=[Route(path="/webhook/events", method="GET", file="tests/webhook_test.ts")],
        external_calls=[ExternalCall(target="https://api.example.com/process", file="tests/webhook_test.ts")],
    )

    findings = generate_findings(scan)

    assert not any(f.title == "Public webhook endpoint may trust attacker-controlled events" for f in findings)


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


def test_chain_generation_ignores_test_only_routes() -> None:
    scan = ScanResult(
        root=".",
        routes=[
            Route(path="/xrpc/com.atproto.server.createSession", method="ANY", file="tests/pds/api.test.ts"),
        ],
        auth_hints=[
            AuthHint(hint="service_name:pds", file="tests/pds/api.test.ts"),
            AuthHint(hint="service_name:relay", file="services/relay/src/store.ts"),
            AuthHint(hint="edge:pds->relay", file="tests/pds/api.test.ts"),
            AuthHint(hint="atproto_namespace:com.atproto", file="tests/pds/api.test.ts"),
            AuthHint(hint="atproto_lexicon:com.atproto.server.createSession", file="lexicons/com/atproto/server/createSession.json"),
            AuthHint(hint="atproto_service_note:pds", file="tests/pds/api.test.ts"),
        ],
        databases=[DatabaseHint(kind="postgresql", file="services/relay/src/store.ts")],
    )

    findings = generate_findings(scan)
    attack_paths = generate_attack_paths(scan)

    assert not any(f.title == "AT Protocol XRPC surface chains into a downstream trust boundary" for f in findings)
    assert not any(path.name == "AT Protocol namespace trust-chain abuse" for path in attack_paths)


def test_chain_generation_uses_dedicated_service_edge_and_protocol_hints() -> None:
    scan = ScanResult(
        root=".",
        routes=[Route(path="/xrpc/com.atproto.server.createSession", method="ANY", file="packages/pds/src/api.ts")],
        service_hints=[
            ServiceHint(hint="service_name:pds", file="packages/pds/src/api.ts"),
            ServiceHint(hint="service_name:relay", file="services/relay/src/store.ts"),
        ],
        edge_hints=[EdgeHint(hint="edge:pds->relay", file="packages/pds/src/api.ts")],
        protocol_hints=[
            ProtocolHint(hint="atproto_namespace:com.atproto", file="packages/pds/src/api.ts"),
            ProtocolHint(
                hint="atproto_lexicon:com.atproto.server.createSession",
                file="lexicons/com/atproto/server/createSession.json",
            ),
            ProtocolHint(hint="atproto_service_note:pds", file="packages/pds/src/api.ts"),
        ],
        databases=[DatabaseHint(kind="postgresql", file="services/relay/src/store.ts")],
    )

    attack_paths = generate_attack_paths(scan)

    assert len(attack_paths) == 1
    assert attack_paths[0].name == "AT Protocol namespace trust-chain abuse"


def test_generate_attack_paths_reuses_provided_attack_surfaces(monkeypatch) -> None:
    scan = ScanResult(
        root=".",
        routes=[Route(path="/admin/reindex", method="POST", file="app/admin.py")],
    )
    provided_surfaces = [
        AttackSurface(
            route="/admin/reindex",
            method="POST",
            file="app/admin.py",
            category="admin",
            exposure="public",
            risk="high",
            auth_signals=[],
            data_store_interaction=False,
            outbound_integration=False,
            rationale=["test surface"],
        )
    ]

    def fail_if_called(_scan: ScanResult) -> list[AttackSurface]:
        raise AssertionError("identify_attack_surfaces should not be called when attack_surfaces are provided")

    monkeypatch.setattr("attackmap.threat_model.identify_attack_surfaces", fail_if_called)

    attack_paths = generate_attack_paths(scan, attack_surfaces=provided_surfaces)

    assert len(attack_paths) == 1
    assert attack_paths[0].name == "Administrative route abuse"


# ---------------------------------------------------------------------------
# #24: a single scan can surface multiple distinct attack-path archetypes
# when distinct archetypes are present in the same codebase.
# ---------------------------------------------------------------------------


def test_distinct_archetypes_in_one_scan_each_produce_their_own_path() -> None:
    """Webhook + admin + auth surfaces on different routes → 3 paths."""
    provided_surfaces = [
        AttackSurface(
            route="/webhook/stripe",
            method="POST",
            file="app/webhook.py",
            category="webhook",
            exposure="public",
            risk="high",
            auth_signals=[],
            data_store_interaction=True,
            outbound_integration=False,
            rationale=["webhook surface"],
        ),
        AttackSurface(
            route="/admin/refund",
            method="POST",
            file="app/admin.py",
            category="admin",
            exposure="public",
            risk="high",
            auth_signals=[],
            data_store_interaction=False,
            outbound_integration=False,
            rationale=["admin surface"],
        ),
        AttackSurface(
            route="/login",
            method="POST",
            file="app/auth.py",
            category="auth",
            exposure="public",
            risk="medium",
            auth_signals=[],
            data_store_interaction=False,
            outbound_integration=False,
            rationale=["auth surface"],
        ),
    ]
    scan = ScanResult(root=".")
    paths = generate_attack_paths(scan, attack_surfaces=provided_surfaces)
    names = [p.name for p in paths]
    assert "External event spoofing into internal state change" in names
    assert "Administrative route abuse" in names
    assert "Authentication boundary bypass" in names
    assert len(paths) == 3


def test_same_surface_is_not_double_counted_across_archetypes() -> None:
    """A webhook surface that propagates via data also matches public_data;
    only one path should fire on that surface."""
    surface = AttackSurface(
        route="/webhook/stripe",
        method="POST",
        file="app/webhook.py",
        category="webhook",
        exposure="public",
        risk="high",
        auth_signals=[],
        data_store_interaction=True,
        outbound_integration=False,
        rationale=["both archetypes"],
    )
    scan = ScanResult(root=".")
    paths = generate_attack_paths(scan, attack_surfaces=[surface])
    assert [p.name for p in paths] == ["External event spoofing into internal state change"]


def test_max_attack_paths_cap_is_respected() -> None:
    """At most MAX_ATTACK_PATHS basic paths emit, even with more matching surfaces."""
    from attackmap.threat_model import MAX_ATTACK_PATHS

    surfaces = [
        AttackSurface(route="/webhook/a", method="POST", file="webhook.py", category="webhook", exposure="public", risk="high", auth_signals=[], data_store_interaction=True, outbound_integration=False, rationale=[]),
        AttackSurface(route="/admin/a", method="POST", file="admin.py", category="admin", exposure="public", risk="high", auth_signals=[], data_store_interaction=False, outbound_integration=False, rationale=[]),
        AttackSurface(route="/login", method="POST", file="auth.py", category="auth", exposure="public", risk="medium", auth_signals=[], data_store_interaction=False, outbound_integration=False, rationale=[]),
        AttackSurface(route="/upload", method="POST", file="upload.py", category="upload", exposure="public", risk="medium", auth_signals=[], data_store_interaction=False, outbound_integration=False, rationale=[]),
        AttackSurface(route="/api/items", method="GET", file="api.py", category="public_api", exposure="public", risk="medium", auth_signals=[], data_store_interaction=True, outbound_integration=False, rationale=[]),
        AttackSurface(route="/api/proxy", method="GET", file="proxy.py", category="public_api", exposure="public", risk="medium", auth_signals=[], data_store_interaction=False, outbound_integration=True, rationale=[]),
    ]
    scan = ScanResult(root=".")
    paths = generate_attack_paths(scan, attack_surfaces=surfaces)
    assert len(paths) <= MAX_ATTACK_PATHS
