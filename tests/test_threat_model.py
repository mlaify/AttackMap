from attackmap.models import AttackSurface, AuthHint, DatabaseHint, EdgeHint, ExternalCall, FrameworkHint, ProtocolHint, Route, ScanResult, SecretHint, ServiceHint
from attackmap.threat_model import (
    _build_probable_chains,
    confidence_bucket,
    generate_attack_paths,
    generate_findings,
)


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


# ---------------------------------------------------------------------------
# #15: basic-archetype attack paths cite file-local evidence when available.
# ---------------------------------------------------------------------------


def test_basic_archetype_path_appends_evidence_step_from_scan() -> None:
    """When a scan has databases / externals / secrets in the same file as
    the entry surface, the emitted path ends with an Evidence step naming
    them — not a generic 4-step narrative."""
    surface = AttackSurface(
        route="/admin/reindex",
        method="POST",
        file="app/admin.py",
        category="admin",
        exposure="public",
        risk="high",
        auth_signals=[],
        data_store_interaction=True,
        outbound_integration=True,
        rationale=["evidence test"],
    )
    scan = ScanResult(
        root=".",
        databases=[DatabaseHint(kind="postgresql", file="app/admin.py")],
        external_calls=[ExternalCall(target="https://analytics.example.com/ingest", file="app/admin.py")],
        secret_hints=[SecretHint(name="ANALYTICS_API_KEY", file="app/admin.py")],
    )
    paths = generate_attack_paths(scan, attack_surfaces=[surface])
    assert len(paths) == 1
    evidence_steps = [step for step in paths[0].steps if step.startswith("Evidence:")]
    assert len(evidence_steps) == 1
    body = evidence_steps[0]
    assert "postgresql" in body
    assert "analytics.example.com" in body
    assert "ANALYTICS_API_KEY" in body


def test_basic_archetype_path_omits_evidence_step_when_scan_is_empty() -> None:
    """No file-local artifacts → no Evidence step. Existing 4-step shape is
    preserved when there's nothing to cite (keeps CLI output stable)."""
    surface = AttackSurface(
        route="/admin/reindex",
        method="POST",
        file="app/admin.py",
        category="admin",
        exposure="public",
        risk="high",
        auth_signals=[],
        data_store_interaction=False,
        outbound_integration=False,
        rationale=["no evidence"],
    )
    scan = ScanResult(root=".")
    paths = generate_attack_paths(scan, attack_surfaces=[surface])
    assert len(paths) == 1
    assert not any(step.startswith("Evidence:") for step in paths[0].steps)
    assert len(paths[0].steps) == 4


def test_evidence_only_cites_signals_from_the_same_file_as_the_surface() -> None:
    """Signals in unrelated files must not be pulled in — the evidence
    step is a same-file citation, not a repo-wide summary."""
    surface = AttackSurface(
        route="/admin/reindex",
        method="POST",
        file="app/admin.py",
        category="admin",
        exposure="public",
        risk="high",
        auth_signals=[],
        data_store_interaction=False,
        outbound_integration=False,
        rationale=["scoped evidence"],
    )
    scan = ScanResult(
        root=".",
        databases=[
            DatabaseHint(kind="postgresql", file="app/admin.py"),      # same file — cited
            DatabaseHint(kind="redis", file="app/cache/other.py"),     # different file — NOT cited
        ],
    )
    paths = generate_attack_paths(scan, attack_surfaces=[surface])
    evidence = next(step for step in paths[0].steps if step.startswith("Evidence:"))
    assert "postgresql" in evidence
    assert "redis" not in evidence


# ---------------------------------------------------------------------------
# #13: Omeka/Laminas chain linker enrichments.
#
# The framework chain linker was in place before #13; this issue asks
# for it to consume the richer signals the Omeka/Laminas analyzers
# already emit (extensions, dependencies, surface classification),
# expose confidence in a low/medium/high bucket, and cite analyzer
# provenance in the evidence.
# ---------------------------------------------------------------------------


def test_confidence_bucket_thresholds() -> None:
    assert confidence_bucket(0.30) == "low"
    assert confidence_bucket(0.54) == "low"
    assert confidence_bucket(0.55) == "medium"
    assert confidence_bucket(0.74) == "medium"
    assert confidence_bucket(0.75) == "high"
    assert confidence_bucket(0.95) == "high"


def test_omeka_extension_binding_boosts_chain_confidence_and_evidence() -> None:
    """Adding Omeka/Laminas extension + mapping + surface hints on top
    of a base MVC scan lifts the confidence, names the framework
    signals in the evidence, and lands the chain at or above `medium`."""
    file = "module/Application/config/module.config.php"
    # Sparse base scan — only a controller hint, no service, no sink.
    # Leaves headroom below the 0.95 cap so the enrichments show up.
    plain = ScanResult(
        root=".",
        routes=[Route(path="/admin", method="ANY", file=file)],
        framework_hints=[
            FrameworkHint(hint="controller:Application\\Controller\\AdminController", file=file),
        ],
    )
    enriched = ScanResult(
        root=".",
        routes=[Route(path="/admin", method="ANY", file=file)],
        framework_hints=[
            FrameworkHint(hint="controller:Application\\Controller\\AdminController", file=file),
            FrameworkHint(hint="omeka_extension:service_manager", file=file),
            FrameworkHint(hint="laminas_controller_mapping", file=file),
            FrameworkHint(hint="omeka_dependency", file=file),
            FrameworkHint(hint="omeka_surface:admin", file=file),
        ],
    )
    plain_chain = _build_probable_chains(plain)[0]
    enriched_chain = _build_probable_chains(enriched)[0]

    assert enriched_chain.confidence > plain_chain.confidence
    # Enriched must be strictly higher and land in medium or high.
    assert confidence_bucket(enriched_chain.confidence) in {"medium", "high"}

    evidence_text = " ".join(enriched_chain.evidence)
    assert "omeka extension binding" in evidence_text
    assert "laminas controller mapping" in evidence_text
    assert "omeka dependency" in evidence_text
    assert "omeka surface classification" in evidence_text
    assert "admin" in evidence_text


def test_chain_evidence_cites_source_analyzer_when_provenance_is_available() -> None:
    """When contributing hints carry `source_analyzer` (set by core
    via #14), the chain's evidence lines end with `[via <analyzer>]`."""
    file = "module/Application/config/module.config.php"
    scan = ScanResult(
        root=".",
        routes=[Route(path="/admin", method="ANY", file=file)],
        framework_hints=[
            FrameworkHint(
                hint="controller:Application\\Controller\\AdminController",
                file=file,
                source_analyzer="php-laminas",
            ),
            FrameworkHint(
                hint="omeka_extension:module",
                file=file,
                source_analyzer="omeka-s",
            ),
        ],
        databases=[DatabaseHint(kind="sql", file="module/Application/src/Service/AdminService.php")],
    )
    chain = _build_probable_chains(scan)[0]
    joined = " ".join(chain.evidence)
    assert "[via php-laminas]" in joined
    assert "[via omeka-s]" in joined


def test_emitted_attack_path_includes_confidence_bucket() -> None:
    """The attack path emitted from a framework chain includes the
    low/medium/high label alongside the numeric confidence."""
    file = "module/Application/config/module.config.php"
    scan = ScanResult(
        root=".",
        routes=[Route(path="/admin", method="ANY", file=file)],
        framework_hints=[
            FrameworkHint(hint="controller:Application\\Controller\\AdminController", file=file),
            FrameworkHint(hint="service:Application\\Service\\AdminService", file=file),
            FrameworkHint(hint="omeka_extension:service_manager", file=file),
            FrameworkHint(hint="omeka_surface:admin", file=file),
        ],
        databases=[DatabaseHint(kind="sql", file=file)],
    )
    paths = generate_attack_paths(scan)
    evidence_step = next(step for step in paths[0].steps if step.startswith("Evidence:"))
    # Format: "confidence=0.85 (high); ..."
    assert " (high)" in evidence_step or " (medium)" in evidence_step
    assert "confidence=" in evidence_step


# ---------------------------------------------------------------------------
# #5: richer, more connected attack paths.
# ---------------------------------------------------------------------------


def test_public_data_propagation_step_names_the_same_file_datastore() -> None:
    """The Propagation narrative now says 'reaches a `sqlite` data store
    in `app.py`' when the archetype's surface shares a file with a
    database hint, instead of the generic 'close to the data store'."""
    surface = AttackSurface(
        route="/orders",
        method="POST",
        file="app/orders.py",
        category="public_api",
        exposure="public",
        risk="medium",
        auth_signals=[],
        data_store_interaction=True,
        outbound_integration=False,
        rationale=[],
    )
    scan = ScanResult(
        root=".",
        databases=[DatabaseHint(kind="sqlite", file="app/orders.py")],
    )
    paths = generate_attack_paths(scan, attack_surfaces=[surface])
    propagation = next(s for s in paths[0].steps if s.startswith("Propagation:"))
    assert "`sqlite`" in propagation
    assert "`app/orders.py`" in propagation


def test_integration_propagation_step_names_the_same_file_external_call() -> None:
    surface = AttackSurface(
        route="/proxy",
        method="GET",
        file="app/proxy.py",
        category="public_api",
        exposure="public",
        risk="medium",
        auth_signals=[],
        data_store_interaction=False,
        outbound_integration=True,
        rationale=[],
    )
    scan = ScanResult(
        root=".",
        external_calls=[ExternalCall(target="https://vendor.example/api", file="app/proxy.py")],
    )
    paths = generate_attack_paths(scan, attack_surfaces=[surface])
    propagation = next(s for s in paths[0].steps if s.startswith("Propagation:"))
    assert "`https://vendor.example/api`" in propagation
    assert "`app/proxy.py`" in propagation


def test_public_data_archetype_fans_out_across_distinct_files() -> None:
    """Three public-data routes in three separate files produce three
    concrete paths, each anchored on its own file."""
    surfaces = [
        AttackSurface(
            route=f"/svc/{name}",
            method="POST",
            file=f"app/{name}.py",
            category="public_api",
            exposure="public",
            risk="medium",
            auth_signals=[],
            data_store_interaction=True,
            outbound_integration=False,
            rationale=[],
        )
        for name in ("orders", "invoices", "customers")
    ]
    scan = ScanResult(
        root=".",
        databases=[
            DatabaseHint(kind="postgresql", file="app/orders.py"),
            DatabaseHint(kind="sqlite", file="app/invoices.py"),
            DatabaseHint(kind="redis", file="app/customers.py"),
        ],
    )
    paths = generate_attack_paths(scan, attack_surfaces=surfaces)
    public_data_paths = [p for p in paths if p.name == "Public input into sensitive data path"]
    assert len(public_data_paths) == 3
    entry_files = set()
    for p in public_data_paths:
        entry = next(s for s in p.steps if s.startswith("Entry:"))
        for name in ("orders", "invoices", "customers"):
            if f"app/{name}.py" in entry:
                entry_files.add(name)
    assert entry_files == {"orders", "invoices", "customers"}


def test_public_data_fanout_collapses_same_file_surfaces_to_one_path() -> None:
    """Three routes all in the same file share the same story — only one
    path is emitted (surface dedup is by-file, not by-route)."""
    surfaces = [
        AttackSurface(
            route=path,
            method="POST",
            file="app/handlers.py",
            category="public_api",
            exposure="public",
            risk="medium",
            auth_signals=[],
            data_store_interaction=True,
            outbound_integration=False,
            rationale=[],
        )
        for path in ("/a", "/b", "/c")
    ]
    scan = ScanResult(
        root=".",
        databases=[DatabaseHint(kind="postgresql", file="app/handlers.py")],
    )
    paths = generate_attack_paths(scan, attack_surfaces=surfaces)
    public_data_paths = [p for p in paths if p.name == "Public input into sensitive data path"]
    assert len(public_data_paths) == 1


# ---------------------------------------------------------------------------
# #4: severity scoring and prioritization tags.
# ---------------------------------------------------------------------------


from attackmap.threat_model import compute_finding_score  # noqa: E402


def test_compute_finding_score_range() -> None:
    """Score formula: severity_weight * confidence_multiplier."""
    assert compute_finding_score("high", "high") == 100
    assert compute_finding_score("high", "medium") == 75
    assert compute_finding_score("high", "low") == 50
    assert compute_finding_score("medium", "high") == 50
    assert compute_finding_score("medium", "medium") == 37
    assert compute_finding_score("low", "high") == 10
    assert compute_finding_score("low", "low") == 5


def test_findings_carry_prioritization_tags() -> None:
    scan = ScanResult(
        root=".",
        routes=[
            Route(path="/webhook/x", method="POST", file="api.py"),
            Route(path="/admin/y", method="POST", file="api.py"),
            Route(path="/login", method="POST", file="api.py"),
        ],
        databases=[DatabaseHint(kind="postgresql", file="api.py")],
        external_calls=[ExternalCall(target="https://vendor.example", file="api.py")],
        secret_hints=[SecretHint(name="API_KEY", file="config.py")],
    )
    findings = generate_findings(scan)
    tag_map = {f.title: f.tags for f in findings}

    # Webhook finding: exposed-endpoint + auth-missing
    webhook_tags = next(v for k, v in tag_map.items() if "webhook" in k.lower())
    assert "exposed-endpoint" in webhook_tags
    assert "auth-missing" in webhook_tags

    # Admin finding: exposed-endpoint + auth-missing + privileged
    admin_tags = next(v for k, v in tag_map.items() if "administrative" in k.lower())
    assert "privileged" in admin_tags

    # Secret finding: secret-exposure
    secret_tags = next(v for k, v in tag_map.items() if "secret" in k.lower())
    assert "secret-exposure" in secret_tags


def test_findings_are_scored_and_score_is_populated() -> None:
    scan = ScanResult(
        root=".",
        routes=[Route(path="/webhook/x", method="POST", file="api.py")],
        databases=[DatabaseHint(kind="postgresql", file="api.py")],
    )
    findings = generate_findings(scan)
    assert all(f.score is not None for f in findings)
    for f in findings:
        assert f.score == compute_finding_score(f.severity, f.confidence)


def test_findings_sorted_severity_then_score_descending_then_title() -> None:
    """Same-severity findings are ordered by score descending, so a
    HIGH/HIGH surfaces above a HIGH/MEDIUM."""
    scan = ScanResult(
        root=".",
        routes=[
            Route(path="/webhook/x", method="POST", file="api.py"),   # HIGH/HIGH
            Route(path="/admin/y", method="POST", file="api.py"),     # HIGH/HIGH
            Route(path="/upload", method="POST", file="api.py"),      # HIGH/MEDIUM
        ],
        databases=[DatabaseHint(kind="postgresql", file="api.py")],
    )
    findings = generate_findings(scan)
    # Filter to HIGH-severity findings
    highs = [f for f in findings if f.severity == "high"]
    assert len(highs) >= 2
    # The HIGH/MEDIUM upload finding must appear AFTER the HIGH/HIGH pair
    upload_idx = next((i for i, f in enumerate(highs) if "Upload" in f.title), None)
    assert upload_idx is not None
    for i, f in enumerate(highs):
        if i < upload_idx:
            assert f.confidence in {"high"}  # HIGH/HIGH precedes HIGH/MEDIUM


# ---------------------------------------------------------------------------
# #39: hard-coded secrets get their own HIGH finding, separate from
# env-reference secrets which stay MEDIUM.
# ---------------------------------------------------------------------------


def test_hardcoded_secret_produces_high_severity_finding() -> None:
    scan = ScanResult(
        root=".",
        secret_hints=[
            SecretHint(name="AKIA…MPLE", file="app.py", kind="aws_access_key", confidence=1.0),
        ],
    )
    findings = generate_findings(scan)
    hard = next(
        f for f in findings
        if f.title == "Hard-coded secret literals were found in source or config"
    )
    assert hard.severity == "high"
    assert "hardcoded-literal" in hard.tags
    assert "data-risk" in hard.tags


def test_env_reference_finding_stays_medium_when_hardcoded_is_absent() -> None:
    scan = ScanResult(
        root=".",
        secret_hints=[SecretHint(name="DB_PASSWORD", file="app.py")],  # default kind = env_reference
    )
    findings = generate_findings(scan)
    env = next(
        f for f in findings
        if f.title == "Secret-bearing environment variables are referenced in executable paths"
    )
    assert env.severity == "medium"
    # No hardcoded finding should fire when only env references exist.
    assert not any(
        f.title == "Hard-coded secret literals were found in source or config" for f in findings
    )


def test_hardcoded_finding_ranks_above_env_reference_finding() -> None:
    scan = ScanResult(
        root=".",
        secret_hints=[
            SecretHint(name="AKIA…MPLE", file="app.py", kind="aws_access_key", confidence=1.0),
            SecretHint(name="DB_PASSWORD", file="app.py"),  # env_reference
        ],
    )
    findings = generate_findings(scan)
    titles = [f.title for f in findings]
    hard_idx = titles.index("Hard-coded secret literals were found in source or config")
    env_idx = titles.index("Secret-bearing environment variables are referenced in executable paths")
    assert hard_idx < env_idx  # HIGH sorts above MEDIUM
