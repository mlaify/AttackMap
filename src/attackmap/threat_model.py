from __future__ import annotations

from dataclasses import dataclass

from .analyzer import identify_attack_surfaces
from .models import AttackPath, AttackSurface, Finding, Route, ScanResult

LOW_QUALITY_SEGMENTS = ("/tests/", "/__tests__/", "/fixtures/", "/mocks/", "/examples/")

# Cap on the number of basic-archetype attack paths emitted per scan.
# Lifted from 1 in #24; capped here to keep reports focused — anything
# beyond the top few is typically redundant with what findings already
# surface. Chain-archetype paths (atproto / service / framework) emit
# alone and don't count toward this cap.
MAX_ATTACK_PATHS = 5


def _surface_label(surface: AttackSurface) -> str:
    return f"{surface.method} {surface.route} in {surface.file}"


def _severity_rank(value: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(value, 3)


def _action_step(label: str, action: str) -> str:
    return f"{label}: {action}"


def _finding_evidence(surface: AttackSurface) -> str:
    details: list[str] = [_surface_label(surface)]
    if surface.auth_signals:
        details.append(f"auth signals: {', '.join(surface.auth_signals)}")
    else:
        details.append("no auth signals observed")
    if surface.data_store_interaction:
        details.append("data store reachable")
    if surface.outbound_integration:
        details.append("external integration reachable")
    return "; ".join(details)


@dataclass(frozen=True)
class ProbableChain:
    route_method: str
    route_path: str
    route_file: str
    controller: str | None
    action: str | None
    service: str | None
    sink: str
    confidence: float
    evidence: list[str]


@dataclass(frozen=True)
class ServiceChain:
    route_method: str
    route_path: str
    route_file: str
    entry_service: str
    next_service: str | None
    sink: str
    confidence: float
    evidence: list[str]
    env_risk: str | None = None


@dataclass(frozen=True)
class AtprotoChain:
    route_method: str
    route_path: str
    route_file: str
    namespace: str
    entry_service: str
    next_service: str | None
    sink: str
    confidence: float
    evidence: list[str]
    env_risk: str | None = None


def _extract_prefixed_hints(scan: ScanResult, prefix: str) -> list[tuple[str, str]]:
    grouped_hints: list[tuple[str, str]] = []
    for hint in scan.auth_hints:
        if hint.hint.startswith(prefix):
            grouped_hints.append((hint.hint.removeprefix(prefix), hint.file))

    # Phase-2 migration support: allow specialized non-auth hint categories to
    # carry prefixed values while keeping auth_hints fallback behavior.
    if prefix.startswith("service_"):
        for hint in scan.service_hints:
            if hint.hint.startswith(prefix):
                grouped_hints.append((hint.hint.removeprefix(prefix), hint.file))
    elif prefix.startswith("edge:"):
        for hint in scan.edge_hints:
            if hint.hint.startswith(prefix):
                grouped_hints.append((hint.hint.removeprefix(prefix), hint.file))
    elif prefix.startswith("entrypoint:"):
        for hint in scan.entrypoint_hints:
            if hint.hint.startswith(prefix):
                grouped_hints.append((hint.hint.removeprefix(prefix), hint.file))
    elif prefix.startswith(("atproto_", "protocol:")):
        for hint in scan.protocol_hints:
            if hint.hint.startswith(prefix):
                grouped_hints.append((hint.hint.removeprefix(prefix), hint.file))
    elif prefix.startswith(("controller:", "service:", "omeka_", "laminas_")):
        for hint in scan.framework_hints:
            if hint.hint.startswith(prefix):
                grouped_hints.append((hint.hint.removeprefix(prefix), hint.file))

    deduped: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in grouped_hints:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)
    return deduped


def _is_low_quality_source(path_or_text: str) -> bool:
    normalized = path_or_text.replace("\\", "/").lower()
    return any(segment in f"/{normalized}/" for segment in LOW_QUALITY_SEGMENTS)


def _runtime_routes(scan: ScanResult) -> list[Route]:
    return [route for route in scan.routes if not _is_low_quality_source(route.file)]


def _extract_edge_hints(scan: ScanResult) -> list[tuple[str, str, str]]:
    edges: list[tuple[str, str, str]] = []
    all_edge_hints = [*scan.edge_hints, *scan.auth_hints]
    for hint in all_edge_hints:
        if not hint.hint.startswith("edge:"):
            continue
        raw_edge = hint.hint.removeprefix("edge:")
        if "->" not in raw_edge:
            continue
        source, target = raw_edge.split("->", 1)
        source_name = source.strip().lower()
        target_name = target.strip().lower()
        if not source_name or not target_name:
            continue
        edges.append((source_name, target_name, hint.file))
    return edges


def _infer_service_name_from_file(file_path: str) -> str | None:
    normalized = file_path.replace("\\", "/")
    parts = normalized.split("/")
    for parent in ("services", "packages", "apps"):
        if parent in parts:
            idx = parts.index(parent)
            if idx + 1 < len(parts):
                return parts[idx + 1].lower()
    return None


def _file_service_map(scan: ScanResult) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for service_name, service_file in _extract_prefixed_hints(scan, "service_name:"):
        mapping[service_file] = service_name.lower()
    for path in [*mapping.keys(), *(route.file for route in scan.routes), *(db.file for db in scan.databases), *(call.file for call in scan.external_calls)]:
        if path in mapping:
            continue
        inferred = _infer_service_name_from_file(path)
        if inferred:
            mapping[path] = inferred
    return mapping


def _build_service_chains(scan: ScanResult) -> list[ServiceChain]:
    service_edges = _extract_edge_hints(scan)
    has_service_hints = any(h.hint.startswith("service_name:") for h in [*scan.service_hints, *scan.auth_hints])
    if not service_edges and not has_service_hints:
        return []

    file_service = _file_service_map(scan)
    edge_targets_by_source: dict[str, list[str]] = {}
    for source, target, _file in service_edges:
        edge_targets_by_source.setdefault(source, []).append(target)

    databases_by_service: dict[str, DatabaseHint] = {}
    for database in scan.databases:
        service = file_service.get(database.file)
        if service and service not in databases_by_service:
            databases_by_service[service] = database

    outbound_by_service: dict[str, ExternalCall] = {}
    env_url_by_service: dict[str, str] = {}
    for call in scan.external_calls:
        service = file_service.get(call.file)
        if not service:
            continue
        if call.target.startswith("env://"):
            env_url_by_service.setdefault(service, call.target)
            continue
        outbound_by_service.setdefault(service, call)

    chains: list[ServiceChain] = []
    for route in _runtime_routes(scan):
        evidence = [f"route {route.method} {route.path} in {route.file}"]
        confidence = 0.35
        entry_service = file_service.get(route.file) or _infer_service_name_from_file(route.file) or "entry-service"
        if file_service.get(route.file):
            confidence += 0.25
            evidence.append(f"entry service from file-local hint: {entry_service}")
        else:
            confidence += 0.1
            evidence.append(f"entry service inferred from repository layout: {entry_service}")

        next_service = None
        sink = "privileged downstream action"
        env_risk = env_url_by_service.get(entry_service)

        candidates = edge_targets_by_source.get(entry_service, [])
        if candidates:
            next_service = candidates[0]
            confidence += 0.15
            evidence.append(f"inter-service edge: {entry_service}->{next_service}")

        sink_service = next_service or entry_service
        if sink_service in databases_by_service:
            db_hint = databases_by_service[sink_service]
            sink = "database"
            confidence += 0.2
            evidence.append(f"database sink in service {sink_service}: {db_hint.kind} ({db_hint.file})")
        elif sink_service in outbound_by_service:
            ext_hint = outbound_by_service[sink_service]
            sink = "external dependency"
            confidence += 0.15
            evidence.append(f"external sink in service {sink_service}: {ext_hint.target} ({ext_hint.file})")
        elif scan.databases:
            sink = "database"
            confidence += 0.05
            evidence.append(f"database hint elsewhere in repo: {scan.databases[0].kind} ({scan.databases[0].file})")
        elif scan.external_calls:
            sink = "external dependency"
            confidence += 0.05
            evidence.append(f"external call elsewhere in repo: {scan.external_calls[0].target} ({scan.external_calls[0].file})")

        if env_risk:
            confidence += 0.05
            evidence.append(f"env-configured dependency in entry service: {env_risk}")

        chains.append(
            ServiceChain(
                route_method=route.method,
                route_path=route.path,
                route_file=route.file,
                entry_service=entry_service,
                next_service=next_service,
                sink=sink,
                confidence=min(confidence, 0.95),
                evidence=evidence,
                env_risk=env_risk,
            )
        )

    chains.sort(key=lambda chain: chain.confidence, reverse=True)
    return chains


def _is_atproto_scan(scan: ScanResult) -> bool:
    return any(hint.hint.startswith("atproto_") for hint in [*scan.protocol_hints, *scan.auth_hints])


def _extract_xrpc_namespace(route_path: str) -> str | None:
    marker = "/xrpc/"
    if marker not in route_path:
        return None
    value = route_path.split(marker, 1)[1].strip("/")
    if not value:
        return None
    if value.startswith("com.atproto."):
        return "com.atproto"
    if value.startswith("app.bsky."):
        return "app.bsky"
    return None


def _build_atproto_chains(scan: ScanResult) -> list[AtprotoChain]:
    if not _is_atproto_scan(scan):
        return []

    file_service = _file_service_map(scan)
    for service_name, service_file in _extract_prefixed_hints(scan, "atproto_service_note:"):
        file_service.setdefault(service_file, service_name.lower())

    edge_targets_by_source: dict[str, list[str]] = {}
    for source, target, _file in _extract_edge_hints(scan):
        edge_targets_by_source.setdefault(source, []).append(target)

    namespaces = {name for name, _file in _extract_prefixed_hints(scan, "atproto_namespace:")}
    lexicons = {name for name, _file in _extract_prefixed_hints(scan, "atproto_lexicon:")}
    xrpc_refs = {name for name, _file in _extract_prefixed_hints(scan, "atproto_xrpc_ref:")}
    service_edges = {name for name, _file in _extract_prefixed_hints(scan, "atproto_service_edge:")}
    stream_hints = {name for name, _file in _extract_prefixed_hints(scan, "atproto_event_stream:")}

    databases_by_service: dict[str, tuple[str, str]] = {}
    for database in scan.databases:
        service = file_service.get(database.file)
        if service and service not in databases_by_service:
            databases_by_service[service] = (database.kind, database.file)

    outbound_by_service: dict[str, tuple[str, str]] = {}
    env_url_by_service: dict[str, str] = {}
    for call in scan.external_calls:
        service = file_service.get(call.file)
        if not service:
            continue
        if call.target.startswith("env://"):
            env_url_by_service.setdefault(service, call.target)
            continue
        outbound_by_service.setdefault(service, (call.target, call.file))

    chains: list[AtprotoChain] = []
    for route in _runtime_routes(scan):
        namespace = _extract_xrpc_namespace(route.path)
        if namespace is None:
            continue

        evidence = [f"xrpc route {route.method} {route.path} in {route.file}"]
        confidence = 0.45
        if namespace in namespaces:
            confidence += 0.1
            evidence.append(f"namespace signal observed: {namespace}")

        endpoint_name = route.path.removeprefix("/xrpc/")
        if endpoint_name in lexicons:
            confidence += 0.1
            evidence.append(f"lexicon-defined endpoint: {endpoint_name}")
        if endpoint_name in xrpc_refs:
            confidence += 0.05
            evidence.append(f"code-level xrpc reference: {endpoint_name}")

        entry_service = file_service.get(route.file) or _infer_service_name_from_file(route.file) or "entry-service"
        if file_service.get(route.file):
            confidence += 0.15
            evidence.append(f"entry service from analyzer hints: {entry_service}")
        else:
            confidence += 0.05
            evidence.append(f"entry service inferred from repository layout: {entry_service}")

        next_service = None
        sink = "privileged downstream action"
        env_risk = env_url_by_service.get(entry_service)

        edge_candidates = edge_targets_by_source.get(entry_service, [])
        if edge_candidates:
            next_service = edge_candidates[0]
            confidence += 0.1
            evidence.append(f"inter-service edge: {entry_service}->{next_service}")
        elif service_edges:
            next_service = sorted(service_edges)[0]
            confidence += 0.05
            evidence.append(f"atproto env-derived service edge: {entry_service}->{next_service}")

        sink_service = next_service or entry_service
        if sink_service in databases_by_service:
            kind, db_file = databases_by_service[sink_service]
            sink = "database"
            confidence += 0.15
            evidence.append(f"database sink in service {sink_service}: {kind} ({db_file})")
        elif sink_service in outbound_by_service:
            target, outbound_file = outbound_by_service[sink_service]
            sink = "external dependency"
            confidence += 0.12
            evidence.append(f"outbound sink in service {sink_service}: {target} ({outbound_file})")
        elif scan.databases:
            sink = "database"
            confidence += 0.03
            evidence.append(f"database hint elsewhere in repo: {scan.databases[0].kind} ({scan.databases[0].file})")
        elif scan.external_calls:
            sink = "external dependency"
            confidence += 0.03
            evidence.append(f"external call elsewhere in repo: {scan.external_calls[0].target} ({scan.external_calls[0].file})")

        if env_risk:
            confidence += 0.04
            evidence.append(f"env-configured dependency in entry service: {env_risk}")
        if stream_hints:
            confidence += 0.03
            evidence.append(f"event stream exposure hints: {', '.join(sorted(stream_hints)[:2])}")

        chains.append(
            AtprotoChain(
                route_method=route.method,
                route_path=route.path,
                route_file=route.file,
                namespace=namespace,
                entry_service=entry_service,
                next_service=next_service,
                sink=sink,
                confidence=min(confidence, 0.95),
                evidence=evidence,
                env_risk=env_risk,
            )
        )

    chains.sort(key=lambda chain: chain.confidence, reverse=True)
    return chains


def _file_module_key(file_path: str) -> str:
    normalized = file_path.replace("\\", "/")
    marker = "/module/"
    if marker in normalized:
        suffix = normalized.split(marker, 1)[1]
        parts = suffix.split("/")
        if parts and parts[0]:
            return f"module/{parts[0].lower()}"
    parts = normalized.split("/")
    if parts:
        return parts[0].lower()
    return normalized.lower()


def _guess_action(route_path: str) -> str | None:
    lower = route_path.lower()
    if "/admin" in lower:
        return "admin action"
    if "/api" in lower:
        return "api action"
    if lower.startswith("/s/") or "/site" in lower:
        return "site action"
    return None


def _is_framework_mvc_scan(scan: ScanResult) -> bool:
    framework_values = [*scan.framework_hints, *scan.auth_hints]
    return any(
        hint.hint.startswith("controller:")
        or hint.hint.startswith("service:")
        or hint.hint.startswith("omeka_")
        or hint.hint.startswith("laminas_")
        for hint in framework_values
    )


def _build_probable_chains(scan: ScanResult) -> list[ProbableChain]:
    controllers = _extract_prefixed_hints(scan, "controller:")
    services = _extract_prefixed_hints(scan, "service:")
    db_by_module = {_file_module_key(db.file): db for db in scan.databases}
    external_by_module = {_file_module_key(call.file): call for call in scan.external_calls}

    chains: list[ProbableChain] = []
    for route in _runtime_routes(scan):
        module_key = _file_module_key(route.file)
        evidence = [f"route {route.method} {route.path} in {route.file}"]
        confidence = 0.35

        route_controller = next((name for name, file in controllers if file == route.file), None)
        if route_controller is None:
            route_controller = next((name for name, file in controllers if _file_module_key(file) == module_key), None)
            if route_controller:
                confidence += 0.15
                evidence.append(f"controller inferred by module proximity: {route_controller}")
        else:
            confidence += 0.25
            evidence.append(f"controller in same file: {route_controller}")

        route_service = next((name for name, file in services if file == route.file), None)
        if route_service is None:
            route_service = next((name for name, file in services if _file_module_key(file) == module_key), None)
            if route_service:
                confidence += 0.10
                evidence.append(f"service inferred by module proximity: {route_service}")
        else:
            confidence += 0.20
            evidence.append(f"service in same file: {route_service}")

        sink = "privileged action"
        if module_key in db_by_module:
            sink = "database"
            confidence += 0.2
            evidence.append(f"database hint in same module: {db_by_module[module_key].kind} ({db_by_module[module_key].file})")
        elif module_key in external_by_module:
            sink = "external integration"
            confidence += 0.15
            evidence.append(f"external call in same module: {external_by_module[module_key].target} ({external_by_module[module_key].file})")
        elif scan.databases:
            sink = "database"
            confidence += 0.05
            evidence.append(f"database hint elsewhere in repo: {scan.databases[0].kind} ({scan.databases[0].file})")
        elif scan.external_calls:
            sink = "external integration"
            confidence += 0.05
            evidence.append(
                f"external call elsewhere in repo: {scan.external_calls[0].target} ({scan.external_calls[0].file})"
            )

        action = _guess_action(route.path)
        if action:
            confidence += 0.05
            evidence.append(f"route naming suggests {action}")

        chains.append(
            ProbableChain(
                route_method=route.method,
                route_path=route.path,
                route_file=route.file,
                controller=route_controller,
                action=action,
                service=route_service,
                sink=sink,
                confidence=min(confidence, 0.95),
                evidence=evidence,
            )
        )

    chains.sort(key=lambda chain: chain.confidence, reverse=True)
    return chains


def generate_findings(scan: ScanResult, attack_surfaces: list[AttackSurface] | None = None) -> list[Finding]:
    surfaces = attack_surfaces if attack_surfaces is not None else identify_attack_surfaces(scan)
    runtime_surfaces = [surface for surface in surfaces if not _is_low_quality_source(surface.file)]
    findings: list[Finding] = []
    atproto_chains = _build_atproto_chains(scan)
    service_chains = _build_service_chains(scan)
    chains = _build_probable_chains(scan) if _is_framework_mvc_scan(scan) else []
    webhook_surfaces = [
        surface
        for surface in runtime_surfaces
        if surface.category == "webhook"
        and surface.exposure == "public"
        and surface.method in {"POST", "PUT", "PATCH", "DELETE", "ANY"}
        and (surface.data_store_interaction or surface.outbound_integration)
        and not any(signal in {"jwt", "oauth", "authorization", "service_auth"} for signal in surface.auth_signals)
    ]
    admin_surfaces = [surface for surface in runtime_surfaces if surface.category == "admin"]
    upload_surfaces = [surface for surface in runtime_surfaces if surface.category == "upload"]
    auth_surfaces = [surface for surface in runtime_surfaces if surface.category == "auth"]
    public_data_surfaces = [
        surface
        for surface in runtime_surfaces
        if surface.exposure == "public" and surface.data_store_interaction and surface.category != "health"
    ]
    public_integration_surfaces = [
        surface
        for surface in runtime_surfaces
        if surface.exposure == "public" and surface.outbound_integration
    ]

    if webhook_surfaces:
        findings.append(
            Finding(
                title="Public webhook endpoint may trust attacker-controlled events",
                severity="high",
                evidence=[_finding_evidence(surface) for surface in webhook_surfaces[:10]],
                mitigation="Require signature verification before processing webhook payloads, reject replays, and keep any downstream state change behind strict validation.",
                confidence="high",
            )
        )

    if admin_surfaces:
        findings.append(
            Finding(
                title="Administrative routes appear reachable from the main application surface",
                severity="high",
                evidence=[_finding_evidence(surface) for surface in admin_surfaces[:10]],
                mitigation="Require strong authentication and explicit server-side authorization on every admin action, and move admin routes behind a narrower exposure boundary where possible.",
                confidence="high",
            )
        )

    if upload_surfaces:
        findings.append(
            Finding(
                title="Upload or import routes expand attacker-controlled input handling",
                severity="high",
                evidence=[_finding_evidence(surface) for surface in upload_surfaces[:10]],
                mitigation="Constrain accepted formats, isolate parsers, scan uploaded content, and treat imported files as untrusted all the way through storage and processing.",
                confidence="medium",
            )
        )

    if auth_surfaces and not any(surface.auth_signals for surface in auth_surfaces):
        findings.append(
            Finding(
                title="Authentication routes were detected without strong nearby auth controls",
                severity="medium",
                evidence=[_finding_evidence(surface) for surface in auth_surfaces[:10]],
                mitigation="Review these routes for rate limiting, credential validation, token or session handling, and the exact point where trust is established server-side.",
                confidence="medium",
            )
        )

    if public_integration_surfaces and not any(h.hint in {"jwt", "oauth", "bearer", "token"} for h in scan.auth_hints):
        findings.append(
            Finding(
                title="Public routes appear to influence outbound integrations without clear auth signals",
                severity="medium",
                evidence=[_finding_evidence(surface) for surface in public_integration_surfaces[:10]],
                mitigation="Check how outbound requests are authenticated, signed, and authorized, and confirm that untrusted route input cannot directly steer third-party actions.",
                confidence="medium",
            )
        )

    if scan.secret_hints:
        findings.append(
            Finding(
                title="Secret-bearing environment variables are referenced in executable paths",
                severity="medium",
                evidence=[f"{hint.name} in {hint.file}" for hint in scan.secret_hints[:10]],
                mitigation="Confirm these secrets are injected securely, never logged or returned, rotated regularly, and scoped only to the privileges each route actually needs.",
                confidence="high",
            )
        )

    if public_data_surfaces:
        findings.append(
            Finding(
                title="Public routes likely sit close to sensitive data operations",
                severity="medium",
                evidence=[_finding_evidence(surface) for surface in public_data_surfaces[:10]],
                mitigation="Validate untrusted input before it reaches business logic, enforce authorization at the route boundary, and verify that downstream queries or writes stay parameterized.",
                confidence="medium",
            )
        )

    if atproto_chains:
        top_atproto_chain = atproto_chains[0]
        findings.append(
            Finding(
                title="AT Protocol XRPC surface chains into a downstream trust boundary",
                severity="high" if top_atproto_chain.sink in {"database", "privileged downstream action"} else "medium",
                evidence=[f"confidence={top_atproto_chain.confidence:.2f}", *top_atproto_chain.evidence[:6]],
                mitigation=(
                    "Enforce namespace-specific authz on XRPC handlers, validate service-auth at each hop, and constrain "
                    "downstream service/database permissions per endpoint."
                ),
                confidence="high" if top_atproto_chain.confidence >= 0.7 else "medium",
            )
        )

    if service_chains:
        top_service_chain = service_chains[0]
        findings.append(
            Finding(
                title="Inter-service trust chain reaches a sensitive downstream sink",
                severity="high" if top_service_chain.sink in {"database", "privileged downstream action"} else "medium",
                evidence=[f"confidence={top_service_chain.confidence:.2f}", *top_service_chain.evidence[:6]],
                mitigation=(
                    "Apply explicit authn/authz checks at each service hop, constrain service-to-service callers, and "
                    "treat env-configured upstream and downstream endpoints as untrusted until verified."
                ),
                confidence="high" if top_service_chain.confidence >= 0.7 else "medium",
            )
        )

    if chains:
        top_chain = chains[0]
        findings.append(
            Finding(
                title="Framework route-to-service chain reaches a sensitive sink",
                severity="high" if top_chain.sink in {"database", "privileged action"} else "medium",
                evidence=[f"confidence={top_chain.confidence:.2f}", *top_chain.evidence[:6]],
                mitigation=(
                    "Validate and authorize at the route boundary, enforce controller-level policy checks, and gate "
                    "service/factory entry points before database writes or privileged actions."
                ),
                confidence="high" if top_chain.confidence >= 0.7 else "medium",
            )
        )

    if not findings:
        findings.append(
            Finding(
                title="Heuristic scan found only a limited attack surface",
                severity="low",
                evidence=["No major route, secret, or integration patterns triggered a stronger finding."],
                mitigation="Treat this as a weak signal, expand parser coverage, and manually validate the real entry points and trust boundaries.",
                confidence="low",
            )
        )

    return sorted(findings, key=lambda finding: (_severity_rank(finding.severity), finding.title))


def generate_attack_paths(scan: ScanResult, attack_surfaces: list[AttackSurface] | None = None) -> list[AttackPath]:
    """
    Generate plausible attacker-centric paths from recon signals.

    If `attack_surfaces` is provided, reuse it to avoid redundant surface
    recomputation in callers that already translated recon -> surface.
    """
    surfaces_source = attack_surfaces if attack_surfaces is not None else identify_attack_surfaces(scan)
    surfaces = [surface for surface in surfaces_source if not _is_low_quality_source(surface.file)]
    atproto_chains = _build_atproto_chains(scan)
    service_chains = _build_service_chains(scan)
    chains = _build_probable_chains(scan) if _is_framework_mvc_scan(scan) else []

    if atproto_chains:
        top_chain = atproto_chains[0]
        chain_label = (
            f"{top_chain.entry_service} -> {top_chain.next_service}"
            if top_chain.next_service
            else top_chain.entry_service
        )
        steps = [
            _action_step(
                "Entry",
                f"Attacker reaches {top_chain.route_method} {top_chain.route_path} in {top_chain.route_file}",
            ),
            _action_step("Namespace", f"Endpoint is exposed in AT Protocol namespace `{top_chain.namespace}`"),
            _action_step("Service entry", f"XRPC request is handled by service `{top_chain.entry_service}`"),
        ]
        if top_chain.next_service:
            steps.append(
                _action_step(
                    "Propagation",
                    f"Service trust edge allows request influence to reach `{top_chain.next_service}`",
                )
            )
        if top_chain.env_risk:
            steps.append(
                _action_step(
                    "Config risk",
                    f"Runtime behavior depends on env-configured endpoint {top_chain.env_risk}, which can widen downstream trust exposure",
                )
            )
        steps.extend(
            [
                _action_step("Sink", f"Influence reaches {top_chain.sink} through protocol-driven service flow"),
                _action_step("Evidence", f"confidence={top_chain.confidence:.2f}; {'; '.join(top_chain.evidence[:4])}"),
            ]
        )
        return [
            AttackPath(
                name="AT Protocol namespace trust-chain abuse",
                steps=steps,
                impact=(
                    f"An exposed XRPC namespace can be abused to propagate across `{chain_label}` and affect {top_chain.sink} "
                    "when per-namespace authorization and inter-service trust controls are weak."
                ),
            )
        ]

    if service_chains:
        top_chain = service_chains[0]
        chain_label = (
            f"{top_chain.entry_service} -> {top_chain.next_service}"
            if top_chain.next_service
            else top_chain.entry_service
        )
        steps = [
            _action_step(
                "Entry",
                f"Attacker reaches {top_chain.route_method} {top_chain.route_path} in {top_chain.route_file}",
            ),
            _action_step("Service entry", f"Request is handled by service `{top_chain.entry_service}`"),
        ]
        if top_chain.next_service:
            steps.append(
                _action_step(
                    "Propagation",
                    f"Service-to-service trust edge allows request influence to reach `{top_chain.next_service}`",
                )
            )
        if top_chain.env_risk:
            steps.append(
                _action_step(
                    "Config risk",
                    f"Runtime behavior depends on env-configured endpoint {top_chain.env_risk}, which can widen trust assumptions if misconfigured",
                )
            )
        steps.extend(
            [
                _action_step(
                    "Sink",
                    f"Influence reaches {top_chain.sink}, creating a plausible unauthorized downstream action path",
                ),
                _action_step(
                    "Evidence",
                    f"confidence={top_chain.confidence:.2f}; {'; '.join(top_chain.evidence[:4])}",
                ),
            ]
        )
        return [
            AttackPath(
                name="Distributed service trust-chain abuse",
                steps=steps,
                impact=(
                    f"A public API foothold can propagate across `{chain_label}` and affect {top_chain.sink} "
                    "if service boundaries or downstream trust checks are weak."
                ),
            )
        ]

    if chains:
        top_chain = chains[0]
        controller_text = top_chain.controller or "framework controller mapping"
        service_text = top_chain.service or "framework service/factory"
        action_text = top_chain.action or "application action"
        sink_text = top_chain.sink
        evidence_text = "; ".join(top_chain.evidence[:4])
        return [
            AttackPath(
                name="Framework route-to-sink attack chain",
                steps=[
                    _action_step(
                        "Entry",
                        f"Attacker reaches {top_chain.route_method} {top_chain.route_path} in {top_chain.route_file}",
                    ),
                    _action_step("Routing", f"Framework route config maps request toward {controller_text} ({action_text})"),
                    _action_step("Execution", f"Controller path likely invokes {service_text}"),
                    _action_step(
                        "Sink",
                        f"Request influence reaches {sink_text}, creating an opportunity for unauthorized state change or abuse",
                    ),
                    _action_step("Evidence", f"confidence={top_chain.confidence:.2f}; {evidence_text}"),
                ],
                impact=(
                    "A public request can be chained through framework routing and service execution to sensitive operations "
                    "if boundary validation and authorization checks are weak or misplaced."
                ),
            )
        ]

    # Basic archetypes append rather than early-return. A single scan can
    # surface multiple distinct attack-path archetypes — see #24. Each
    # archetype consumes one surface; we dedup by surface identity so the
    # same route doesn't anchor two paths.
    webhook_surface = next((surface for surface in surfaces if surface.category == "webhook"), None)
    admin_surface = next((surface for surface in surfaces if surface.category == "admin"), None)
    auth_surface = next((surface for surface in surfaces if surface.category == "auth"), None)
    upload_surface = next((surface for surface in surfaces if surface.category == "upload"), None)
    public_data_surface = next(
        (surface for surface in surfaces if surface.exposure == "public" and surface.data_store_interaction and surface.category != "health"),
        None,
    )
    integration_surface = next(
        (surface for surface in surfaces if surface.exposure == "public" and surface.outbound_integration),
        None,
    )

    paths: list[AttackPath] = []
    consumed: set[tuple[str, str, str]] = set()

    def _surface_key(surface: AttackSurface) -> tuple[str, str, str]:
        return (surface.file, surface.route, surface.method)

    def _claim(surface: AttackSurface | None) -> bool:
        if surface is None:
            return False
        key = _surface_key(surface)
        if key in consumed:
            return False
        consumed.add(key)
        return True

    if webhook_surface and (public_data_surface or integration_surface) and _claim(webhook_surface):
        # Webhooks consume their downstream propagation surface so the
        # public-data / integration archetypes don't also fire on the
        # same route.
        if public_data_surface:
            _claim(public_data_surface)
        if integration_surface:
            _claim(integration_surface)
        steps = [
            _action_step("Entry", f"An attacker reaches {webhook_surface.method} {webhook_surface.route} in {webhook_surface.file}, a webhook-style endpoint that accepts untrusted inbound events"),
            _action_step("Weak point", "The endpoint is treated like a trusted integration boundary before its input is fully verified"),
        ]
        if public_data_surface:
            steps.append(_action_step("Propagation", "Attacker-controlled input is processed close to a data store, making unauthorized writes or state changes plausible"))
        if integration_surface:
            steps.append(_action_step("Propagation", "The same request path can also influence outbound service calls, which widens the blast radius beyond the application itself"))
        steps.append(_action_step("Impact", "The attacker drives business actions that should only occur after a trusted event or validated request"))
        paths.append(
            AttackPath(
                name="External event spoofing into internal state change",
                steps=steps,
                impact="Unauthorized state changes can be triggered from the internet and then propagated into internal data or downstream systems.",
            )
        )

    if _claim(admin_surface):
        paths.append(
            AttackPath(
                name="Administrative route abuse",
                steps=[
                    _action_step("Entry", f"An attacker reaches {admin_surface.method} {admin_surface.route} in {admin_surface.file}, a route associated with privileged behavior"),
                    _action_step("Weak point", "Authentication or authorization around that route is bypassed, reused, or enforced too late"),
                    _action_step("Propagation", "Administrative actions execute with attacker influence and affect higher-value parts of the system"),
                    _action_step("Impact", "Privileged changes, sensitive data access, or configuration abuse follow from a single foothold"),
                ],
                impact="Privilege escalation or destructive administrative actions from a route that should be tightly controlled.",
            )
        )

    if _claim(auth_surface):
        paths.append(
            AttackPath(
                name="Authentication boundary bypass",
                steps=[
                    _action_step("Entry", f"An attacker targets {auth_surface.method} {auth_surface.route} in {auth_surface.file}, which controls login, tokens, or session state"),
                    _action_step("Weak point", "Credential handling, token validation, or session establishment is weaker than the route implies"),
                    _action_step("Propagation", "The attacker converts that weakness into an authenticated foothold"),
                    _action_step("Impact", "The foothold becomes the starting point for deeper movement into protected application behavior"),
                ],
                impact="Account takeover or a trusted session that opens access to additional internal actions.",
            )
        )

    if _claim(upload_surface):
        paths.append(
            AttackPath(
                name="Untrusted file handling abuse",
                steps=[
                    _action_step("Entry", f"An attacker submits content to {upload_surface.method} {upload_surface.route} in {upload_surface.file}"),
                    _action_step("Weak point", "The application accepts or parses attacker-controlled files too broadly"),
                    _action_step("Propagation", "Storage, parsing, or downstream consumers treat that content as safer than it is"),
                    _action_step("Impact", "The result is execution, persistence of malicious content, or operational disruption"),
                ],
                impact="Stored malicious content, parser abuse, or denial of service from untrusted file input.",
            )
        )

    if _claim(public_data_surface):
        paths.append(
            AttackPath(
                name="Public input into sensitive data path",
                steps=[
                    _action_step("Entry", f"An attacker uses {public_data_surface.method} {public_data_surface.route} in {public_data_surface.file} as a public foothold"),
                    _action_step("Weak point", "Input validation or authorization is weaker than the route exposure suggests"),
                    _action_step("Propagation", "Attacker-controlled data reaches code operating close to the data store"),
                    _action_step("Impact", "Confidentiality, integrity, or authorization guarantees around application data are weakened"),
                ],
                impact="Unauthorized data access or modification through a public-facing application route.",
            )
        )

    if _claim(integration_surface):
        paths.append(
            AttackPath(
                name="Outbound trust boundary abuse",
                steps=[
                    _action_step("Entry", f"An attacker influences {integration_surface.method} {integration_surface.route} in {integration_surface.file}, which sits near an outbound integration"),
                    _action_step("Weak point", "The application assumes too much trust in external calls or responses"),
                    _action_step("Propagation", "Spoofed, replayed, or attacker-steered third-party interactions affect internal logic"),
                    _action_step("Impact", "Unsafe business decisions or downstream actions follow from a weak external trust boundary"),
                ],
                impact="Poisoned state or unsafe downstream actions caused by over-trusting an external dependency.",
            )
        )

    # Cap to keep report output focused; if more than this fires, the
    # extras are usually redundant noise that downstream review surfaces
    # via findings anyway.
    return paths[:MAX_ATTACK_PATHS]
