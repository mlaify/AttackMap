from __future__ import annotations

from dataclasses import dataclass

from .analyzer import identify_attack_surfaces
from .exploitability import best_by_sink_kind, score_exploitability
from .models import AttackPath, AttackSurface, AttackTechnique, Finding, Route, ScanResult, TaintChain
from .route_auth_fusion import synthesize_unauthenticated_routes

LOW_QUALITY_SEGMENTS = ("/tests/", "/__tests__/", "/fixtures/", "/mocks/", "/examples/")

# Cap on the number of basic-archetype attack paths emitted per scan.
# Lifted from 1 in #24; capped here to keep reports focused — anything
# beyond the top few is typically redundant with what findings already
# surface. Chain-archetype paths (atproto / service / framework) emit
# alone and don't count toward this cap.
MAX_ATTACK_PATHS = 5

# Per-archetype fan-out cap (#5). When multiple distinct files satisfy
# an archetype (e.g. three different public-data routes each writing
# to their own datastore), emit one path per file up to this many.
# Keeps the multi-vector story visible without exploding into noise.
MAX_PER_ARCHETYPE_FANOUT = 3


def _surface_label(surface: AttackSurface) -> str:
    return f"{surface.method} {surface.route} in {surface.file}"


def _severity_rank(value: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(value, 3)


# #4: prioritization scoring. Higher score = triage first within severity.
# Formula: severity_weight × confidence_multiplier, rounded to int.
_SEVERITY_WEIGHT = {"high": 100, "medium": 50, "low": 10}
_CONFIDENCE_MULTIPLIER = {"high": 1.0, "medium": 0.75, "low": 0.5}


def compute_finding_score(severity: str, confidence: str) -> int:
    """Compute the prioritization score for a finding.

    Range: 5 (low/low) to 100 (high/high). Used as a secondary sort key
    inside a severity band so a HIGH/HIGH lands above a HIGH/LOW.
    """
    return int(_SEVERITY_WEIGHT.get(severity, 0) * _CONFIDENCE_MULTIPLIER.get(confidence, 0.5))


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


def _distinct_by_file(
    surfaces: list[AttackSurface],
    predicate,
    limit: int,
) -> list[AttackSurface]:
    """Return the first `limit` surfaces matching `predicate`, one per file.

    Used by #5 fan-out so a repo with three public-data routes in three
    different files each produces its own concrete path — while three
    routes in the same file collapse to one (same story anyway).
    """
    picked: list[AttackSurface] = []
    seen_files: set[str] = set()
    for surface in surfaces:
        if not predicate(surface):
            continue
        if surface.file in seen_files:
            continue
        seen_files.add(surface.file)
        picked.append(surface)
        if len(picked) >= limit:
            break
    return picked


def _same_file_datastore(surface: AttackSurface, scan: ScanResult) -> tuple[str, str] | None:
    """Return `(kind, file)` of a datastore in the same file as the surface,
    or None. Used by #5 to make Propagation steps name the concrete sink."""
    for hint in scan.databases:
        if hint.file == surface.file:
            return (hint.kind, hint.file)
    return None


def _same_file_external(surface: AttackSurface, scan: ScanResult) -> tuple[str, str] | None:
    """Return `(target, file)` of an external call in the same file as the
    surface, or None. #5 narrative enrichment."""
    for call in scan.external_calls:
        if call.file == surface.file:
            return (call.target, call.file)
    return None


def _surface_evidence(surface: AttackSurface, scan: ScanResult, max_items: int = 4) -> list[str]:
    """Collect concrete evidence tied to a surface — same-file signals only.

    Used by basic-archetype attack paths to anchor their narrative in
    specific databases, external calls, and secrets present in the same
    file as the entry surface, rather than emitting a generic 4-step
    story. Keeps the evidence chain narrow and defensible: if it's in
    the same file as the vulnerable route, we can cite it without
    speculating about how signals connect.
    """
    evidence: list[str] = []
    for hint in scan.databases:
        if hint.file == surface.file:
            evidence.append(f"data store in same file: {hint.kind} ({hint.file})")
    for call in scan.external_calls:
        if call.file == surface.file:
            evidence.append(f"external call in same file: {call.target} ({call.file})")
    for secret in scan.secret_hints:
        if secret.file == surface.file:
            evidence.append(f"env-configured secret in same file: {secret.name} ({secret.file})")
    return evidence[:max_items]


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


def _provenance_by_hint(scan: ScanResult) -> dict[str, str]:
    """Index hint text -> `source_analyzer` across framework/auth hints.

    Used by the chain linker (#13) to name the analyzer that produced
    each contributing signal in the emitted evidence line. Empty dict
    when no signals carry provenance (e.g. hand-constructed test scans).
    """
    index: dict[str, str] = {}
    for hint_list in (scan.framework_hints, scan.auth_hints):
        for hint in hint_list:
            src = getattr(hint, "source_analyzer", None)
            if src and hint.hint not in index:
                index[hint.hint] = src
    return index


def _cited(label: str, value: str, provenance: dict[str, str], hint_key: str) -> str:
    """Format `label: value` and append `[via <analyzer>]` when provenance exists."""
    source = provenance.get(hint_key)
    base = f"{label}: {value}"
    return f"{base} [via {source}]" if source else base


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


def confidence_bucket(value: float) -> str:
    """Bucket a numeric confidence into the low/medium/high labels #13 asks
    for. Thresholds picked so a bare route+sink lands in `low`, a chain
    with controller+sink lands in `medium`, and a chain that also picks
    up an Omeka/Laminas framework signal (extension or dependency hint)
    lands in `high`.
    """
    if value >= 0.75:
        return "high"
    if value >= 0.55:
        return "medium"
    return "low"


_TAINT_SINK_LABEL: dict[str, str] = {
    "sql_execute": "database (SQL execute)",
    "subprocess_shell": "command execution",
    "eval": "code eval",
    "exec": "code exec",
    "dynamic_open": "filesystem open",
    "unsafe_deserialization": "unsafe deserialization",
    "ssti": "template injection",
    "ssrf": "outbound request (SSRF)",
    "nosql_injection": "NoSQL query",
    "open_redirect": "redirect target",
}


# Per-sink-kind specification for the dedicated taint findings (#68).
# Each dangerous sink kind reachable from a route produces one aggregated
# Finding. `severity` is the Finding severity; `technique` is an ATT&CK
# reference. Sinks NOT in this table (sql_execute, dynamic_open) are
# surfaced through the probable-chain finding path instead of a dedicated
# finding.
_TAINT_FINDING_SPEC: dict[str, dict[str, str]] = {
    "eval": {
        "severity": "high",
        "title": "Request-reachable code execution via eval",
        "mitigation": "Never pass request-derived data to eval. Use a domain-specific parser or an explicit allow-list of operations.",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
    "exec": {
        "severity": "high",
        "title": "Request-reachable code execution via exec",
        "mitigation": "Never pass request-derived data to exec. Refactor to call named functions selected via a validated allow-list.",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
    "subprocess_shell": {
        "severity": "high",
        "title": "Request-reachable OS command execution",
        "mitigation": "Prefer argv-list subprocess calls with shell=False. Never interpolate request data into a shell string; validate and constrain any external command inputs.",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
    "unsafe_deserialization": {
        "severity": "high",
        "title": "Request-reachable unsafe deserialization",
        "mitigation": "Do not deserialize attacker-controlled data with pickle/marshal/yaml.load/ObjectInputStream/unserialize. Use a data-only format (JSON) with a schema, or a safe loader (yaml.safe_load).",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
    "ssti": {
        "severity": "high",
        "title": "Request-reachable server-side template injection",
        "mitigation": "Never render request-derived strings as templates. Pass untrusted data as template *variables* (auto-escaped), not as the template source.",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
    "ssrf": {
        "severity": "medium",
        "title": "Request-reachable server-side request forgery (SSRF)",
        "mitigation": "Validate and allow-list outbound destinations, resolve and pin DNS, block link-local/metadata ranges (169.254.0.0/16, fd00::/8), and disable redirects to internal hosts.",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "nosql_injection": {
        "severity": "medium",
        "title": "Request-reachable NoSQL injection",
        "mitigation": "Never pass a raw request object as a query filter. Cast and validate each field, reject operator keys ($where, $gt, ...) in user input, and disable server-side JavaScript execution.",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "open_redirect": {
        "severity": "medium",
        "title": "Request-reachable open redirect",
        "mitigation": "Never redirect to a request-derived URL directly. Redirect only to a server-side allow-list of paths/hosts, or map an opaque key to the destination; reject absolute URLs and protocol-relative (`//`) targets.",
        "technique_id": "T1204",
        "technique_name": "User Execution",
        "tactic": "Execution",
    },
}


# Per-kind spec for insecure-crypto findings (#70). One aggregated
# finding per crypto weakness kind present in the scan.
_CRYPTO_FINDING_SPEC: dict[str, dict[str, str]] = {
    "weak_password_hash": {
        "severity": "high",
        "title": "Weak password hashing (MD5/SHA-1)",
        "mitigation": "Hash passwords with a memory-hard KDF — argon2id, scrypt, or bcrypt — never a bare MD5/SHA-1/SHA-256 digest. Migrate existing hashes on next login.",
        "technique_id": "T1110.002",
        "technique_name": "Brute Force: Password Cracking",
        "tactic": "Credential Access",
    },
    "weak_cipher": {
        "severity": "high",
        "title": "Weak or broken cipher (DES/3DES/RC4/Blowfish)",
        "mitigation": "Replace legacy ciphers with AES-256-GCM (or ChaCha20-Poly1305). DES/3DES/RC4 are cryptographically broken.",
        "technique_id": "T1600",
        "technique_name": "Weaken Encryption",
        "tactic": "Defense Evasion",
    },
    "ecb_mode": {
        "severity": "medium",
        "title": "Insecure ECB block-cipher mode",
        "mitigation": "ECB leaks plaintext structure. Use an authenticated mode (AES-GCM) with a unique per-message nonce; in Java, always specify the transformation explicitly (e.g. \"AES/GCM/NoPadding\").",
        "technique_id": "T1600",
        "technique_name": "Weaken Encryption",
        "tactic": "Defense Evasion",
    },
    "static_iv_salt": {
        "severity": "medium",
        "title": "Hard-coded IV or salt",
        "mitigation": "Generate the IV/nonce and salt randomly per operation with a CSPRNG and store/transmit them alongside the ciphertext. A static IV/salt defeats the primitive's security.",
        "technique_id": "T1600",
        "technique_name": "Weaken Encryption",
        "tactic": "Defense Evasion",
    },
    "insecure_random": {
        "severity": "medium",
        "title": "Insecure randomness for a security value",
        "mitigation": "Use a CSPRNG for tokens/keys/salts/nonces/OTPs: `secrets` (Python), `crypto.randomBytes` (Node), `crypto/rand` (Go). `Math.random`/`random`/`rand`/`mt_rand` are predictable.",
        "technique_id": "T1600",
        "technique_name": "Weaken Encryption",
        "tactic": "Defense Evasion",
    },
    "insecure_tls": {
        "severity": "high",
        "title": "TLS certificate/hostname verification disabled",
        "mitigation": "Never disable certificate or hostname verification (`verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify: true`) or use deprecated TLS/SSL versions. Fix the trust store instead of turning off validation.",
        "technique_id": "T1557",
        "technique_name": "Adversary-in-the-Middle",
        "tactic": "Credential Access",
    },
}


# Per-kind spec for web-hardening findings (#71).
_WEB_HARDENING_FINDING_SPEC: dict[str, dict[str, str]] = {
    "cors_wildcard_credentials": {
        "severity": "high",
        "title": "CORS allows credentials with a wildcard/reflected origin",
        "mitigation": "Never combine `Access-Control-Allow-Credentials: true` with a `*` or reflected origin. Allow-list explicit trusted origins; if credentials aren't needed, drop the credentials flag.",
        "technique_id": "T1539",
        "technique_name": "Steal Web Session Cookie",
        "tactic": "Credential Access",
    },
    "csrf_disabled": {
        "severity": "medium",
        "title": "CSRF protection disabled or exempted",
        "mitigation": "Keep CSRF protection on for cookie-authenticated, state-changing routes. If an endpoint is a token-authenticated API that legitimately doesn't need it, scope the exemption narrowly and document why.",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "insecure_cookie": {
        "severity": "medium",
        "title": "Session cookie set without secure flags",
        "mitigation": "Set `HttpOnly`, `Secure`, and `SameSite=Lax` (or `Strict`) on session cookies. `SameSite=None` must always be paired with `Secure`.",
        "technique_id": "T1539",
        "technique_name": "Steal Web Session Cookie",
        "tactic": "Credential Access",
    },
    "weak_csp": {
        "severity": "medium",
        "title": "Content-Security-Policy allows unsafe-inline/unsafe-eval",
        "mitigation": "Remove `'unsafe-inline'` and `'unsafe-eval'` from the CSP; use nonces or hashes for inline scripts. These directives largely defeat CSP's XSS protection.",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "debug_enabled": {
        "severity": "medium",
        "title": "Debug mode or unrestricted management endpoints enabled",
        "mitigation": "Never ship with debug mode on (Flask/Django `DEBUG`, Rails `consider_all_requests_local`) or Spring actuator endpoints exposed with `*`. Debug consoles leak internals and can enable RCE.",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
}


# Per-kind spec for novel vuln-class findings (#77).
_CODE_WEAKNESS_FINDING_SPEC: dict[str, dict[str, str]] = {
    "prototype_pollution": {
        "severity": "high",
        "title": "Prototype pollution",
        "mitigation": "Never write attacker-controlled keys to `__proto__`/`constructor.prototype` or deep-merge a raw request object. Use a null-prototype object (`Object.create(null)`), a Map, or a merge that rejects `__proto__`/`constructor` keys.",
        "technique_id": "T1059.007",
        "technique_name": "Command and Scripting Interpreter: JavaScript",
        "tactic": "Execution",
    },
    "mass_assignment": {
        "severity": "high",
        "title": "Mass assignment / overposting",
        "mitigation": "Never bind a whole request body to a model. Explicitly allow-list assignable fields (serializers, DTOs, strong params with a field list) so attackers can't set privileged attributes (is_admin, role, owner_id).",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "jwt_weakness": {
        "severity": "high",
        "title": "JWT verification weakness (alg=none / signature not verified)",
        "mitigation": "Pin an explicit allow-list of signing algorithms (never include `none`), always verify the signature, and reject tokens whose header `alg` isn't expected. Don't decode without verifying.",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "xxe": {
        "severity": "high",
        "title": "XML external entity (XXE) processing enabled",
        "mitigation": "Disable DTD/external-entity resolution in the XML parser (lxml `resolve_entities=False`, Java `disallow-doctype-decl`/secure processing, PHP keep `libxml_disable_entity_loader` default). Prefer a data format without entities where possible.",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "redos": {
        "severity": "medium",
        "title": "Regular expression vulnerable to catastrophic backtracking (ReDoS)",
        "mitigation": "Rewrite the pattern to avoid nested quantifiers ((a+)+, (.*)*) and ambiguous alternation; use possessive quantifiers/atomic groups, a linear-time engine (RE2), or cap the length of user-supplied strings matched against it.",
        "technique_id": "T1499",
        "technique_name": "Endpoint Denial of Service",
        "tactic": "Impact",
    },
    "insecure_upload": {
        "severity": "high",
        "title": "Uploaded file persisted with a client-controlled name/path",
        "mitigation": "Never derive the stored path from the client filename. Generate a server-side name, store outside the web root, validate content type/size, and strip path separators before use.",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "graphql_exposure": {
        "severity": "low",
        "title": "GraphQL introspection / playground enabled",
        "mitigation": "Disable introspection and the GraphiQL/playground UI in production, and add query depth/complexity limits to prevent schema disclosure and expensive-query DoS.",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
}


# Rank for picking the most severe issue in an aggregated group.
_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


# CI-workflow security (#142). Severity is taken from the emitted issues (some
# kinds tier per instance — e.g. unpinned semver tag vs. branch ref), so the
# spec carries only the taxonomy, title, remediation, and ATT&CK mapping.
_WORKFLOW_FINDING_SPEC: dict[str, dict[str, str]] = {
    "script_injection": {
        "title": "CI script injection via untrusted context in a run: step",
        "mitigation": "Never interpolate `${{ github.event.* }}` / `github.head_ref` directly into a run: script — a crafted issue/PR title or branch name runs arbitrary shell. Bind the value to an `env:` variable and reference it as `\"$ENVVAR\"` so it's passed as data, not expanded into the command.",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
    "pr_target_checkout": {
        "title": "pull_request_target checks out untrusted PR code",
        "mitigation": "`pull_request_target` runs with the base repo's secrets in scope. Don't check out and build the PR head ref in that context. Use `pull_request` for untrusted code, or check out only the base ref and never run fork-supplied build/test scripts with secrets available.",
        "technique_id": "T1195",
        "technique_name": "Supply Chain Compromise",
        "tactic": "Initial Access",
    },
    "unpinned_action": {
        "title": "Unpinned GitHub Action (not pinned to a commit SHA)",
        "mitigation": "Pin third-party actions to a full 40-character commit SHA (`uses: org/action@<sha>`), not a moving tag or branch. A tag/branch lets the action owner — or anyone who compromises them — change what runs in your pipeline. Dependabot can keep the pinned SHAs updated.",
        "technique_id": "T1195.001",
        "technique_name": "Supply Chain Compromise: Compromise Software Dependencies and Development Tools",
        "tactic": "Initial Access",
    },
    "secret_in_run": {
        "title": "Secret interpolated into a run: shell step",
        "mitigation": "Don't expand `${{ secrets.* }}` directly into a run: script — it can leak via the command line (`ps`), step logs, or a child process. Pass the secret through the step's `env:` block and reference it as an environment variable.",
        "technique_id": "T1552",
        "technique_name": "Unsecured Credentials",
        "tactic": "Credential Access",
    },
    "broad_permissions": {
        "title": "Over-broad GITHUB_TOKEN permissions (write-all)",
        "mitigation": "Set least-privilege `permissions:` per job (default to `contents: read` and grant only what a job needs). `write-all` gives a compromised step or action full write access to the repo, releases, packages, and more.",
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Privilege Escalation",
    },
    "self_hosted_pr": {
        "title": "Self-hosted runner exposed to pull-request code",
        "mitigation": "Self-hosted runners on a `pull_request`/`pull_request_target` trigger let fork PRs run arbitrary code on your infrastructure (and persist between jobs). Use ephemeral GitHub-hosted runners for public-repo PR workflows, or gate self-hosted jobs behind an environment/approval and never on `pull_request_target`.",
        "technique_id": "T1584.004",
        "technique_name": "Compromise Infrastructure: Server",
        "tactic": "Resource Development",
    },
}


_ANOMALY_FINDING_SPEC: dict[str, dict[str, str]] = {
    "auth_outlier": {
        "severity": "high",
        "title": "Authorization outlier — route missing an auth check its siblings enforce",
        "mitigation": "Confirm whether the flagged route is intended to be public. If not, apply the same auth/authorization guard its sibling routes use (decorator, middleware, or policy). Inconsistent enforcement across a resource cohort is a common source of broken access control.",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "validation_outlier": {
        "severity": "medium",
        "title": "Validation outlier — handler skips input validation its peers apply",
        "mitigation": "Apply the same input validation/schema its sibling handlers use. An unvalidated state-changing endpoint among validated peers is a likely gap for injection or malformed-input bugs.",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "method_outlier": {
        "severity": "medium",
        "title": "Method outlier — lone state-changing endpoint in a read-only cohort",
        "mitigation": "Verify the state-changing endpoint is intended and adequately protected. A single write method among an otherwise read-only resource cohort can indicate an accidentally-exposed mutation.",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "invariant_violation": {
        "severity": "high",
        "title": "Invariant violation — handler reaches a dangerous sink without the guard its peers apply",
        "mitigation": "Confirm whether the flagged handler should reach this sink unguarded. If not, apply the same auth/validation guard its sibling handlers place before the sink. A mined invariant broken by a single site is a common shape for a forgotten check on an injection or access-control path.",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
}


def _numeric_to_confidence(value: float) -> str:
    """Map an anomaly's numeric confidence onto the Finding scale."""
    if value >= 0.75:
        return "high"
    if value >= 0.55:
        return "medium"
    return "low"


def _taint_by_route_file(scan: ScanResult) -> dict[str, list[TaintChain]]:
    """Group taint chains by originating route file for fast lookup."""
    out: dict[str, list[TaintChain]] = {}
    for chain in scan.taint_chains:
        out.setdefault(chain.route_file, []).append(chain)
    return out


def _best_taint_for_route(
    route: Route, taint_by_file: dict[str, list[TaintChain]]
) -> TaintChain | None:
    candidates = [
        c
        for c in taint_by_file.get(route.file, ())
        if c.route_path == route.path
        and c.route_method == route.method
        and not c.sanitized  # #137: a neutralized path isn't a probable exploit
    ]
    if not candidates:
        return None
    # Prefer the closest sink (fewest import hops); break ties by confidence.
    return min(candidates, key=lambda c: (c.hops, -c.confidence))


def _build_probable_chains(scan: ScanResult) -> list[ProbableChain]:
    controllers = _extract_prefixed_hints(scan, "controller:")
    services = _extract_prefixed_hints(scan, "service:")
    taint_by_file = _taint_by_route_file(scan)
    # Framework-family hints from the Omeka/Laminas analyzers. These aren't
    # required to build a chain but they *strengthen* the evidence when
    # present — see #13. Each contributes a small confidence bump and an
    # evidence line naming the file it came from.
    laminas_mappings = _extract_prefixed_hints(scan, "laminas_controller_mapping")
    laminas_deps = _extract_prefixed_hints(scan, "laminas_dependency")
    omeka_deps = _extract_prefixed_hints(scan, "omeka_dependency")
    omeka_extensions = _extract_prefixed_hints(scan, "omeka_extension:")
    omeka_surfaces = _extract_prefixed_hints(scan, "omeka_surface:")

    # Provenance index: hint value -> source_analyzer, so we can name the
    # analyzer that emitted each contributing signal in the chain evidence
    # (#14).
    provenance = _provenance_by_hint(scan)

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
                evidence.append(
                    _cited("controller inferred by module proximity", route_controller, provenance, f"controller:{route_controller}")
                )
        else:
            confidence += 0.25
            evidence.append(
                _cited("controller in same file", route_controller, provenance, f"controller:{route_controller}")
            )

        route_service = next((name for name, file in services if file == route.file), None)
        if route_service is None:
            route_service = next((name for name, file in services if _file_module_key(file) == module_key), None)
            if route_service:
                confidence += 0.10
                evidence.append(
                    _cited("service inferred by module proximity", route_service, provenance, f"service:{route_service}")
                )
        else:
            confidence += 0.20
            evidence.append(
                _cited("service in same file", route_service, provenance, f"service:{route_service}")
            )

        # Framework-family reinforcement. Each additional Omeka/Laminas
        # signal in the same module bumps confidence a little; a route
        # that lands on Omeka admin surface with an extension binding
        # ends up in the `high` bucket.
        for label, hints, weight, key_prefix in (
            ("laminas controller mapping", laminas_mappings, 0.05, "laminas_controller_mapping"),
            ("laminas dependency", laminas_deps, 0.03, "laminas_dependency"),
            ("omeka dependency", omeka_deps, 0.03, "omeka_dependency"),
            ("omeka extension binding", omeka_extensions, 0.05, "omeka_extension:"),
        ):
            same_module_hint = next(
                (name for name, file in hints if _file_module_key(file) == module_key),
                None,
            )
            if same_module_hint is not None:
                confidence += weight
                evidence.append(
                    _cited(label, same_module_hint or "(marker)", provenance, f"{key_prefix}{same_module_hint or ''}".rstrip(":"))
                )

        # Omeka surface (admin / api / site) classification. Doesn't
        # affect chain confidence directly — the route's surface risk is
        # handled elsewhere — but naming the surface in evidence gives
        # readers of the attack path a domain-shaped hook.
        omeka_surface = next(
            (name for name, file in omeka_surfaces if _file_module_key(file) == module_key),
            None,
        )
        if omeka_surface is not None:
            evidence.append(
                _cited("omeka surface classification", omeka_surface, provenance, f"omeka_surface:{omeka_surface}")
            )

        sink = "privileged action"
        best_taint = _best_taint_for_route(route, taint_by_file)
        if module_key in db_by_module:
            sink = "database"
            confidence += 0.2
            evidence.append(f"database hint in same module: {db_by_module[module_key].kind} ({db_by_module[module_key].file})")
        elif module_key in external_by_module:
            sink = "external integration"
            confidence += 0.15
            evidence.append(f"external call in same module: {external_by_module[module_key].target} ({external_by_module[module_key].file})")
        elif best_taint is not None:
            # Taint chain gives us a specific cross-file sink cite —
            # stronger than the "sink somewhere in repo" fallback (#45).
            sink = _TAINT_SINK_LABEL[best_taint.sink_kind]
            confidence += 0.15
            evidence.append(
                f"taint chain: {best_taint.sink_kind} at {best_taint.sink_file}:{best_taint.sink_line} "
                f"reachable in {best_taint.hops} import hop(s) via {' → '.join(best_taint.files)}"
            )
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

        # If we already attributed a same-module sink, taint chain still
        # corroborates — add it as evidence without re-shaping the sink.
        if best_taint is not None and sink not in {
            _TAINT_SINK_LABEL[best_taint.sink_kind],
            "privileged action",
        }:
            confidence += 0.05
            evidence.append(
                f"taint chain corroborates: {best_taint.sink_kind} at "
                f"{best_taint.sink_file}:{best_taint.sink_line} ({best_taint.hops} hop(s))"
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
                tags=["exposed-endpoint", "auth-missing"],
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
                tags=["exposed-endpoint", "auth-missing", "privileged"],
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
                tags=["exposed-endpoint", "input-handling"],
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
                tags=["exposed-endpoint", "auth-missing"],
            )
        )

    # Fuse per-route middleware/guard chains + auth_hints into precise
    # "unauthenticated state-changing route" findings (#140). Complements the
    # category-specific findings above (webhook/admin/upload/auth) by covering
    # the general public_api mutating-route case with per-route chain resolution.
    findings.extend(synthesize_unauthenticated_routes(scan, runtime_surfaces))

    if public_integration_surfaces and not any(h.hint in {"jwt", "oauth", "bearer", "token"} for h in scan.auth_hints):
        findings.append(
            Finding(
                title="Public routes appear to influence outbound integrations without clear auth signals",
                severity="medium",
                evidence=[_finding_evidence(surface) for surface in public_integration_surfaces[:10]],
                mitigation="Check how outbound requests are authenticated, signed, and authorized, and confirm that untrusted route input cannot directly steer third-party actions.",
                confidence="medium",
                tags=["integration-risk", "auth-missing"],
            )
        )

    # Split secret findings by kind (#39). Hard-coded literals get HIGH
    # severity — exposure is broader than env references (visible to
    # anyone with repo read access, not just runtime access) — and their
    # own tags so downstream triage and reporting can distinguish them.
    hardcoded_secrets = [h for h in scan.secret_hints if h.kind != "env_reference"]
    env_reference_secrets = [h for h in scan.secret_hints if h.kind == "env_reference"]

    if hardcoded_secrets:
        # Group by kind for evidence line density; still cap at 10 total.
        evidence_lines = [
            f"[{hint.kind}] {hint.name} in {hint.file}"
            for hint in hardcoded_secrets[:10]
        ]
        findings.append(
            Finding(
                title="Hard-coded secret literals were found in source or config",
                severity="high",
                evidence=evidence_lines,
                mitigation=(
                    "Rotate every detected credential immediately, purge it from git history, "
                    "and move to environment-injected or vault-managed values. Anyone with read "
                    "access to the repository already has these secrets."
                ),
                confidence="high",
                tags=["secret-exposure", "data-risk", "hardcoded-literal"],
            )
        )

    if env_reference_secrets:
        findings.append(
            Finding(
                title="Secret-bearing environment variables are referenced in executable paths",
                severity="medium",
                evidence=[f"{hint.name} in {hint.file}" for hint in env_reference_secrets[:10]],
                mitigation="Confirm these secrets are injected securely, never logged or returned, rotated regularly, and scoped only to the privileges each route actually needs.",
                confidence="high",
                tags=["secret-exposure"],
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
                tags=["exposed-endpoint", "data-risk"],
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
                tags=["atproto-chain", "data-risk"],
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
                tags=["service-chain", "data-risk"],
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
                tags=["framework-chain", "data-risk"],
            )
        )

    # #60 — CVE hits on SBOM entries. One Finding per vulnerable dep,
    # aggregating every advisory affecting it in the evidence list.
    vulns_by_pkg: dict[tuple[str, str, str], list] = {}
    for vuln in scan.vulnerabilities:
        vulns_by_pkg.setdefault(
            (vuln.ecosystem, vuln.package_name, vuln.package_version), []
        ).append(vuln)
    for (eco, name, version), pkg_vulns in vulns_by_pkg.items():
        top_severity = min(
            (_severity_rank(v.severity) for v in pkg_vulns), default=_severity_rank("medium")
        )
        title_severity_word = {0: "critical", 1: "moderate", 2: "low"}.get(top_severity, "moderate")
        evidence_lines: list[str] = []
        for v in sorted(pkg_vulns, key=lambda x: (_severity_rank(x.severity), x.id)):
            summary_snip = (v.summary[:120] + "…") if len(v.summary) > 120 else v.summary
            aliases = f" (aka {', '.join(v.aliases[:3])})" if v.aliases else ""
            score = f" CVSS {v.cvss_score:.1f}" if v.cvss_score is not None else ""
            ref = v.references[0] if v.references else ""
            ref_part = f" — {ref}" if ref else ""
            evidence_lines.append(
                f"{v.id}{aliases} [{v.severity}{score}]: {summary_snip}{ref_part}"
            )
        finding_severity = "high" if top_severity == 0 else ("medium" if top_severity == 1 else "low")
        # Transitive-dependency provenance (#143): cite the resolution path so a
        # reviewer can see the vulnerable package was pulled in indirectly.
        transitive = next((v for v in pkg_vulns if not v.direct), None)
        provenance_lines: list[str] = []
        if transitive is not None:
            if transitive.resolution_path:
                provenance_lines.append(
                    f"Transitive dependency — resolution path: {transitive.resolution_path}"
                )
            else:
                provenance_lines.append("Transitive (indirect) dependency")
        findings.append(
            Finding(
                title=f"Vulnerable dependency: {name}@{version} ({eco})",
                severity=finding_severity,  # type: ignore[arg-type]
                evidence=[
                    f"{len(pkg_vulns)} known advisor{'y' if len(pkg_vulns) == 1 else 'ies'} for "
                    f"{title_severity_word}-severity impact",
                    *provenance_lines,
                    *evidence_lines[:10],
                ],
                mitigation=(
                    f"Upgrade `{name}` beyond the affected range shown, verify no direct"
                    " or transitive callers depend on removed symbols, and re-run"
                    " `attackmap analyze --cve` to confirm the finding clears."
                ),
                confidence="high",
                tags=["cve", "dependency", eco],
            )
        )

    # Broken object-level authorization (BOLA/IDOR, #69). Routes with a
    # resource-id param that reach a datastore with no ownership check
    # nearby. Split into a HIGH finding for write methods and a MEDIUM
    # finding for reads, per the OWASP API #1 severity shape.
    bola = scan.authz_candidates
    if bola:
        # Object identifiers arrive via path params, query params, RPC methods
        # (XRPC/tRPC), or GraphQL fields (#139). A write is any mutating HTTP
        # verb or a GraphQL mutation.
        _write_methods = {"POST", "PUT", "PATCH", "DELETE", "MUTATION"}
        _surface_label = {
            "path_param": "path id",
            "query_param": "query param",
            "rpc_method": "RPC method",
            "graphql_field": "field arg",
        }
        write_candidates = [c for c in bola if c.route_method in _write_methods]
        read_candidates = [c for c in bola if c.route_method not in _write_methods]
        for group, severity, verb in (
            (write_candidates, "high", "modify"),
            (read_candidates, "medium", "read"),
        ):
            if not group:
                continue
            evidence = [
                f"{c.route_method} {c.route_path} "
                f"({_surface_label.get(c.surface, 'id')} `{c.id_param}`) "
                f"in {c.route_file} — {c.db_evidence}"
                for c in group[:10]
            ]
            if len(group) > 10:
                evidence.append(f"+{len(group) - 10} more route(s) with the same pattern")
            findings.append(
                Finding(
                    title=f"Possible broken object-level authorization (BOLA/IDOR) on {verb} routes",
                    severity=severity,  # type: ignore[arg-type]
                    evidence=evidence,
                    mitigation=(
                        "Enforce an object-level authorization check on every access: confirm the "
                        "authenticated principal owns or may access the requested resource id "
                        "server-side — scope the query by the caller's identity or evaluate a policy "
                        "— before reading or modifying the record. Never trust the id from the "
                        "request alone."
                    ),
                    confidence="medium",
                    tags=["broken-authorization", "exposed-endpoint", "data-risk"],
                    attack_techniques=[
                        AttackTechnique(
                            technique_id="T1190",
                            name="Exploit Public-Facing Application",
                            tactic="Initial Access",
                            url="https://attack.mitre.org/techniques/T1190/",
                        )
                    ],
                )
            )

    # Insecure crypto / weak randomness (#70). One aggregated finding per
    # weakness kind present, ordered by the spec's declaration.
    crypto_by_kind: dict[str, list] = {}
    for weakness in scan.crypto_weaknesses:
        crypto_by_kind.setdefault(weakness.kind, []).append(weakness)
    for kind, spec in _CRYPTO_FINDING_SPEC.items():
        items = crypto_by_kind.get(kind)
        if not items:
            continue
        evidence = [
            f"{w.file}:{w.line} — {w.evidence_text}" if w.evidence_text else f"{w.file}:{w.line}"
            for w in items[:10]
        ]
        if len(items) > 10:
            evidence.append(f"+{len(items) - 10} more occurrence(s)")
        findings.append(
            Finding(
                title=spec["title"],
                severity=spec["severity"],  # type: ignore[arg-type]
                evidence=evidence,
                mitigation=spec["mitigation"],
                confidence="medium",
                tags=["insecure-crypto"],
                attack_techniques=[
                    AttackTechnique(
                        technique_id=spec["technique_id"],
                        name=spec["technique_name"],
                        tactic=spec["tactic"],
                        url=f"https://attack.mitre.org/techniques/{spec['technique_id'].replace('.', '/')}/",
                    )
                ],
            )
        )

    # Web-hardening gaps (#71). One aggregated finding per issue kind.
    web_by_kind: dict[str, list] = {}
    for issue in scan.web_hardening_issues:
        web_by_kind.setdefault(issue.kind, []).append(issue)
    for kind, spec in _WEB_HARDENING_FINDING_SPEC.items():
        items = web_by_kind.get(kind)
        if not items:
            continue
        evidence = [
            f"{i.file}:{i.line} — {i.evidence_text}" if i.evidence_text else f"{i.file}:{i.line}"
            for i in items[:10]
        ]
        if len(items) > 10:
            evidence.append(f"+{len(items) - 10} more occurrence(s)")
        findings.append(
            Finding(
                title=spec["title"],
                severity=spec["severity"],  # type: ignore[arg-type]
                evidence=evidence,
                mitigation=spec["mitigation"],
                confidence="medium",
                tags=["web-hardening"],
                attack_techniques=[
                    AttackTechnique(
                        technique_id=spec["technique_id"],
                        name=spec["technique_name"],
                        tactic=spec["tactic"],
                        url=f"https://attack.mitre.org/techniques/{spec['technique_id'].replace('.', '/')}/",
                    )
                ],
            )
        )

    # Novel vuln classes (#77). One aggregated finding per weakness kind.
    code_by_kind: dict[str, list] = {}
    for weakness in scan.code_weaknesses:
        code_by_kind.setdefault(weakness.kind, []).append(weakness)
    for kind, spec in _CODE_WEAKNESS_FINDING_SPEC.items():
        items = code_by_kind.get(kind)
        if not items:
            continue
        evidence = [
            f"{i.file}:{i.line} — {i.evidence_text}" if i.evidence_text else f"{i.file}:{i.line}"
            for i in items[:10]
        ]
        if len(items) > 10:
            evidence.append(f"+{len(items) - 10} more occurrence(s)")
        findings.append(
            Finding(
                title=spec["title"],
                severity=spec["severity"],  # type: ignore[arg-type]
                evidence=evidence,
                mitigation=spec["mitigation"],
                confidence="medium",
                tags=["novel-vuln"],
                attack_techniques=[
                    AttackTechnique(
                        technique_id=spec["technique_id"],
                        name=spec["technique_name"],
                        tactic=spec["tactic"],
                        url=f"https://attack.mitre.org/techniques/{spec['technique_id'].replace('.', '/')}/",
                    )
                ],
            )
        )

    # CI workflow security (#142). One aggregated finding per issue kind; the
    # finding severity is the max over that kind's issues (some kinds tier per
    # instance — semver-tag vs. branch unpinned action, PR vs. PR-target runner).
    workflow_by_kind: dict[str, list] = {}
    for issue in scan.workflow_issues:
        workflow_by_kind.setdefault(issue.kind, []).append(issue)
    for kind, spec in _WORKFLOW_FINDING_SPEC.items():
        items = workflow_by_kind.get(kind)
        if not items:
            continue
        severity = max((i.severity for i in items), key=_SEVERITY_ORDER.__getitem__)
        evidence = []
        for i in items[:10]:
            loc = f"{i.file}:{i.line}" if i.line else i.file
            detail = f" — {i.evidence_text}" if i.evidence_text else ""
            ctx = f" [{i.context}]" if i.context else ""
            evidence.append(f"{loc}{ctx}{detail}")
        if len(items) > 10:
            evidence.append(f"+{len(items) - 10} more occurrence(s)")
        findings.append(
            Finding(
                title=spec["title"],
                severity=severity,  # type: ignore[arg-type]
                evidence=evidence,
                mitigation=spec["mitigation"],
                confidence="high",
                tags=["ci-security", "supply-chain"],
                attack_techniques=[
                    AttackTechnique(
                        technique_id=spec["technique_id"],
                        name=spec["technique_name"],
                        tactic=spec["tactic"],
                        url=f"https://attack.mitre.org/techniques/{spec['technique_id'].replace('.', '/')}/",
                    )
                ],
            )
        )

    # Anomaly / outlier findings (#78). One aggregated finding per kind,
    # each evidence line naming the peer group and the deviation. The
    # finding's confidence tracks the strongest (most consistent) cohort.
    anomalies_by_kind: dict[str, list] = {}
    for anomaly in scan.anomalies:
        anomalies_by_kind.setdefault(anomaly.kind, []).append(anomaly)
    for kind, spec in _ANOMALY_FINDING_SPEC.items():
        items = anomalies_by_kind.get(kind)
        if not items:
            continue
        items.sort(key=lambda a: -a.confidence)
        evidence = []
        for a in items[:10]:
            loc = f"{a.route_file}:{a.route_line}" if a.route_line else a.route_file
            peers = f" (peers: {', '.join(a.peer_examples)})" if a.peer_examples else ""
            # Cite the mined invariant (invariant_violation) as the norm broken.
            invariant = f" [invariant: {a.invariant}]" if a.invariant else ""
            evidence.append(
                f"{a.route_method} {a.route_path} [{loc}] — {a.deviation}{invariant}{peers} "
                f"[confidence={a.confidence:.2f}]"
            )
        if len(items) > 10:
            evidence.append(f"+{len(items) - 10} more outlier(s)")
        findings.append(
            Finding(
                title=spec["title"],
                severity=spec["severity"],  # type: ignore[arg-type]
                evidence=evidence,
                mitigation=spec["mitigation"],
                confidence=_numeric_to_confidence(items[0].confidence),
                tags=["anomaly"],
                attack_techniques=[
                    AttackTechnique(
                        technique_id=spec["technique_id"],
                        name=spec["technique_name"],
                        tactic=spec["tactic"],
                        url=f"https://attack.mitre.org/techniques/{spec['technique_id'].replace('.', '/')}/",
                    )
                ],
            )
        )

    # Dangerous taint sinks each get a dedicated, sink-specific finding
    # (#68) — surfaced even outside the framework-MVC gate that `chains`
    # sits behind. One aggregated finding per sink kind reachable from a
    # route, ordered by the spec's declaration.
    taint_by_kind: dict[str, list] = {}
    for chain in scan.taint_chains:
        # Sanitized chains (#137) are neutralized before the sink — keep them
        # as evidence in scan.taint_chains but don't raise a finding for them.
        if chain.sanitized:
            continue
        if chain.sink_kind in _TAINT_FINDING_SPEC:
            taint_by_kind.setdefault(chain.sink_kind, []).append(chain)
    taint_findings_by_kind: dict[str, Finding] = {}
    for kind, spec in _TAINT_FINDING_SPEC.items():
        kind_chains = taint_by_kind.get(kind)
        if not kind_chains:
            continue
        top = min(kind_chains, key=lambda c: (c.hops, -c.confidence))
        evidence = [
            f"route {top.route_method} {top.route_path} in {top.route_file}",
            f"sink at {top.sink_file}:{top.sink_line} ({_TAINT_SINK_LABEL.get(kind, kind)})",
            f"import path: {' → '.join(top.files)} ({top.hops} hop(s))",
        ]
        if len(kind_chains) > 1:
            evidence.append(
                f"+{len(kind_chains) - 1} more route(s) reach a {_TAINT_SINK_LABEL.get(kind, kind)} sink"
            )
        taint_finding = Finding(
            title=spec["title"],
            severity=spec["severity"],  # type: ignore[arg-type]
            evidence=evidence,
            mitigation=spec["mitigation"],
            confidence="medium",
            tags=["taint-chain", "input-handling", "data-risk"],
            attack_techniques=[
                AttackTechnique(
                    technique_id=spec["technique_id"],
                    name=spec["technique_name"],
                    tactic=spec["tactic"],
                    url=f"https://attack.mitre.org/techniques/{spec['technique_id'].replace('.', '/')}/",
                )
            ],
        )
        taint_findings_by_kind[kind] = taint_finding
        findings.append(taint_finding)

    # Exploitability fusion (#79): attach the best 'exploitable now' score for
    # each sink kind to its aggregated taint finding, so triage can lead with
    # the public + no-auth + dangerous-sink combinations.
    if taint_findings_by_kind:
        best = best_by_sink_kind(score_exploitability(scan, attack_surfaces))
        for kind, finding in taint_findings_by_kind.items():
            scored = best.get(kind)
            if scored is not None:
                finding.exploitability = scored.score
                finding.exploitability_tier = scored.tier

    if not findings:
        findings.append(
            Finding(
                title="Heuristic scan found only a limited attack surface",
                severity="low",
                evidence=["No major route, secret, or integration patterns triggered a stronger finding."],
                mitigation="Treat this as a weak signal, expand parser coverage, and manually validate the real entry points and trust boundaries.",
                confidence="low",
                tags=["weak-signal"],
            )
        )

    # #4: attach numeric score for triage ordering, then sort by
    # (severity, -score, title). Same-severity findings surface in
    # confidence-weighted order so a HIGH/HIGH beats a HIGH/LOW.
    for finding in findings:
        finding.score = compute_finding_score(finding.severity, finding.confidence)
    return sorted(
        findings,
        key=lambda f: (_severity_rank(f.severity), -(f.score or 0), f.title),
    )


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
                    _action_step(
                        "Evidence",
                        f"confidence={top_chain.confidence:.2f} ({confidence_bucket(top_chain.confidence)}); {evidence_text}",
                    ),
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

    def _with_evidence(surface: AttackSurface, base_steps: list[str]) -> list[str]:
        # If we can cite concrete file-local artifacts (data stores,
        # external calls, secrets), append an Evidence step so the path
        # narrative is anchored in specific code, not just archetype-level
        # generalities. See #15.
        evidence = _surface_evidence(surface, scan)
        if evidence:
            return [*base_steps, _action_step("Evidence", "; ".join(evidence))]
        return base_steps

    if webhook_surface and (public_data_surface or integration_surface) and _claim(webhook_surface):
        # Webhooks consume their downstream propagation surface so the
        # public-data / integration archetypes don't also fire on the
        # same route.
        if public_data_surface:
            _claim(public_data_surface)
        if integration_surface:
            _claim(integration_surface)
        # Enrich the Propagation steps with concrete same-file artifacts
        # when we can find them — see #5.
        webhook_db = _same_file_datastore(webhook_surface, scan)
        webhook_ext = _same_file_external(webhook_surface, scan)
        steps = [
            _action_step("Entry", f"An attacker reaches {webhook_surface.method} {webhook_surface.route} in {webhook_surface.file}, a webhook-style endpoint that accepts untrusted inbound events"),
            _action_step("Weak point", "The endpoint is treated like a trusted integration boundary before its input is fully verified"),
        ]
        if public_data_surface:
            if webhook_db:
                steps.append(_action_step(
                    "Propagation",
                    f"Attacker-controlled input reaches a `{webhook_db[0]}` data store in `{webhook_db[1]}`, making unauthorized writes or state changes plausible",
                ))
            else:
                steps.append(_action_step("Propagation", "Attacker-controlled input is processed close to a data store, making unauthorized writes or state changes plausible"))
        if integration_surface:
            if webhook_ext:
                steps.append(_action_step(
                    "Propagation",
                    f"The same request path also influences an outbound call to `{webhook_ext[0]}` from `{webhook_ext[1]}`, widening the blast radius beyond the application itself",
                ))
            else:
                steps.append(_action_step("Propagation", "The same request path can also influence outbound service calls, which widens the blast radius beyond the application itself"))
        steps.append(_action_step("Impact", "The attacker drives business actions that should only occur after a trusted event or validated request"))
        paths.append(
            AttackPath(
                name="External event spoofing into internal state change",
                steps=_with_evidence(webhook_surface, steps),
                impact="Unauthorized state changes can be triggered from the internet and then propagated into internal data or downstream systems.",
            )
        )

    if _claim(admin_surface):
        paths.append(
            AttackPath(
                name="Administrative route abuse",
                steps=_with_evidence(admin_surface, [
                    _action_step("Entry", f"An attacker reaches {admin_surface.method} {admin_surface.route} in {admin_surface.file}, a route associated with privileged behavior"),
                    _action_step("Weak point", "Authentication or authorization around that route is bypassed, reused, or enforced too late"),
                    _action_step("Propagation", "Administrative actions execute with attacker influence and affect higher-value parts of the system"),
                    _action_step("Impact", "Privileged changes, sensitive data access, or configuration abuse follow from a single foothold"),
                ]),
                impact="Privilege escalation or destructive administrative actions from a route that should be tightly controlled.",
            )
        )

    if _claim(auth_surface):
        paths.append(
            AttackPath(
                name="Authentication boundary bypass",
                steps=_with_evidence(auth_surface, [
                    _action_step("Entry", f"An attacker targets {auth_surface.method} {auth_surface.route} in {auth_surface.file}, which controls login, tokens, or session state"),
                    _action_step("Weak point", "Credential handling, token validation, or session establishment is weaker than the route implies"),
                    _action_step("Propagation", "The attacker converts that weakness into an authenticated foothold"),
                    _action_step("Impact", "The foothold becomes the starting point for deeper movement into protected application behavior"),
                ]),
                impact="Account takeover or a trusted session that opens access to additional internal actions.",
            )
        )

    if _claim(upload_surface):
        paths.append(
            AttackPath(
                name="Untrusted file handling abuse",
                steps=_with_evidence(upload_surface, [
                    _action_step("Entry", f"An attacker submits content to {upload_surface.method} {upload_surface.route} in {upload_surface.file}"),
                    _action_step("Weak point", "The application accepts or parses attacker-controlled files too broadly"),
                    _action_step("Propagation", "Storage, parsing, or downstream consumers treat that content as safer than it is"),
                    _action_step("Impact", "The result is execution, persistence of malicious content, or operational disruption"),
                ]),
                impact="Stored malicious content, parser abuse, or denial of service from untrusted file input.",
            )
        )

    # Per-file fan-out for public_data. A repo with distinct data-touching
    # files each becomes its own path (bounded by MAX_ATTACK_PATHS at the
    # end). See #5.
    for candidate in _distinct_by_file(
        surfaces,
        lambda s: s.exposure == "public" and s.data_store_interaction and s.category != "health",
        limit=MAX_PER_ARCHETYPE_FANOUT,
    ):
        if not _claim(candidate):
            continue
        db = _same_file_datastore(candidate, scan)
        propagation = (
            f"Attacker-controlled data reaches a `{db[0]}` data store in `{db[1]}`"
            if db
            else "Attacker-controlled data reaches code operating close to the data store"
        )
        paths.append(
            AttackPath(
                name="Public input into sensitive data path",
                steps=_with_evidence(candidate, [
                    _action_step("Entry", f"An attacker uses {candidate.method} {candidate.route} in {candidate.file} as a public foothold"),
                    _action_step("Weak point", "Input validation or authorization is weaker than the route exposure suggests"),
                    _action_step("Propagation", propagation),
                    _action_step("Impact", "Confidentiality, integrity, or authorization guarantees around application data are weakened"),
                ]),
                impact="Unauthorized data access or modification through a public-facing application route.",
            )
        )

    for candidate in _distinct_by_file(
        surfaces,
        lambda s: s.exposure == "public" and s.outbound_integration,
        limit=MAX_PER_ARCHETYPE_FANOUT,
    ):
        if not _claim(candidate):
            continue
        ext = _same_file_external(candidate, scan)
        propagation = (
            f"Spoofed, replayed, or attacker-steered interaction with `{ext[0]}` (from `{ext[1]}`) affects internal logic"
            if ext
            else "Spoofed, replayed, or attacker-steered third-party interactions affect internal logic"
        )
        paths.append(
            AttackPath(
                name="Outbound trust boundary abuse",
                steps=_with_evidence(candidate, [
                    _action_step("Entry", f"An attacker influences {candidate.method} {candidate.route} in {candidate.file}, which sits near an outbound integration"),
                    _action_step("Weak point", "The application assumes too much trust in external calls or responses"),
                    _action_step("Propagation", propagation),
                    _action_step("Impact", "Unsafe business decisions or downstream actions follow from a weak external trust boundary"),
                ]),
                impact="Poisoned state or unsafe downstream actions caused by over-trusting an external dependency.",
            )
        )

    # BOLA/IDOR archetype (#69): an id-bearing route reaching data with no
    # ownership check. Independent of the surface-claim machinery above —
    # it keys off scan.authz_candidates.
    bola = scan.authz_candidates
    if bola:
        _bola_write_methods = {"POST", "PUT", "PATCH", "DELETE", "MUTATION"}
        top = min(
            bola,
            key=lambda c: (c.route_method not in _bola_write_methods, c.route_file),
        )
        action = "modify" if top.route_method in _bola_write_methods else "read"
        paths.append(
            AttackPath(
                name="Object-level authorization bypass (BOLA/IDOR)",
                steps=[
                    _action_step(
                        "Entry",
                        f"An authenticated attacker calls {top.route_method} {top.route_path} in {top.route_file}, which takes a resource id (`{top.id_param}`)",
                    ),
                    _action_step(
                        "Weak point",
                        "No ownership or authorization check is visible near the handler — the resource id from the request is trusted directly",
                    ),
                    _action_step(
                        "Propagation",
                        f"The attacker enumerates or substitutes `{top.id_param}` values; {top.db_evidence}, so the query returns another principal's record",
                    ),
                    _action_step(
                        "Impact",
                        f"Cross-tenant / cross-user ability to {action} records that should be out of scope for the caller",
                    ),
                ],
                impact=f"Horizontal privilege escalation — attackers {action} other users' objects by changing an id in the request.",
            )
        )

    # Cap to keep report output focused; if more than this fires, the
    # extras are usually redundant noise that downstream review surfaces
    # via findings anyway.
    return paths[:MAX_ATTACK_PATHS]
