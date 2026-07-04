"""Service topology and trust-boundary graph (#18).

The threat-model chain builders (`_build_service_chains`,
`_build_atproto_chains`) each walk analyzer hints ad-hoc to reason about
service-to-service relationships. This module lifts that walk into a
reusable, inspectable **graph structure** so:

  - consumers (LLM prompts, JSON reports, review pipelines) can see the
    topology without reconstructing it themselves,
  - future chain builders share one source of truth for "which services
    exist and how are they connected",
  - the shape is testable in isolation.

The graph is computed on demand (`build_service_graph(scan)`). It is
*not* attached to `ScanResult` — additive-only, no schema change to the
analyzer contract or serialization surface.

## Node kinds

Nodes represent services. A service is identified by its slug — the
name analyzers emit via `service_name:<slug>` hints, or inferred from
repository layout (`services/<name>/…`, `packages/<name>/…`, or
`apps/<name>/…`).

## Edge kinds

  - ``http-call`` — outbound HTTP call to a host that looks like a
    named peer service (e.g. `https://worker.internal/…`).
  - ``env-configured`` — outbound configured via an environment
    variable that names a peer (`WORKER_URL`, `FEEDGEN_URL`).
  - ``analyzer-declared`` — an analyzer explicitly emitted
    `edge:<from>-><to>` (e.g. from node-service's inter-service HTTP
    or async worker code).
  - ``async-queue`` — a BullMQ / Kafka topic edge (`queue://bullmq/…`
    or `queue://kafka/…` targets emitted by node-service 0.2.0).

Each edge carries a `file` citation so the topology stays evidence-backed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import urlparse

from .models import ScanResult


EdgeKind = Literal["http-call", "env-configured", "analyzer-declared", "async-queue"]


@dataclass(frozen=True)
class ServiceNode:
    name: str
    role: str = "service"
    files_seen: tuple[str, ...] = ()


@dataclass(frozen=True)
class ServiceEdge:
    source: str
    target: str
    kind: EdgeKind
    file: str
    evidence: str = ""


@dataclass
class ServiceGraph:
    """A snapshot of the services + trust boundaries visible in a scan.

    Node ordering: first-seen wins (in the order signals appear across
    the input scan). Edges dedup by ``(source, target, kind)`` — a peer
    reached both via HTTP and via env-configured URL shows up as two
    edges.
    """

    nodes: list[ServiceNode] = field(default_factory=list)
    edges: list[ServiceEdge] = field(default_factory=list)

    def node_names(self) -> set[str]:
        return {n.name for n in self.nodes}

    def has_node(self, name: str) -> bool:
        return any(n.name == name for n in self.nodes)

    def peers_of(self, name: str) -> list[str]:
        """Direct outbound neighbors of `name`, ordered as edges were added."""
        seen: set[str] = set()
        out: list[str] = []
        for e in self.edges:
            if e.source == name and e.target not in seen:
                seen.add(e.target)
                out.append(e.target)
        return out


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------


def build_service_graph(scan: ScanResult) -> ServiceGraph:
    """Compute the service topology visible in `scan`.

    Purely heuristic; no protocol-specific parsing. Consumes hints the
    analyzer plugins already emit — `service_name:*`, `service_role:*`,
    `edge:src->dst`, plus outbound URLs and env-configured endpoints.
    Repo layout (`services/*`, `packages/*`, `apps/*`) is used as a
    fallback when no explicit `service_name:` hint fires for a file.
    """
    graph = ServiceGraph()
    nodes: dict[str, ServiceNode] = {}
    file_to_service = _file_service_map(scan)

    def _record_node(name: str, role: str = "service", file: str | None = None) -> None:
        name = name.strip().lower()
        if not name:
            return
        existing = nodes.get(name)
        files = list(existing.files_seen) if existing else []
        if file and file not in files:
            files.append(file)
        role_final = existing.role if existing and existing.role != "service" else role
        nodes[name] = ServiceNode(name=name, role=role_final, files_seen=tuple(files))

    # 1) Service nodes from explicit `service_name:*` hints.
    for hint in _iter_hints(scan):
        if hint[0].startswith("service_name:"):
            name = hint[0].removeprefix("service_name:")
            _record_node(name, file=hint[1])
    # 2) Roles from `service_role:*` hints.
    for hint in _iter_hints(scan):
        if hint[0].startswith("service_role:"):
            role = hint[0].removeprefix("service_role:")
            # Attach role to whichever service the same file names.
            for file_service_name in _services_in_file(hint[1], scan):
                _record_node(file_service_name, role=role, file=hint[1])
    # 3) Fallback nodes from repo layout: each unique file in services/*,
    # packages/*, apps/* implies a node named after the directory.
    for path in _files_in_scan(scan):
        inferred = _infer_from_layout(path)
        if inferred:
            _record_node(inferred, file=path)

    # 4) Edges from explicit `edge:src->dst` hints (analyzer-declared).
    seen_edges: set[tuple[str, str, str]] = set()

    def _record_edge(source: str, target: str, kind: EdgeKind, file: str, evidence: str = "") -> None:
        source = source.strip().lower()
        target = target.strip().lower()
        if not source or not target or source == target:
            return
        key = (source, target, kind)
        if key in seen_edges:
            return
        seen_edges.add(key)
        graph.edges.append(ServiceEdge(source=source, target=target, kind=kind, file=file, evidence=evidence))
        # Auto-create sink nodes so the target is inspectable even when
        # the analyzer never saw its own code (external peer).
        _record_node(source, file=file)
        _record_node(target, file=file)

    for hint_value, hint_file in _iter_hints(scan):
        if not hint_value.startswith("edge:"):
            continue
        payload = hint_value.removeprefix("edge:")
        if "->" not in payload:
            continue
        src, dst = payload.split("->", 1)
        _record_edge(src, dst, "analyzer-declared", hint_file, evidence=hint_value)

    # 5) HTTP-call edges — outbound URLs whose host looks like a peer.
    for call in scan.external_calls:
        target = call.target
        # Async queues (node-service 0.2.0 emits `queue://bullmq/<name>`
        # and `queue://kafka/<topic>` as external_calls). Model these
        # as their own edge kind so consumers can distinguish sync/async.
        if target.startswith("queue://"):
            proto_name = target.removeprefix("queue://").split("/", 1)
            if len(proto_name) == 2:
                proto, name = proto_name
                source = _service_owning_file(call.file, file_to_service)
                if source:
                    _record_edge(
                        source,
                        f"{proto}:{name}",
                        "async-queue",
                        call.file,
                        evidence=target,
                    )
            continue
        # env://VAR_URL pseudo-target from the node-service analyzer.
        if target.startswith("env://"):
            env_name = target.removeprefix("env://")
            peer = _service_from_env_name(env_name)
            source = _service_owning_file(call.file, file_to_service)
            if source and peer:
                _record_edge(source, peer, "env-configured", call.file, evidence=target)
            continue
        # Ordinary URL. Match host to a known service if possible.
        peer = _service_from_url(target)
        source = _service_owning_file(call.file, file_to_service)
        if source and peer:
            _record_edge(source, peer, "http-call", call.file, evidence=target)

    # Emit nodes in a stable order — insertion order.
    graph.nodes = list(nodes.values())
    return graph


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iter_hints(scan: ScanResult):
    """Yield (hint, file) across all hint families the analyzers use to
    describe service structure."""
    for hint in scan.auth_hints:
        yield (hint.hint, hint.file)
    for hint in scan.service_hints:
        yield (hint.hint, hint.file)
    for hint in scan.edge_hints:
        yield (hint.hint, hint.file)


def _files_in_scan(scan: ScanResult) -> set[str]:
    files: set[str] = set()
    for r in scan.routes:
        files.add(r.file)
    for c in scan.external_calls:
        files.add(c.file)
    for d in scan.databases:
        files.add(d.file)
    for h in scan.auth_hints:
        files.add(h.file)
    return files


def _infer_from_layout(path: str) -> str | None:
    normalized = path.replace("\\", "/")
    parts = normalized.split("/")
    for parent in ("services", "packages", "apps"):
        if parent in parts:
            idx = parts.index(parent)
            if idx + 1 < len(parts):
                return parts[idx + 1].lower()
    return None


def _file_service_map(scan: ScanResult) -> dict[str, str]:
    """Best-guess service name per file, resolved by explicit
    ``service_name:<slug>`` hints first, then repo-layout fallback."""
    mapping: dict[str, str] = {}
    for hint_value, hint_file in _iter_hints(scan):
        if hint_value.startswith("service_name:"):
            name = hint_value.removeprefix("service_name:").lower()
            if name and hint_file not in mapping:
                mapping[hint_file] = name
    return mapping


def _services_in_file(file: str, scan: ScanResult) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for hint_value, hint_file in _iter_hints(scan):
        if hint_file != file:
            continue
        if not hint_value.startswith("service_name:"):
            continue
        name = hint_value.removeprefix("service_name:").lower()
        if name and name not in seen:
            seen.add(name)
            names.append(name)
    return names


def _service_owning_file(file: str, file_to_service: dict[str, str]) -> str | None:
    if file in file_to_service:
        return file_to_service[file]
    return _infer_from_layout(file)


def _service_from_url(target: str) -> str | None:
    """Extract a service slug from an outbound URL. Mirrors the same
    lightweight heuristic the node-service analyzer uses so both agree
    on what constitutes a peer name."""
    try:
        host = urlparse(target).hostname or ""
    except ValueError:
        return None
    if not host:
        return None
    if host in {"localhost", "127.0.0.1"}:
        return "local-service"
    return host.split(".")[0].split("-")[0].lower()


def _service_from_env_name(env_name: str) -> str | None:
    token = env_name.upper().removesuffix("_URL")
    if token.endswith("_SERVICE"):
        token = token.removesuffix("_SERVICE")
    token = token.replace("__", "_").strip("_")
    if not token:
        return None
    return token.lower().replace("_", "-")


__all__ = [
    "ServiceGraph",
    "ServiceNode",
    "ServiceEdge",
    "EdgeKind",
    "build_service_graph",
]
