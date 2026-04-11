from __future__ import annotations

from collections import Counter

import networkx as nx

from .models import AttackSurface, ScanResult


def identify_attack_surfaces(scan: ScanResult) -> list[AttackSurface]:
    surfaces: list[AttackSurface] = []
    auth_hints_by_file: dict[str, set[str]] = {}
    global_auth_hints = sorted({hint.hint for hint in scan.auth_hints})

    for hint in scan.auth_hints:
        auth_hints_by_file.setdefault(hint.file, set()).add(hint.hint)

    for route in scan.routes:
        path_lower = route.path.lower()
        file_auth_hints = sorted(auth_hints_by_file.get(route.file, set()))
        auth_signals = file_auth_hints or global_auth_hints
        rationale: list[str] = []
        exposure: AttackSurface["exposure"] = "public"
        internal_handler_markers = {
            "handler_visibility:internal",
            "handler_type:internal_handler",
            "service_role:worker",
            "service_role:event_consumer",
            "service_role:internal_handler",
        }
        has_explicit_public_visibility = "handler_visibility:public" in auth_signals
        has_internal_handler_hint = any(marker in auth_signals for marker in internal_handler_markers) and not has_explicit_public_visibility

        if "webhook" in path_lower:
            category = "webhook"
            risk = "high"
            rationale.append("Webhook endpoints commonly accept attacker-controlled input from the internet.")
        elif any(segment in path_lower for segment in ("/admin", "/manage", "/root")):
            category = "admin"
            risk = "high"
            rationale.append("Administrative routes are high-value targets because they expose privileged actions.")
        elif any(segment in path_lower for segment in ("/login", "/signin", "/signup", "/auth", "/session", "/token", "/oauth")):
            category = "auth"
            risk = "high" if not auth_signals else "medium"
            rationale.append("Authentication endpoints are common targets for brute force, token abuse, and session attacks.")
        elif any(segment in path_lower for segment in ("/upload", "/import", "/file")):
            category = "upload"
            risk = "high"
            rationale.append("Upload and import flows often lead to parser abuse or untrusted file handling.")
        elif any(segment in path_lower for segment in ("/internal", "/debug")):
            category = "internal"
            exposure = "internal"
            risk = "medium"
            rationale.append("Internal or debug routes are risky if they become reachable from untrusted networks.")
        elif any(segment in path_lower for segment in ("/health", "/ready", "/live", "/metrics")):
            category = "health"
            risk = "low"
            rationale.append("Operational endpoints reveal limited attack surface but may disclose useful reconnaissance details.")
        else:
            category = "public_api"
            risk = "medium" if scan.databases or scan.external_calls else "low"
            rationale.append("Public application routes are initial footholds for probing input handling and authorization gaps.")

        if has_internal_handler_hint and category not in {"admin", "auth", "webhook"}:
            exposure = "internal"
            if category == "public_api":
                category = "internal"
            risk = "medium" if category != "health" else "low"
            rationale.append("Service-level handler metadata suggests this route is internal-facing (worker/event/internal handler path).")

        if auth_signals:
            rationale.append(f"Auth indicators observed: {', '.join(auth_signals)}.")
        else:
            rationale.append("No auth indicators were observed near this route.")

        if scan.databases:
            rationale.append("Datastore usage was detected elsewhere in the repository, so route-to-data flows are plausible.")
        if scan.external_calls:
            rationale.append("Outbound HTTP calls were detected, creating trust boundaries to third-party systems.")

        surfaces.append(
            AttackSurface(
                route=route.path,
                method=route.method,
                file=route.file,
                category=category,
                exposure=exposure,
                risk=risk,
                auth_signals=auth_signals,
                data_store_interaction=bool(scan.databases),
                outbound_integration=bool(scan.external_calls),
                rationale=rationale,
            )
        )

    return surfaces


def summarize_architecture(scan: ScanResult, graph: nx.DiGraph) -> str:
    route_count = len(scan.routes)
    dbs = sorted({db.kind for db in scan.databases})
    external_targets = sorted({call.target for call in scan.external_calls})
    auth_summary = sorted({hint.hint for hint in scan.auth_hints})
    secret_count = len(scan.secret_hints)
    graph_edges = sorted(
        f"{source} -> {target} ({data['relation']})"
        for source, target, data in graph.edges(data=True)
        if "relation" in data
    )

    lines = [
        "# Architecture Summary",
        "",
        "## Overview",
        f"- AttackMap inferred a {'web-facing' if route_count else 'non-web'} repository with {route_count} entry point{'s' if route_count != 1 else ''}.",
        f"- Files scanned: {scan.files_scanned}",
        f"- Languages detected: {', '.join(scan.languages) if scan.languages else 'none'}",
        f"- Inferred entry points: {route_count}",
        f"- Datastores detected: {', '.join(dbs) if dbs else 'none'}",
        f"- External targets detected: {', '.join(external_targets) if external_targets else 'none'}",
        f"- Auth hints observed: {', '.join(auth_summary) if auth_summary else 'none'}",
        f"- Secret-like env references: {secret_count}",
    ]

    if scan.routes:
        common = Counter(route.file for route in scan.routes).most_common(3)
        lines.extend(
            [
                "",
                "## Entry Point Concentration",
                *[f"- {file}: {count} routes" for file, count in common],
            ]
        )
        busiest_file, busiest_count = common[0]
        lines.extend(
            [
                "",
                "## Likely Review Starting Point",
                f"- Start with `{busiest_file}`. It contains {busiest_count} of the detected routes and is the fastest place to validate exposure and trust boundaries.",
            ]
        )

    if graph_edges:
        lines.extend(
            [
                "",
                "## Inferred Trust Boundaries",
                *[f"- {edge}" for edge in graph_edges[:10]],
            ]
        )

    lines.extend(
        [
            "",
            "## Analyst Notes",
            "- AttackMap inferred this system shape heuristically from framework patterns, dependencies, and code hints.",
            "- Treat this as an initial map for security review, then validate the highest-risk routes and boundaries manually.",
        ]
    )

    return "\n".join(lines)


def _risk_rank(value: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(value, 3)


def _surface_summary(surface: AttackSurface) -> str:
    traits: list[str] = []
    if surface.auth_signals:
        traits.append(f"auth signals: {', '.join(surface.auth_signals)}")
    else:
        traits.append("no auth signals observed")

    if surface.data_store_interaction:
        traits.append("data store reachable")
    if surface.outbound_integration:
        traits.append("external trust boundary")

    return "; ".join(traits)


def summarize_attack_surface(scan: ScanResult, attack_surfaces: list[AttackSurface] | None = None) -> str:
    surfaces = attack_surfaces if attack_surfaces is not None else identify_attack_surfaces(scan)
    ordered_surfaces = sorted(surfaces, key=lambda surface: (_risk_rank(surface.risk), surface.route, surface.method))
    external_targets = sorted({call.target for call in scan.external_calls})
    auth_summary = sorted({a.hint for a in scan.auth_hints})
    high_risk = [surface for surface in ordered_surfaces if surface.risk == "high"]
    auth_and_admin = [surface for surface in ordered_surfaces if surface.category in {"auth", "admin"}]
    public_entry_points = [surface for surface in ordered_surfaces if surface.exposure == "public" and surface.category not in {"auth", "admin", "health"}]
    operational_routes = [surface for surface in ordered_surfaces if surface.category in {"health", "internal"}]

    lines = [
        "# Attack Surface",
        "",
        "## Priority View",
        f"- High-risk entry points: {len(high_risk)}",
        f"- Public routes detected: {sum(1 for surface in ordered_surfaces if surface.exposure == 'public')}",
        f"- Internal-only routes detected: {sum(1 for surface in ordered_surfaces if surface.exposure == 'internal')}",
        f"- Routes with likely data access: {sum(1 for surface in ordered_surfaces if surface.data_store_interaction)}",
        f"- Routes with outbound trust boundaries: {sum(1 for surface in ordered_surfaces if surface.outbound_integration)}",
    ]

    lines.extend(["", "## Highest-Risk Entry Points"])
    if high_risk:
        for surface in high_risk[:10]:
            lines.append(
                f"- {surface.method} {surface.route} ({surface.file}) -> {surface.category}; {_surface_summary(surface)}"
            )
    else:
        lines.append("- No high-risk entry points were classified")

    lines.extend(["", "## Auth And Privileged Routes"])
    if auth_and_admin:
        for surface in auth_and_admin[:10]:
            lines.append(
                f"- [{surface.risk.upper()}] {surface.method} {surface.route} "
                f"({surface.file}) -> {surface.category}, {surface.exposure}; {_surface_summary(surface)}"
            )
    else:
        lines.append("- No dedicated auth or admin routes were classified")

    lines.extend(["", "## Public Application Routes"])
    if public_entry_points:
        for surface in public_entry_points[:10]:
            lines.append(
                f"- [{surface.risk.upper()}] {surface.method} {surface.route} "
                f"({surface.file}) -> {surface.category}, {surface.exposure}; {_surface_summary(surface)}"
            )
    else:
        lines.append("- No additional public application routes were classified")

    lines.extend(["", "## Operational And Internal Routes"])
    if operational_routes:
        for surface in operational_routes[:10]:
            lines.append(
                f"- [{surface.risk.upper()}] {surface.method} {surface.route} "
                f"({surface.file}) -> {surface.category}, {surface.exposure}; {_surface_summary(surface)}"
            )
    else:
        lines.append("- No health, metrics, debug, or internal routes were classified")

    lines.extend(["", "## External Dependencies"])
    if external_targets:
        for target in external_targets[:25]:
            lines.append(f"- {target}")
    else:
        lines.append("- No explicit outbound HTTP calls detected")

    lines.extend(["", "## Secrets And Auth Hints"])
    if scan.secret_hints:
        for hint in scan.secret_hints[:25]:
            lines.append(f"- Secret-related env usage: {hint.name} ({hint.file})")
    else:
        lines.append("- No secret-like environment variable usage detected")

    if auth_summary:
        lines.append(f"- Auth-related keywords observed: {', '.join(auth_summary)}")
    else:
        lines.append("- No auth-related keywords observed")

    return "\n".join(lines)
