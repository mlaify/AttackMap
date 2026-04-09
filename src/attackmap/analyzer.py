from __future__ import annotations

from collections import Counter

import networkx as nx

from .models import ScanResult


def summarize_architecture(scan: ScanResult, graph: nx.DiGraph) -> str:
    route_count = len(scan.routes)
    dbs = sorted({db.kind for db in scan.databases})
    external_targets = sorted({call.target for call in scan.external_calls})

    lines = [
        "# Architecture Summary",
        "",
        f"- Files scanned: {scan.files_scanned}",
        f"- Languages detected: {', '.join(scan.languages) if scan.languages else 'none'}",
        f"- Route count: {route_count}",
        f"- Datastores detected: {', '.join(dbs) if dbs else 'none'}",
        f"- External targets detected: {', '.join(external_targets) if external_targets else 'none'}",
    ]

    if scan.routes:
        common = Counter(route.file for route in scan.routes).most_common(3)
        lines.extend(
            [
                "",
                "## Route-heavy files",
                *[f"- {file}: {count} routes" for file, count in common],
            ]
        )

    if graph.number_of_nodes() > 0:
        lines.extend(
            [
                "",
                "## System shape",
                "- AttackMap inferred a lightweight graph linking application entry points, data stores, and outbound dependencies.",
                "- This is heuristic-based and intended as a starting point for review, not a complete source of truth.",
            ]
        )

    return "\n".join(lines)


def summarize_attack_surface(scan: ScanResult) -> str:
    lines = [
        "# Attack Surface",
        "",
        "## Entry points",
    ]

    if scan.routes:
        for route in scan.routes[:25]:
            lines.append(f"- {route.method} {route.path} ({route.file})")
    else:
        lines.append("- No explicit web routes detected")

    lines.extend(["", "## External dependencies"])
    if scan.external_calls:
        for call in scan.external_calls[:25]:
            lines.append(f"- {call.target} ({call.file})")
    else:
        lines.append("- No explicit outbound HTTP calls detected")

    lines.extend(["", "## Secrets and auth hints"])
    if scan.secret_hints:
        for hint in scan.secret_hints[:25]:
            lines.append(f"- Secret-related env usage: {hint.name} ({hint.file})")
    else:
        lines.append("- No secret-like environment variable usage detected")

    if scan.auth_hints:
        auth_summary = ", ".join(sorted({a.hint for a in scan.auth_hints}))
        lines.append(f"- Auth-related keywords observed: {auth_summary}")
    else:
        lines.append("- No auth-related keywords observed")

    return "\n".join(lines)
