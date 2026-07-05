"""Mermaid + Graphviz diagram export (#49).

Two shapes to export:

- **Attack paths**  — each ``AttackPath`` becomes a top-to-bottom
  flowchart with the existing step labels as node text. Steps chain in
  order; the impact line lands in a separate impact node.
- **Service topology** — the ``ServiceGraph`` produced by
  ``build_service_graph`` becomes a directed graph with edge styles
  distinguishing kinds (analyzer-declared / http-call / env-configured
  / async-queue).

Two output formats:

- **Mermaid** — renders inline on GitHub, docs sites, and Notion.
- **Graphviz DOT** — feed into ``dot -Tpng`` / ``dot -Tsvg`` for
  slide-quality graphics.

Nothing new is computed here; this is a pure output transform of
existing model objects.
"""

from __future__ import annotations

from typing import Iterable

from .models import AttackPath
from .topology import ServiceEdge, ServiceGraph

# --- Mermaid ---------------------------------------------------------------


def render_attack_paths_mermaid(paths: Iterable[AttackPath]) -> str:
    """Return a Markdown document with one Mermaid flowchart per path."""
    paths = list(paths)
    if not paths:
        return "# AttackMap — Attack paths\n\n_No attack paths surfaced in this scan._\n"

    parts: list[str] = ["# AttackMap — Attack paths", ""]
    for idx, path in enumerate(paths, start=1):
        parts.append(f"## {idx}. {path.name}")
        parts.append("")
        parts.append("```mermaid")
        parts.append("flowchart TD")
        node_ids = [_mermaid_node_id(idx, step_i) for step_i in range(len(path.steps) + 1)]
        for step_i, step in enumerate(path.steps):
            parts.append(f'  {node_ids[step_i]}["{_mermaid_escape(step)}"]')
        # Impact node — visually distinguished with a rectangular label.
        impact_id = node_ids[-1]
        parts.append(f'  {impact_id}["Impact: {_mermaid_escape(path.impact)}"]')
        parts.append(f"  class {impact_id} impact")
        # Chain: n0 → n1 → n2 → ... → impact
        if node_ids:
            parts.append("  " + " --> ".join(node_ids))
        parts.append("  classDef impact fill:#fee,stroke:#c33,color:#900;")
        parts.append("```")
        parts.append("")
    return "\n".join(parts).rstrip() + "\n"


def render_topology_mermaid(graph: ServiceGraph) -> str:
    """Return a Markdown document with one Mermaid graph for the topology."""
    if not graph.nodes:
        return "# AttackMap — Service topology\n\n_No services surfaced in this scan._\n"

    parts: list[str] = [
        "# AttackMap — Service topology",
        "",
        "```mermaid",
        "flowchart LR",
    ]

    node_id_by_name: dict[str, str] = {}
    for idx, node in enumerate(graph.nodes):
        nid = f"S{idx}"
        node_id_by_name[node.name] = nid
        label = _mermaid_escape(node.name)
        if node.role and node.role != "service":
            label = f"{label}<br/><i>{_mermaid_escape(node.role)}</i>"
        parts.append(f'  {nid}["{label}"]')

    # Edges grouped by kind so the legend line makes sense.
    for edge in graph.edges:
        source = node_id_by_name.get(edge.source)
        target = node_id_by_name.get(edge.target)
        if source is None or target is None:
            continue
        parts.append(f"  {source} {_mermaid_edge(edge)} {target}")

    # Style edges per-kind via linkStyle refs — Mermaid indexes edges in
    # declaration order.
    for idx, edge in enumerate(_valid_edges(graph, node_id_by_name)):
        style = _mermaid_link_style(edge.kind)
        if style:
            parts.append(f"  linkStyle {idx} {style}")

    parts.append("```")
    parts.append("")
    parts.append("_Edge kinds:_ **analyzer-declared** (solid), **http-call** (dashed), **env-configured** (dotted), **async-queue** (thick).")
    return "\n".join(parts).rstrip() + "\n"


def _mermaid_edge(edge: ServiceEdge) -> str:
    label = edge.evidence or edge.kind
    label = _mermaid_escape(label)
    if edge.kind == "http-call":
        return f'-. "{label}" .->'
    if edge.kind == "env-configured":
        return f'-. "{label}" .-'
    if edge.kind == "async-queue":
        return f'== "{label}" ==>'
    # analyzer-declared / default
    return f'-- "{label}" -->'


def _mermaid_link_style(kind: str) -> str:
    if kind == "http-call":
        return "stroke:#2b7,stroke-dasharray:5 5;"
    if kind == "env-configured":
        return "stroke:#888,stroke-dasharray:2 4;"
    if kind == "async-queue":
        return "stroke:#a52,stroke-width:2px;"
    return ""


def _mermaid_node_id(path_idx: int, step_idx: int) -> str:
    return f"P{path_idx}_{step_idx}"


def _mermaid_escape(text: str) -> str:
    """Escape characters Mermaid's flowchart parser hates inside labels."""
    return (
        text.replace("\\", "\\\\")
        .replace('"', "'")
        .replace("\n", " ")
    )


# --- Graphviz DOT ----------------------------------------------------------


def render_attack_paths_dot(paths: Iterable[AttackPath]) -> str:
    """Return a Graphviz DOT document. One subgraph per attack path."""
    paths = list(paths)
    lines: list[str] = ["digraph AttackPaths {", "  rankdir=TB;", "  node [shape=box, style=rounded];"]
    if not paths:
        lines.append('  empty [label="No attack paths surfaced.", shape=note];')
        lines.append("}")
        return "\n".join(lines) + "\n"

    for path_idx, path in enumerate(paths, start=1):
        lines.append(f"  subgraph cluster_p{path_idx} {{")
        lines.append(f'    label="{_dot_escape(path.name)}";')
        lines.append('    style=rounded;')
        node_ids = [f"p{path_idx}_{step_i}" for step_i in range(len(path.steps) + 1)]
        for step_i, step in enumerate(path.steps):
            lines.append(f'    {node_ids[step_i]} [label="{_dot_escape(step)}"];')
        impact_id = node_ids[-1]
        lines.append(
            f'    {impact_id} [label="Impact: {_dot_escape(path.impact)}", '
            f'style="rounded,filled", fillcolor="#fee", color="#c33"];'
        )
        for a, b in zip(node_ids, node_ids[1:]):
            lines.append(f"    {a} -> {b};")
        lines.append("  }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def render_topology_dot(graph: ServiceGraph) -> str:
    """Return a Graphviz DOT document for the service graph."""
    lines: list[str] = ["digraph Topology {", "  rankdir=LR;", "  node [shape=box, style=rounded];"]
    if not graph.nodes:
        lines.append('  empty [label="No services surfaced.", shape=note];')
        lines.append("}")
        return "\n".join(lines) + "\n"

    node_id_by_name: dict[str, str] = {}
    for idx, node in enumerate(graph.nodes):
        nid = f"s{idx}"
        node_id_by_name[node.name] = nid
        label = node.name if node.role in ("", "service") else f"{node.name}\\n[{node.role}]"
        lines.append(f'  {nid} [label="{_dot_escape(label)}"];')

    for edge in graph.edges:
        source = node_id_by_name.get(edge.source)
        target = node_id_by_name.get(edge.target)
        if source is None or target is None:
            continue
        style = _dot_edge_style(edge.kind)
        label = edge.evidence or edge.kind
        lines.append(f'  {source} -> {target} [label="{_dot_escape(label)}"{style}];')

    lines.append("}")
    return "\n".join(lines) + "\n"


def _dot_edge_style(kind: str) -> str:
    if kind == "http-call":
        return ', style=dashed, color="#2b7"'
    if kind == "env-configured":
        return ', style=dotted, color="#888"'
    if kind == "async-queue":
        return ', penwidth=2, color="#a52"'
    return ""  # analyzer-declared → default


def _dot_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


# --- Shared helper ---------------------------------------------------------


def _valid_edges(graph: ServiceGraph, name_to_id: dict[str, str]) -> list[ServiceEdge]:
    return [e for e in graph.edges if e.source in name_to_id and e.target in name_to_id]


__all__ = [
    "render_attack_paths_mermaid",
    "render_attack_paths_dot",
    "render_topology_mermaid",
    "render_topology_dot",
]
