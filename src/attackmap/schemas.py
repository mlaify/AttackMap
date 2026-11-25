"""Versioned JSON report schemas and their compatibility rules (#200).

Three documents are a public contract, each with a ``schema_version``:

- ``attackmap-report.json`` — :data:`REPORT_SCHEMA_VERSION`, schema generated
  from the Pydantic models (:func:`report_schema`);
- ``defensive-review.json`` and ``review-context-pack.json`` — hand-written
  schemas in ``schemas/``.

Semver applies to each schema. A consumer written against ``X.Y`` keeps
working on every ``X.*``: minor versions only add (optional properties,
enum values, ``$defs``); anything that removes or retypes a property, or
removes an enum value, needs a major version. ``schemas/frozen/<name>/<version>.json``
holds the schema each released version shipped; the contract test checks the
current schema against those snapshots (:func:`breaking_changes`).
"""

from __future__ import annotations

from typing import Any

REPORT_SCHEMA_VERSION = "1.2.0"
_DRAFT = "https://json-schema.org/draft/2020-12/schema"


def report_schema() -> dict[str, Any]:
    """The JSON Schema of ``attackmap-report.json``, from the models it dumps."""
    from pydantic.json_schema import models_json_schema

    from .exploitability import ExploitabilityScore
    from .models import AttackChain, AttackPath, AttackSurface, Finding, ScanResult

    models = [ScanResult, AttackSurface, Finding, AttackPath, AttackChain, ExploitabilityScore]
    _, generated = models_json_schema([(m, "serialization") for m in models], ref_template="#/$defs/{model}")
    defs = generated["$defs"]

    def ref(name: str) -> dict[str, str]:
        return {"$ref": f"#/$defs/{name}"}

    def with_fields(name: str, extra: dict[str, Any]) -> dict[str, Any]:
        return {"allOf": [ref(name), {"type": "object", "properties": extra}]}

    text = {"type": "string"}
    return {
        "$schema": _DRAFT,
        "$id": "https://attackmap.dev/schemas/attackmap-report.schema.json",
        "title": "AttackMap report (attackmap-report.json)",
        "type": "object",
        "required": ["schema_version", "scan", "findings", "attack_paths", "attack_chains"],
        "properties": {
            "schema_version": text,
            "scan": ref("ScanResult"),
            "architecture_summary": text,
            "attack_surface_summary": text,
            "defensive_review": text,
            # Validated by their own schemas (schemas/*.schema.json).
            "defensive_review_json": {"type": "object"},
            "review_context_pack": {"type": "object"},
            "attack_surfaces": {"type": "array", "items": ref("AttackSurface")},
            "findings": {"type": "array", "items": with_fields("Finding", {"id": text})},
            "suppressed_findings": {
                "type": "array",
                "items": with_fields(
                    "Finding",
                    {"id": text, "rule": text, "reason": text, "suppressed_by": {"type": "array", "items": text}},
                ),
            },
            "confidence_filter": {
                "type": "object",
                "properties": {"min_confidence": {"enum": ["low", "medium", "high"]}, "filtered": {"type": "integer"}},
            },
            "attack_paths": {"type": "array", "items": ref("AttackPath")},
            "attack_chains": {"type": "array", "items": ref("AttackChain")},
            "exploitability": {"type": "array", "items": ref("ExploitabilityScore")},
        },
        "$defs": dict(sorted(defs.items())),
    }


def schema_versions() -> dict[str, str]:
    """Schema name (``schemas/<name>.schema.json``) → current version."""
    from .context_pack import SCHEMA_VERSION as CONTEXT_PACK_VERSION
    from .review_json import SCHEMA_VERSION as REVIEW_VERSION

    return {
        "attackmap-report": REPORT_SCHEMA_VERSION,
        "defensive-review": REVIEW_VERSION,
        "review-context-pack": CONTEXT_PACK_VERSION,
    }


def _types(node: dict[str, Any]) -> set[str]:
    t = node.get("type")
    if t is None:
        return set()
    return {t} if isinstance(t, str) else set(t)


def breaking_changes(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    """What a consumer of ``old`` would lose reading ``new``: a removed
    property, a narrowed type or a removed enum value, at any depth reachable
    through ``properties``, ``items``, ``allOf``/``anyOf``/``oneOf`` and
    local ``$ref``s. Additions are compatible."""
    out: list[str] = []
    seen: set[tuple[str, str]] = set()

    def resolve(doc: dict[str, Any], node: dict[str, Any]) -> dict[str, Any]:
        while isinstance(node, dict) and "$ref" in node and node["$ref"].startswith("#/"):
            target: Any = doc
            for part in node["$ref"][2:].split("/"):
                target = target.get(part, {}) if isinstance(target, dict) else {}
            node = target
        return node if isinstance(node, dict) else {}

    def walk(o: dict[str, Any], n: dict[str, Any], path: str) -> None:
        key = (str(id(o)), str(id(n)))
        if key in seen:
            return
        seen.add(key)
        o, n = resolve(old, o), resolve(new, n)
        old_t, new_t = _types(o), _types(n)
        if old_t and new_t and not old_t <= new_t:
            out.append(f"{path}: type {sorted(old_t)} -> {sorted(new_t)}")
        if "enum" in o and "enum" in n:
            gone = [v for v in o["enum"] if v not in n["enum"]]
            if gone:
                out.append(f"{path}: enum values removed {gone}")
        for name, sub in (o.get("properties") or {}).items():
            if name not in (n.get("properties") or {}) and not _in_any_branch(new, n, name):
                out.append(f"{path}.{name}: removed")
            elif name in (n.get("properties") or {}):
                walk(sub, n["properties"][name], f"{path}.{name}")
        if isinstance(o.get("items"), dict) and isinstance(n.get("items"), dict):
            walk(o["items"], n["items"], f"{path}[]")
        for combinator in ("allOf", "anyOf", "oneOf"):
            for i, (ob, nb) in enumerate(zip(o.get(combinator) or [], n.get(combinator) or [])):
                walk(ob, nb, f"{path}<{combinator}{i}>")

    def _in_any_branch(doc: dict[str, Any], node: dict[str, Any], name: str) -> bool:
        for combinator in ("allOf", "anyOf", "oneOf"):
            for branch in node.get(combinator) or []:
                if name in (resolve(doc, branch).get("properties") or {}):
                    return True
        return False

    walk(old, new, "$")
    return out


__all__ = ["REPORT_SCHEMA_VERSION", "breaking_changes", "report_schema", "schema_versions"]
