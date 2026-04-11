from __future__ import annotations

from .models import ScanResult

SCHEMA_VERSION = "1.0.0"
LOW_QUALITY_SEGMENTS = ["/tests/", "/__tests__/", "/fixtures/", "/mocks/", "/examples/"]


def _infer_domain_hints(scan: ScanResult) -> dict:
    route_values = [route.path.lower() for route in scan.routes]
    hint_values = [hint.hint.lower() for hint in scan.auth_hints]
    file_values = [route.file.lower() for route in scan.routes]
    combined = " ".join([*route_values, *hint_values, *file_values])

    tags: list[str] = []
    signals: list[str] = []

    if "/xrpc/" in combined or "atproto_" in combined or "com.atproto." in combined:
        tags.append("atproto")
        signals.append("xrpc/atproto namespace patterns observed")
    if "app.bsky." in combined:
        if "atproto" not in tags:
            tags.append("atproto")
        tags.append("bluesky")
        signals.append("app.bsky namespace patterns observed")
    if "laminas" in combined or "module.config.php" in combined:
        tags.append("laminas")
        signals.append("laminas/module config patterns observed")

    if not tags:
        tags.append("general")

    return {
        "tags": sorted(set(tags)),
        "signals": sorted(set(signals)),
    }


def build_review_context_pack(
    review_json: dict,
    scan: ScanResult,
    analyzer_metadata: list[dict[str, object]],
) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "attackmap_review_context_pack",
        "attackmap_review_json": review_json,
        "analyzer_metadata_used": analyzer_metadata,
        "source_quality_rules": {
            "low_quality_path_segments": LOW_QUALITY_SEGMENTS,
            "handling": {
                "default": "down-rank low-quality signals in triage and prioritization",
                "reporting": "retain low-quality signals in raw_structured_signals with explicit evidence-class labeling",
                "operator_note": "do not treat low-quality-only evidence as strong production exposure without corroboration",
            },
        },
        "output_hints": {
            "audience": ["security engineers", "software engineers", "tech leads"],
            "style": {
                "tone": "defensive, concrete, non-hype",
                "reasoning": "evidence-first and uncertainty-aware",
                "disallowed": [
                    "inventing findings or architecture elements",
                    "offensive exploitation guidance",
                ],
            },
            "prioritization": "focus on highest-impact, highest-confidence chains and trust-boundary issues first",
        },
        "domain_hints": _infer_domain_hints(scan),
        "rag_expansion_hooks": {
            "enabled": False,
            "notes": "local-first context pack; retrieval slots intentionally minimal for future expansion",
            "slots": [],
        },
        "limitations_meta": {
            "analysis_mode": "heuristic",
            "notes": [
                "Domain tags are inferred heuristically from routes, hints, and file patterns.",
                "Analyzer metadata reflects analyzers selected to run after detect-filtering.",
            ],
        },
    }
