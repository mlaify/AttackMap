import json
from pathlib import Path


def _load_schema(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def test_defensive_review_schema_declares_required_top_level_sections() -> None:
    schema = _load_schema("schemas/defensive-review.schema.json")
    required = set(schema.get("required", []))

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert "schema_version" in required
    assert "target_metadata" in required
    assert "system_overview" in required
    assert "attack_surface" in required
    assert "strengths" in required
    assert "weaknesses_risk_hotspots" in required
    assert "evidence_chains" in required
    assert "recommendations" in required
    assert "raw_structured_signals" in required
    assert "limitations_meta" in required


def test_context_pack_schema_declares_required_top_level_sections() -> None:
    schema = _load_schema("schemas/review-context-pack.schema.json")
    required = set(schema.get("required", []))

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert "schema_version" in required
    assert "artifact_type" in required
    assert "attackmap_review_json" in required
    assert "analyzer_metadata_used" in required
    assert "source_quality_rules" in required
    assert "output_hints" in required
    assert "domain_hints" in required
    assert "rag_expansion_hooks" in required
    assert "limitations_meta" in required
