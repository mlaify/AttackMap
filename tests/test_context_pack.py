from attackmap.context_pack import SCHEMA_VERSION, build_review_context_pack
from attackmap.models import AuthHint, Route, ScanResult


def test_context_pack_contains_required_sections() -> None:
    scan = ScanResult(
        root=".",
        languages=["python"],
        routes=[Route(path="/health", method="GET", file="app.py")],
        files_scanned=1,
    )
    review_json = {"schema_version": "1.0.0", "system_overview": {"repository_type": "web/service-facing"}}
    analyzer_metadata = [
        {
            "name": "python-web",
            "description": "Built-in analyzer for Python web frameworks and related security signals.",
            "scope": "Python source files handled by the current scanner-backed web heuristics.",
            "ecosystems": ["python", "fastapi", "flask"],
        }
    ]

    payload = build_review_context_pack(review_json, scan, analyzer_metadata)

    assert payload["schema_version"] == SCHEMA_VERSION
    assert payload["attackmap_review_json"] == review_json
    assert payload["analyzer_metadata_used"] == analyzer_metadata
    assert "source_quality_rules" in payload
    assert "output_hints" in payload
    assert "domain_hints" in payload
    assert "rag_expansion_hooks" in payload


def test_context_pack_infers_atproto_and_bluesky_domain_hints() -> None:
    scan = ScanResult(
        root=".",
        languages=["typescript"],
        routes=[Route(path="/xrpc/app.bsky.feed.getFeed", method="ANY", file="packages/pds/src/api.ts")],
        auth_hints=[AuthHint(hint="atproto_namespace:app.bsky", file="packages/pds/src/api.ts")],
        files_scanned=10,
    )
    review_json = {"schema_version": "1.0.0"}

    payload = build_review_context_pack(review_json, scan, [])

    assert "atproto" in payload["domain_hints"]["tags"]
    assert "bluesky" in payload["domain_hints"]["tags"]
