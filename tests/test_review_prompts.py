import json

from attackmap.models import AttackPath, AttackSurface, Finding, Route, ScanResult
from attackmap.review_prompts import render_review_prompts, render_system_prompt, render_user_prompt


def test_system_prompt_contains_grounding_rules() -> None:
    prompt = render_system_prompt()

    assert "evidence-first" in prompt.lower()
    assert "do not invent findings" in prompt.lower()
    assert "observed vs inferred" in prompt.lower()
    assert "defensive" in prompt.lower()


def test_rendered_user_prompt_includes_evidence_pack() -> None:
    scan = ScanResult(
        root=".",
        languages=["typescript"],
        routes=[
            Route(path="/admin/reindex", method="POST", file="services/api/src/admin.ts"),
            Route(path="/xrpc/com.atproto.repo.putRecord", method="ANY", file="lexicons/com/atproto/repo/putRecord.json"),
            Route(path="/debug/fixture", method="GET", file="tests/api/debug.test.ts"),
        ],
        files_scanned=9,
    )
    surfaces = [
        AttackSurface(
            route="/admin/reindex",
            method="POST",
            file="services/api/src/admin.ts",
            category="admin",
            exposure="public",
            risk="high",
            auth_signals=["jwt"],
            data_store_interaction=True,
        ),
        AttackSurface(
            route="/xrpc/com.atproto.repo.putRecord",
            method="ANY",
            file="lexicons/com/atproto/repo/putRecord.json",
            category="public_api",
            exposure="public",
            risk="medium",
            auth_signals=["atproto_namespace:com.atproto"],
            outbound_integration=True,
        ),
        AttackSurface(
            route="/debug/fixture",
            method="GET",
            file="tests/api/debug.test.ts",
            category="public_api",
            exposure="public",
            risk="low",
        ),
    ]
    findings = [
        Finding(
            title="Administrative routes appear reachable from the main application surface",
            severity="high",
            evidence=["POST /admin/reindex in services/api/src/admin.ts"],
            mitigation="Require strict server-side authorization on admin actions.",
            confidence="high",
        )
    ]
    paths = [
        AttackPath(
            name="Administrative service trust-chain abuse",
            steps=["Entry: Attacker reaches POST /admin/reindex in services/api/src/admin.ts"],
            impact="Privileged operations can be triggered from a public foothold.",
        )
    ]

    rendered = render_review_prompts(scan, surfaces, findings, paths)
    user_prompt = render_user_prompt(scan, surfaces, findings, paths)

    assert "Evidence pack (JSON):" in user_prompt
    assert rendered.system
    assert rendered.user == user_prompt

    payload = json.loads(rendered.evidence_json)
    assert payload["evidence_counts"]["observed_runtime_public"] == 1
    assert payload["evidence_counts"]["inferred_protocol"] == 1
    assert payload["evidence_counts"]["low_quality"] == 1
    assert any(item["id"].startswith("surface:") for item in payload["attack_surfaces"])
    assert any(item["id"].startswith("finding:") for item in payload["findings"])
    assert any(item["id"].startswith("path:") for item in payload["attack_paths"])
