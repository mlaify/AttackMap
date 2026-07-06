"""Tests for LLM vulnerability-hypothesis mode (--hunt, #80).

Backend calls are faked (same cli_runner injection the review tests use) so
these run offline and assert the grounding contract, not model output."""

from __future__ import annotations

import json
from typing import Any

from attackmap.cli import HUNT_BANNER
from attackmap.llm_review import generate_llm_review
from attackmap.models import (
    AttackSurface,
    Anomaly,
    Finding,
    Route,
    ScanResult,
    TaintChain,
)
from attackmap.review_prompts import render_hunt_prompts


def _scan() -> ScanResult:
    return ScanResult(
        root="/repo",
        files_scanned=10,
        languages=["python"],
        routes=[Route(path="/authz", method="GET", file="api.py", line=3)],
        taint_chains=[
            TaintChain(
                route_path="/authz",
                route_method="GET",
                route_file="api.py",
                sink_kind="sql_execute",
                sink_file="db.py",
                sink_line=9,
                hops=0,
                files=["api.py", "db.py"],
            )
        ],
        anomalies=[
            Anomaly(
                kind="auth_outlier",
                route_path="/authz",
                route_method="GET",
                route_file="api.py",
                route_line=3,
                peer_group="authz",
                peer_group_size=4,
                consistent_peers=3,
                deviation="3 of 4 routes carry auth; this one does not",
                confidence=0.72,
            )
        ],
    )


def _surfaces() -> list[AttackSurface]:
    return [
        AttackSurface(
            route="/authz",
            method="GET",
            file="api.py",
            category="public_api",
            exposure="public",
            risk="high",
            auth_signals=[],
        )
    ]


def _findings() -> list[Finding]:
    return [Finding(title="Test finding", severity="high", mitigation="fix it")]


# ---------------------------------------------------------------------------
# prompt shape + grounding contract
# ---------------------------------------------------------------------------


def test_hunt_prompt_frames_hypotheses_and_grounding() -> None:
    rendered = render_hunt_prompts(_scan(), _surfaces(), _findings(), [])
    sys = rendered.system
    assert "Hunt Analyst" in sys
    assert "HYPOTHESES" in sys
    # grounding + honesty guardrails
    assert "cite" in sys.lower()
    assert "Do NOT assign CVE" in sys
    assert "exploit code" in sys.lower()
    assert "what a human must verify" in sys.lower()


def test_hunt_pack_includes_taint_exploit_and_anomaly_ids() -> None:
    rendered = render_hunt_prompts(_scan(), _surfaces(), _findings(), [])
    pack = json.loads(rendered.evidence_json)
    assert pack["taint_chains"][0]["id"] == "taint:1"
    assert pack["taint_chains"][0]["sink_kind"] == "sql_execute"
    assert pack["exploitability"][0]["id"] == "exploit:1"
    assert pack["exploitability"][0]["tier"] in {"critical", "high", "medium", "low"}
    assert pack["anomalies"][0]["id"] == "anomaly:1"
    assert pack["anomalies"][0]["kind"] == "auth_outlier"


def test_hunt_and_review_use_distinct_system_prompts() -> None:
    from attackmap.review_prompts import render_review_prompts

    hunt = render_hunt_prompts(_scan(), _surfaces(), _findings(), []).system
    review = render_review_prompts(_scan(), _surfaces(), _findings(), []).system
    assert hunt != review
    assert "Review Analyst" in review
    assert "Hunt Analyst" in hunt


# ---------------------------------------------------------------------------
# backend routing (mode="hunt")
# ---------------------------------------------------------------------------


def _make_cli_runner(stdout: str):
    captured: dict[str, Any] = {}

    class _FakeCompleted:
        def __init__(self) -> None:
            self.stdout = stdout
            self.stderr = ""
            self.returncode = 0

    def _runner(cmd: list[str], stdin_text: str) -> _FakeCompleted:
        captured["cmd"] = cmd
        captured["stdin"] = stdin_text
        return _FakeCompleted()

    return _runner, captured


def test_generate_hunt_sends_hunt_system_prompt() -> None:
    payload = {
        "type": "result",
        "is_error": False,
        "result": "## 1. Hypothesis\nCONFIDENCE: MEDIUM ...",
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 5, "output_tokens": 7},
    }
    runner, captured = _make_cli_runner(json.dumps(payload))
    result = generate_llm_review(
        _scan(),
        _surfaces(),
        _findings(),
        [],
        backend="cli",
        cli_runner=runner,
        mode="hunt",
    )
    assert result.backend == "cli"
    assert "Hypothesis" in result.markdown
    sys_idx = captured["cmd"].index("--system-prompt")
    assert "Hunt Analyst" in captured["cmd"][sys_idx + 1]
    assert "taint_chains" in captured["stdin"]


# ---------------------------------------------------------------------------
# banner
# ---------------------------------------------------------------------------


def test_banner_states_hypotheses_not_detections() -> None:
    assert "HYPOTHESES to confirm" in HUNT_BANNER
    assert "not confirmed vulnerabilities" in HUNT_BANNER
    assert "no cve" in HUNT_BANNER.lower()


def test_hunt_verify_prompt_adjudicates_with_excerpts(tmp_path) -> None:
    """--hunt --verify feeds actual source excerpts and asks for verdicts."""
    from pathlib import Path as _P
    from attackmap.scanner import scan_repo
    from attackmap.recon_to_analysis import translate_recon
    from attackmap.review_prompts import render_hunt_verify_prompts
    (tmp_path / "app.py").write_text(
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/x')\n"
        "def x():\n"
        "    return eval(request.args['e'])\n",
        encoding="utf-8",
    )
    scan = scan_repo(tmp_path)
    analysis = translate_recon(scan)
    r = render_hunt_verify_prompts(scan, analysis.attack_surfaces, analysis.findings, analysis.attack_paths)
    assert "Hunt Verifier" in r.system
    assert "CONFIRMED" in r.system and "REFUTED" in r.system
    pack = json.loads(r.evidence_json)
    assert "code_excerpts" in pack
    # the eval sink line is included as an excerpt with real source
    assert any("eval(request.args" in v for v in pack["code_excerpts"].values())


def test_hunt_verify_routes_to_verify_prompt() -> None:
    payload = {"type": "result", "is_error": False, "result": "## H1\n**Verdict:** CONFIRMED",
               "stop_reason": "end_turn", "usage": {"input_tokens": 5, "output_tokens": 7}}
    runner, captured = _make_cli_runner(json.dumps(payload))
    result = generate_llm_review(_scan(), _surfaces(), _findings(), [], backend="cli",
                                 cli_runner=runner, mode="hunt_verify")
    assert result.backend == "cli"
    sys_idx = captured["cmd"].index("--system-prompt")
    assert "Hunt Verifier" in captured["cmd"][sys_idx + 1]
