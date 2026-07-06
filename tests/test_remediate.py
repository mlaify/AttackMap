"""Tests for LLM remediation mode (--remediate, #106). Backend faked (offline)."""

from __future__ import annotations

import json
from typing import Any

from attackmap.cli import REMEDIATION_BANNER
from attackmap.llm_review import generate_llm_review
from attackmap.models import AttackSurface, Finding, Route, ScanResult
from attackmap.review_prompts import render_remediation_prompts


def _scan() -> ScanResult:
    return ScanResult(root="/repo", files_scanned=5, languages=["python"],
                      routes=[Route(path="/u", method="GET", file="api.py", line=2)])


def _findings() -> list[Finding]:
    return [Finding(title="SQL injection via raw query", severity="high",
                    mitigation="Use parameterized queries.", evidence=["api.py:2 — cursor.execute(...)"])]


def test_remediation_prompt_is_review_first_and_grounded() -> None:
    r = render_remediation_prompts(_scan(), [], _findings(), [])
    assert "Remediation Engineer" in r.system
    assert "review" in r.system.lower()
    assert "Do NOT invent" in r.system
    assert "No exploit code" in r.system


def test_remediation_and_review_prompts_differ() -> None:
    from attackmap.review_prompts import render_review_prompts
    rem = render_remediation_prompts(_scan(), [], _findings(), []).system
    rev = render_review_prompts(_scan(), [], _findings(), []).system
    assert rem != rev
    assert "Review Analyst" in rev and "Remediation Engineer" in rem


def _cli_runner(stdout: str):
    captured: dict[str, Any] = {}

    class _C:
        def __init__(self): self.stdout, self.stderr, self.returncode = stdout, "", 0

    def _r(cmd, stdin):
        captured["cmd"], captured["stdin"] = cmd, stdin
        return _C()
    return _r, captured


def test_generate_remediation_uses_remediation_prompt() -> None:
    payload = {"type": "result", "is_error": False, "result": "## Fix\nParameterize it.",
               "stop_reason": "end_turn", "usage": {"input_tokens": 3, "output_tokens": 4}}
    runner, captured = _cli_runner(json.dumps(payload))
    result = generate_llm_review(_scan(), [], _findings(), [], backend="cli",
                                 cli_runner=runner, mode="remediate")
    assert result.backend == "cli"
    sys_idx = captured["cmd"].index("--system-prompt")
    assert "Remediation Engineer" in captured["cmd"][sys_idx + 1]


def test_remediation_banner_is_review_first() -> None:
    assert "review" in REMEDIATION_BANNER.lower()
    assert "not auto-applied" in REMEDIATION_BANNER.lower()
