"""`attackmap llm-models`: which models the user's credentials can use."""

from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace

from typer.testing import CliRunner

from attackmap import cli, llm_models
from attackmap.llm_models import (
    check_claude_model,
    claude_catalog,
    list_claude_models_api,
    list_codex_models,
    list_local_models,
)
from attackmap.llm_review import LlmReviewError, generate_llm_review

CODEX_CATALOG = {
    "models": [
        {"slug": "gpt-reserve", "display_name": "GPT-Reserve", "visibility": "hide", "priority": 7,
         "supported_reasoning_levels": [{"effort": "low"}], "available_access_programs": {"cyber": ["standard"]}},
        {"slug": "gpt-6-sol", "display_name": "GPT-6-Sol", "visibility": "list", "priority": 6,
         "supported_reasoning_levels": [{"effort": "low"}, {"effort": "max"}], "additional_speed_tiers": ["fast"],
         "available_access_programs": {"cyber": ["standard", "daybreak_blue"]}},
        {"slug": "gpt-6.2-sol", "display_name": "GPT-6.2-Sol", "visibility": "list", "priority": 1,
         "supported_reasoning_levels": [{"effort": "medium"}], "available_access_programs": {"cyber": ["standard"]}},
    ]
}


def _codex_runner(cmd):
    assert cmd == ["codex", "debug", "models"]
    return subprocess.CompletedProcess(cmd, 0, json.dumps(CODEX_CATALOG), "")


def test_codex_catalog_lists_the_account_models_with_access_programs() -> None:
    models = list_codex_models(runner=_codex_runner)
    assert [m.id for m in models] == ["gpt-6.2-sol", "gpt-6-sol"]  # priority order, hidden dropped
    assert models[0].default and not models[1].default
    assert models[1].access_programs == {"cyber": ["standard", "daybreak_blue"]}
    assert models[1].efforts == ("low", "max") and models[1].fast
    assert [m.id for m in list_codex_models(include_hidden=True, runner=_codex_runner)][-1] == "gpt-reserve"


def test_claude_api_lists_what_the_organization_can_call() -> None:
    # Mythos appears only when the Models API returns it (verified organizations).
    rows = [SimpleNamespace(id="claude-mythos-5-2", display_name="Claude Mythos 5.2", deprecated_at=None),
            SimpleNamespace(id="claude-opus-5-5", display_name="Claude Opus 5.5", deprecated_at=None),
            SimpleNamespace(id="claude-opus-4-8", display_name="Claude Opus 4.8", deprecated_at="2026-12-01")]
    client = SimpleNamespace(models=SimpleNamespace(list=lambda: iter(rows)))
    models = {m.id: m for m in list_claude_models_api(client)}
    assert models["claude-mythos-5-2"].gated and models["claude-mythos-5-2"].source == "account"
    assert models["claude-opus-5-5"].default and models["claude-opus-5-5"].fast
    assert models["claude-opus-4-8"].deprecated
    catalog = {m.id: m for m in claude_catalog()}
    assert catalog["claude-mythos-5-2"].source == "catalog" and catalog["claude-haiku-4-5"].efforts == ()


def test_check_claude_model_reads_the_cli_reply() -> None:
    ok = check_claude_model(
        "claude-mythos-5-2",
        runner=lambda cmd, prompt: subprocess.CompletedProcess(cmd, 0, json.dumps({"result": "OK", "is_error": False}), ""),
    )
    assert ok == (True, "available")
    denied = check_claude_model(
        "claude-mythos-5-2",
        runner=lambda cmd, prompt: subprocess.CompletedProcess(
            cmd, 1, json.dumps({"result": "model not available on your plan", "is_error": True}), ""
        ),
    )
    assert denied == (False, "model not available on your plan")


def test_local_server_models() -> None:
    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return None

        def read(self):
            return json.dumps({"data": [{"id": "qwen2.5-coder:32b"}]}).encode()

    models = list_local_models("http://127.0.0.1:11434/v1", opener=lambda url, timeout: _Resp())
    assert [m.id for m in models] == ["qwen2.5-coder:32b"]


def test_llm_models_command_json(monkeypatch) -> None:
    monkeypatch.setattr(llm_models.subprocess, "run", lambda cmd, **kw: _codex_runner(cmd))
    monkeypatch.setattr("attackmap.llm_review._codex_cli_available", lambda: True)
    result = CliRunner().invoke(cli.app, ["llm-models", "--llm-provider", "openai", "--llm-backend", "cli", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["backend"] == "cli" and payload["models"][0]["id"] == "gpt-6.2-sol"
    assert "llm-models" in json.loads(CliRunner().invoke(cli.app, ["capabilities"]).output)["commands"]


def test_access_program_is_passed_to_codex_and_checked_against_the_model(monkeypatch) -> None:
    from attackmap import llm_review

    catalog = {m.id: m for m in list_codex_models(runner=_codex_runner)}
    monkeypatch.setattr(llm_review, "codex_catalog_by_slug", lambda: catalog)
    seen = {}

    def runner(cmd, stdin):
        seen["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, "# Review", "")

    from tests.test_llm_review import _findings, _surfaces, _trivial_scan  # reuse the fixtures

    generate_llm_review(_trivial_scan(), _surfaces(), _findings(), [], provider="openai", backend="cli",
                        model="gpt-6-sol", codex_runner=runner, access_program="daybreak_blue")
    i = seen["cmd"].index("--cyber-access-program")
    assert seen["cmd"][i + 1] == "daybreak_blue"
    try:
        generate_llm_review(_trivial_scan(), _surfaces(), _findings(), [], provider="openai", backend="cli",
                            model="gpt-6.2-sol", codex_runner=runner, access_program="daybreak_blue")
    except LlmReviewError as exc:
        assert "doesn't offer the daybreak_blue access program" in str(exc)
    else:
        raise AssertionError("expected the access program to be refused for gpt-6.2-sol")
