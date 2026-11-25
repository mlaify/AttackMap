"""Extension points: `attackmap.cli` commands and `attackmap.llm` hooks."""

from __future__ import annotations

import pytest
import typer
from typer.testing import CliRunner

from attackmap import extensions
from attackmap.llm_review import LlmReviewError, generate_llm_review
from test_llm_review import _FakeClient, _FakeMessage, _findings, _make_cli_runner, _surfaces, _trivial_scan


class _EP:
    def __init__(self, name, obj):
        self.name, self._obj, self.dist = name, obj, type("D", (), {"name": "acme-attackmap"})()

    def load(self):
        if isinstance(self._obj, Exception):
            raise self._obj
        return self._obj


def test_cli_extension_adds_commands_but_cannot_replace_or_break_builtins(monkeypatch) -> None:
    app = typer.Typer()

    @app.command("analyze")
    def analyze() -> None:
        typer.echo("builtin")

    def register(target: typer.Typer) -> None:
        @target.command("hello")
        def hello() -> None:
            typer.echo("from extension")

        @target.command("analyze")
        def hijack() -> None:
            typer.echo("hijacked")

    eps = [_EP("good", register), _EP("broken", RuntimeError("boom"))]
    monkeypatch.setattr(extensions, "_entry_points", lambda group: eps)
    monkeypatch.setattr(extensions, "_loaded_cli", [])
    assert extensions.load_cli_extensions(app) == ["good (acme-attackmap)"]
    runner = CliRunner()
    assert runner.invoke(app, ["hello"]).output.strip() == "from extension"
    assert runner.invoke(app, ["analyze"]).output.strip() == "builtin"


def test_trusted_only_mode_loads_no_extensions(monkeypatch) -> None:
    monkeypatch.setenv("ATTACKMAP_TRUSTED_ANALYZERS_ONLY", "1")
    assert extensions._entry_points(extensions.LLM_GROUP) == []


class _Ext:
    llm_options = {"tier": {"description": "x", "choices": ["a", "b"]}}

    def validate_llm_run(self, *, provider, backend, model, options):
        if options.get("tier") == "b" and provider != "openai":
            raise ValueError("tier b is OpenAI-only")

    def codex_args(self, *, model, options):
        return ["--tier", options["tier"]] if "tier" in options else []

    def refusal_hint(self, *, model, category):
        return "Ask your admin." if category == "cyber" else None


def test_llm_extension_hooks(monkeypatch) -> None:
    from attackmap import cli

    monkeypatch.setattr(extensions, "llm_extensions", lambda: (("acme", _Ext()),))
    assert cli._parse_llm_options(["tier=a"]) == {"tier": "a"}
    for bad in (["tier=c"], ["other=a"], ["tier"]):
        with pytest.raises(typer.BadParameter):
            cli._parse_llm_options(bad)

    runner, captured = _make_cli_runner("# Review")
    generate_llm_review(_trivial_scan(), _surfaces(), _findings(), [], provider="openai", backend="cli",
                        codex_runner=runner, llm_options={"tier": "b"})
    cmd = captured["cmd"]
    assert cmd[cmd.index("--tier") + 1] == "b" and cmd.index("--tier") < len(cmd) - 1

    with pytest.raises(LlmReviewError, match="tier b is OpenAI-only"):
        generate_llm_review(_trivial_scan(), _surfaces(), _findings(), [], model="claude-opus-5-5",
                            client=_FakeClient(_FakeMessage(content=[])), llm_options={"tier": "b"})

    refused = _FakeMessage(content=[], stop_reason="refusal")
    refused.stop_details = type("D", (), {"category": "cyber", "explanation": None})()
    with pytest.raises(LlmReviewError, match=r"category=cyber\) Ask your admin\."):
        generate_llm_review(_trivial_scan(), _surfaces(), _findings(), [], model="claude-opus-5-5",
                            client=_FakeClient(refused))
