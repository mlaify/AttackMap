"""AttackMap's own install/execution supply chain (#237)."""

from __future__ import annotations

import logging
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from attackmap import analyzers
from attackmap.analyzers import (
    analyzer_install_url,
    discover_installed_analyzers,
    install_analyzer_module,
    official_plugin,
    select_requested_analyzers,
)
from attackmap.cli import app
from attackmap.plugins_lock import OFFICIAL_PLUGINS
from attackmap.sdk import AnalyzerMetadata, AnalyzerResult
from attackmap.workflow_scanner import scan_workflows

ROOT = Path(__file__).resolve().parents[1]
runner = CliRunner()
SHA = re.compile(r"@[0-9a-f]{40}$")


# ---------- action.yml ----------


def test_action_has_no_expressions_inside_run_blocks() -> None:
    action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    for step in action["runs"]["steps"]:
        assert "${{" not in step.get("run", ""), step.get("name")


def test_action_pins_every_remote_action_to_a_commit() -> None:
    action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    uses = [s["uses"] for s in action["runs"]["steps"] if "uses" in s]
    assert uses and all(SHA.search(u) for u in uses), uses


def test_self_scan_reports_nothing_for_our_action() -> None:
    assert [i for i in scan_workflows(ROOT) if i.file == "action.yml"] == []


def test_composite_action_injection_and_unpinned_uses_are_flagged(tmp_path: Path) -> None:
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "action.yml").write_text(
        "name: x\nruns:\n  using: composite\n  steps:\n"
        "    - uses: actions/checkout@v4\n"
        "    - shell: bash\n      run: echo \"${{ inputs.title }}\"\n",
        encoding="utf-8",
    )
    kinds = {(i.file, i.kind, i.line) for i in scan_workflows(tmp_path)}
    assert ("nested/action.yml", "script_injection", 7) in kinds
    assert ("nested/action.yml", "unpinned_action", 5) in kinds


# ---------- pinned plugins ----------


def test_every_official_plugin_installs_from_an_immutable_commit() -> None:
    assert len(OFFICIAL_PLUGINS) == 15
    for entry in OFFICIAL_PLUGINS:
        url = analyzer_install_url(entry["package"])
        assert SHA.search(url), url
        assert url.startswith(f"{entry['package']} @ git+https://github.com/mlaify/{entry['repo']}.git@")


def test_all_extra_matches_the_lock() -> None:
    extra = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["optional-dependencies"]["all"]
    pinned = {line for line in extra if " @ git+" in line}
    assert pinned == {analyzer_install_url(e["package"]) for e in OFFICIAL_PLUGINS}


def test_official_plugin_lookup_accepts_analyzer_repo_and_package_names() -> None:
    assert official_plugin("omeka-s")["repo"] == "attack-map-analyzer-omeka-s"
    assert official_plugin("mlaify/attackmap-analyzer-go")["package"] == "attackmap-analyzer-go"
    assert official_plugin("pyhton") is None


# ---------- -m auto-install ----------


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    return repo


def test_unknown_module_errors_without_any_install(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list = []
    monkeypatch.setattr(analyzers.subprocess, "run", lambda *a, **k: calls.append(a))
    result = runner.invoke(app, ["analyze", str(_repo(tmp_path)), "-m", "pyhton", "--install-missing"])
    assert result.exit_code != 0
    assert "not an official AttackMap analyzer" in " ".join(result.output.split())
    assert calls == []


def test_missing_official_module_without_flag_prints_pinned_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list = []
    monkeypatch.setattr(analyzers.subprocess, "run", lambda *a, **k: calls.append(a))
    result = runner.invoke(app, ["analyze", str(_repo(tmp_path)), "-m", "go"])
    assert result.exit_code != 0
    assert "--install-missing" in result.output
    assert re.search(r"attackmap-analyzer-go\.git@[0-9a-f]{40}", result.output.replace("\n", "").replace(" ", "").replace("│", ""))
    assert calls == []


class _FakeGo:
    metadata = AnalyzerMetadata(name="go", description="d", scope="s", ecosystems=("go",))

    @property
    def name(self) -> str:
        return "go"

    def detect(self, root) -> bool:
        return True

    def analyze(self, root) -> AnalyzerResult:
        return AnalyzerResult(root=str(root))


def test_install_missing_installs_the_pinned_commit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    installed: list[str] = []
    state = {"ready": False}
    real_registry = analyzers.get_registered_analyzers

    def fake_install(repo_name: str) -> None:
        installed.append(analyzer_install_url(repo_name))
        state["ready"] = True

    monkeypatch.setattr(analyzers, "install_analyzer_module", fake_install)
    monkeypatch.setattr(analyzers, "get_registered_analyzers", lambda: [*real_registry(), *([_FakeGo()] if state["ready"] else [])])
    selected = select_requested_analyzers(["go"], auto_install=True)
    assert [a.name for a in selected] == ["go"]
    assert len(installed) == 1 and SHA.search(installed[0])


def test_install_refuses_system_interpreter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "base_prefix", sys.prefix)
    monkeypatch.delenv("ATTACKMAP_ALLOW_SYSTEM_INSTALL", raising=False)
    with pytest.raises(RuntimeError, match="system Python"):
        install_analyzer_module("go")


def test_install_surfaces_pip_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "base_prefix", "/definitely/not/the/venv")

    def failing_run(cmd, **kwargs):
        raise subprocess.CalledProcessError(1, cmd, output="", stderr="ERROR: Repository not found.")

    monkeypatch.setattr(analyzers.subprocess, "run", failing_run)
    with pytest.raises(RuntimeError, match="Repository not found"):
        install_analyzer_module("go")


# ---------- third-party entry points ----------


class _FakeDist:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeEntryPoint:
    group = "attackmap.analyzers"

    def __init__(self, name: str, dist: str) -> None:
        self.name = name
        self.dist = _FakeDist(dist)

    def load(self):
        return _FakeGo


class _FakeEntryPoints(list):
    def select(self, group: str):
        return [ep for ep in self if ep.group == group]


def test_third_party_analyzer_warns_and_is_skipped_when_trusted_only(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    eps = _FakeEntryPoints([_FakeEntryPoint("go", "evil-typosquat"), _FakeEntryPoint("go", "attackmap_analyzer_go")])
    monkeypatch.setattr(analyzers, "entry_points", lambda: eps)
    with caplog.at_level(logging.WARNING, logger=analyzers.logger.name):
        assert len(discover_installed_analyzers()) == 2
    assert "evil-typosquat" in caplog.text and "not an official" in caplog.text
    monkeypatch.setenv("ATTACKMAP_TRUSTED_ANALYZERS_ONLY", "1")
    assert len(discover_installed_analyzers()) == 1  # only the official distribution


def test_trusted_only_flag_does_not_leak_into_the_process(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ATTACKMAP_TRUSTED_ANALYZERS_ONLY", raising=False)
    result = runner.invoke(app, ["analyze", str(_repo(tmp_path)), "-o", str(tmp_path / "o"), "--trusted-analyzers-only"])
    assert result.exit_code == 0, result.output
    import os

    assert "ATTACKMAP_TRUSTED_ANALYZERS_ONLY" not in os.environ
