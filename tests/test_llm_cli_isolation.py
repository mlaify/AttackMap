"""The claude/codex CLI backends run isolated from the scanned repository (#232)."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from attackmap import llm_review
from attackmap.llm_review import (
    CLAUDE_CLI_HARDENING_ARGS,
    LlmReviewError,
    generate_llm_review,
    scrub_cli_env,
)
from attackmap.models import ScanResult

HOSTILE_REPO = Path(__file__).parent / "fixtures" / "hostile_agent_repo"
CLAUDE_HELP = "--tools --setting-sources --strict-mcp-config --no-session-persistence"
CODEX_HELP = "--cd --ephemeral --ignore-rules --sandbox"
CLAUDE_OK = '{"type":"result","subtype":"success","is_error":false,"result":"# Review"}'


def _scan() -> ScanResult:
    return ScanResult(root=str(HOSTILE_REPO), languages=["python"], files_scanned=1)


class _Completed:
    def __init__(self, stdout: str) -> None:
        self.stdout = stdout
        self.stderr = ""
        self.returncode = 0


@pytest.fixture
def capture_run(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Patch subprocess.run inside llm_review and record the call."""
    captured: dict[str, Any] = {}

    def fake_run(cmd: list[str], **kwargs: Any) -> _Completed:
        captured["cmd"] = cmd
        captured.update(kwargs)
        cwd = kwargs.get("cwd")
        captured["cwd_existed_empty"] = cwd is not None and Path(cwd).is_dir() and not any(Path(cwd).iterdir())
        return _Completed(captured.get("stdout", ""))

    monkeypatch.setattr(llm_review.subprocess, "run", fake_run)
    monkeypatch.setattr(llm_review.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        llm_review, "_cli_help_text", lambda argv: CLAUDE_HELP if argv[0] == "claude" else CODEX_HELP
    )
    return captured


def test_claude_argv_disables_tools_project_settings_and_mcp() -> None:
    captured: dict[str, Any] = {}

    def runner(cmd: list[str], stdin: str) -> _Completed:
        captured["cmd"] = cmd
        return _Completed(CLAUDE_OK)

    generate_llm_review(_scan(), [], [], [], backend="cli", cli_runner=runner)
    cmd = captured["cmd"]
    assert cmd[cmd.index("--tools") + 1] == ""
    assert cmd[cmd.index("--setting-sources") + 1] == "user"
    assert "--strict-mcp-config" in cmd
    assert cmd[cmd.index("--mcp-config") + 1] == '{"mcpServers":{}}'
    assert "--no-session-persistence" in cmd
    assert "--dangerously-skip-permissions" not in cmd
    assert "--bare" not in cmd  # --bare would drop subscription (OAuth) auth


def test_claude_runs_in_empty_temp_dir_never_the_repo_or_caller_cwd(
    capture_run: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(HOSTILE_REPO)
    capture_run["stdout"] = CLAUDE_OK
    generate_llm_review(_scan(), [], [], [], backend="cli")

    cwd = Path(capture_run["cwd"])
    assert capture_run["cwd_existed_empty"]
    assert cwd.resolve() != HOSTILE_REPO.resolve()
    assert cwd.resolve() != Path(os.getcwd()).resolve()
    assert not cwd.exists(), "the temp dir is removed after the call"
    assert tuple(capture_run["cmd"][3 : 3 + len(CLAUDE_CLI_HARDENING_ARGS)]) == CLAUDE_CLI_HARDENING_ARGS


def test_codex_argv_and_cwd_are_an_ephemeral_temp_dir(
    capture_run: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(HOSTILE_REPO)
    capture_run["stdout"] = "# Review"
    generate_llm_review(_scan(), [], [], [], provider="openai", backend="cli")

    cmd = capture_run["cmd"]
    assert cmd[cmd.index("--cd") + 1] == capture_run["cwd"]
    assert capture_run["cwd_existed_empty"]
    assert Path(capture_run["cwd"]).resolve() != HOSTILE_REPO.resolve()
    assert "--ephemeral" in cmd
    assert "--ignore-rules" in cmd
    assert cmd[cmd.index("--sandbox") + 1] == "read-only"


def test_subprocess_env_is_scrubbed(capture_run: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_leak")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws_leak")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-keep")
    capture_run["stdout"] = CLAUDE_OK
    generate_llm_review(_scan(), [], [], [], backend="cli")

    env = capture_run["env"]
    assert "GITHUB_TOKEN" not in env
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert env["ANTHROPIC_API_KEY"] == "sk-ant-keep"
    assert env["PATH"] == os.environ["PATH"]


@pytest.mark.parametrize("provider", ["claude", "openai"])
def test_refuses_cli_without_hardening_flags(
    capture_run: dict[str, Any], monkeypatch: pytest.MonkeyPatch, provider: str
) -> None:
    monkeypatch.setattr(llm_review, "_cli_help_text", lambda argv: "an old CLI with no such flags")
    with pytest.raises(LlmReviewError, match="isolated from the scanned repository"):
        generate_llm_review(_scan(), [], [], [], provider=provider, backend="cli")  # type: ignore[arg-type]
    assert "cmd" not in capture_run, "the unhardened CLI must never be invoked"


def test_scrub_cli_env_rules() -> None:
    env = {
        "PATH": "/bin",
        "HOME": "/home/u",
        "GITHUB_TOKEN": "x",
        "GH_TOKEN": "x",
        "NPM_TOKEN": "x",
        "DB_PASSWORD": "x",
        "SSH_AUTH_SOCK": "/tmp/agent",
        "AWS_PROFILE": "prod",
        "ANTHROPIC_API_KEY": "a",
        "CLAUDE_CODE_OAUTH_TOKEN": "o",
        "OPENAI_API_KEY": "b",
    }
    claude = scrub_cli_env(env, "claude")
    assert set(claude) == {"PATH", "HOME", "ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"}
    openai = scrub_cli_env(env, "openai")
    assert set(openai) == {"PATH", "HOME", "OPENAI_API_KEY"}


def test_claude_on_bedrock_keeps_cloud_credentials() -> None:
    env = {"CLAUDE_CODE_USE_BEDROCK": "1", "AWS_PROFILE": "p", "AWS_REGION": "us-east-1", "GITHUB_TOKEN": "x"}
    assert set(scrub_cli_env(env, "claude")) == {"CLAUDE_CODE_USE_BEDROCK", "AWS_PROFILE", "AWS_REGION"}
    assert "AWS_PROFILE" not in scrub_cli_env(env, "openai")


@pytest.mark.skipif(
    not (os.environ.get("ATTACKMAP_LIVE_CLI_TESTS") and shutil.which("claude")),
    reason="live test: set ATTACKMAP_LIVE_CLI_TESTS=1 with an authenticated `claude` CLI",
)
def test_live_hostile_repo_hooks_and_mcp_never_fire(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "hook-fired"
    monkeypatch.setenv("ATTACKMAP_HOOK_MARKER", str(marker))
    monkeypatch.chdir(HOSTILE_REPO)
    llm_review._cli_help_text.cache_clear()
    try:
        generate_llm_review(_scan(), [], [], [], backend="cli", model="claude-haiku-4-5-20251001")
    except LlmReviewError:
        pass  # auth/network failures are fine — the hook must still not fire
    assert not marker.exists(), "a hook or MCP server from the scanned repo ran"


def test_help_probe_runs_in_temp_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen.update(kwargs)
        return subprocess.CompletedProcess(cmd, 0, "--tools", "")

    monkeypatch.setattr(llm_review.subprocess, "run", fake_run)
    llm_review._cli_help_text.cache_clear()
    assert "--tools" in llm_review._cli_help_text(("claude-probe-test", "--help"))
    assert seen["cwd"] != os.getcwd()
