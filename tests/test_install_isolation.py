"""`attackmap suggest --install` / `--install-missing` must not run code from
the scanned checkout (GHSA-qv53-p57x-x9m4): `python -m pip` puts the current
directory first on sys.path, so a committed `pip/` package ran instead of pip."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from attackmap import analyzers
from attackmap.analyzers import analyzer_install_command, install_analyzer_module

FAKE_PIP = {
    "pip/__init__.py": "import os, pathlib\n"
    "pathlib.Path(os.environ['POC_MARKER']).write_text('repo pip imported')\n",
    "pip/__main__.py": "import sys\nprint('FAKE PIP RAN'); sys.exit(0)\n",
}


def _checkout_with_fake_pip(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    for rel, body in FAKE_PIP.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(body, encoding="utf-8")
    return repo


def test_install_command_runs_python_in_isolated_mode() -> None:
    command = analyzer_install_command("go")
    assert command[:4] == [sys.executable, "-I", "-m", "pip"]


def test_isolated_mode_keeps_a_checkout_pip_package_off_sys_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The interpreter itself: from inside the checkout, `-m pip` without -I
    imports the repo's package; with -I (what AttackMap now runs) it does not."""
    repo = _checkout_with_fake_pip(tmp_path)
    marker = tmp_path / "marker.txt"
    env = {**os.environ, "POC_MARKER": str(marker)}
    env.pop("PYTHONSAFEPATH", None)
    unsafe = subprocess.run([sys.executable, "-m", "pip", "--version"], cwd=repo, env=env, capture_output=True, text=True)
    assert "FAKE PIP RAN" in unsafe.stdout and marker.exists()  # the vulnerable shape
    marker.unlink()
    safe = subprocess.run([sys.executable, "-I", "-m", "pip", "--version"], cwd=repo, env=env, capture_output=True, text=True)
    assert "FAKE PIP RAN" not in safe.stdout
    assert not marker.exists()


def test_install_runs_outside_the_checkout_with_a_clean_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _checkout_with_fake_pip(tmp_path)
    monkeypatch.chdir(repo)
    monkeypatch.setenv("PYTHONPATH", str(repo))
    monkeypatch.setattr(analyzers.sys, "prefix", "/venv")
    monkeypatch.setattr(analyzers.sys, "base_prefix", "/usr")
    seen: dict = {}

    def fake_run(command, **kwargs):  # noqa: ANN001
        seen["command"] = command
        seen["cwd"] = kwargs.get("cwd")
        seen["cwd_empty"] = not any(Path(kwargs["cwd"]).iterdir())
        seen["env"] = kwargs.get("env")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(analyzers.subprocess, "run", fake_run)
    install_analyzer_module("go")
    assert seen["command"][1] == "-I"
    assert seen["cwd"] is not None and Path(seen["cwd"]).resolve() != repo.resolve()
    assert seen["cwd_empty"]
    assert "PYTHONPATH" not in seen["env"]
    assert seen["env"]["PYTHONSAFEPATH"] == "1"
