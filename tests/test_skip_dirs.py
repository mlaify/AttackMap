"""Skip directories are matched relative to the scanned root (#215)."""

from __future__ import annotations

import re
import shutil
from pathlib import Path

from typer.testing import CliRunner

from attackmap.analyzers import resolve_run_analyzers
from attackmap.cli import app
from attackmap.scanner import scan_repo
from attackmap.srcpaths import SKIP_DIRS, in_skipped_dir

runner = CliRunner()
_ANSI = re.compile(r"\x1b\[[0-9;]*m")

FILES = {
    "app.py": "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/x')\ndef x():\n    return 'x'\n",
    "web/App.tsx": "export const App = () => null;\n",
    "node_modules/lib/index.js": "app.get('/vendored', h)\n",
    "dist/bundle.js": "app.get('/built', h)\n",
}


def _make(root: Path) -> Path:
    for rel, body in FILES.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(body, encoding="utf-8")
    return root


def test_repo_under_a_build_directory_scans_the_same(tmp_path: Path) -> None:
    plain = scan_repo(_make(tmp_path / "proj"))
    shutil.copytree(tmp_path / "proj", tmp_path / "build" / "proj")
    nested = scan_repo(tmp_path / "build" / "proj")
    assert plain.files_scanned == nested.files_scanned == 2
    assert [r.path for r in nested.routes] == [r.path for r in plain.routes] == ["/x"]


def test_detect_runs_for_a_repo_under_dist(tmp_path: Path) -> None:
    repo = _make(tmp_path / "dist" / "out" / "proj")
    names = {a.name for a in resolve_run_analyzers(repo, None)}
    assert {"python-web", "javascript-web"} <= names


def test_skipped_dirs_inside_the_repo_are_still_skipped(tmp_path: Path) -> None:
    scan = scan_repo(_make(tmp_path / "proj"))
    assert "/vendored" not in {r.path for r in scan.routes}
    assert "/built" not in {r.path for r in scan.routes}


def test_in_skipped_dir_only_looks_at_directories() -> None:
    assert in_skipped_dir("node_modules/x.js") and in_skipped_dir("a/target/b.rs")
    assert not in_skipped_dir("build.py") and not in_skipped_dir("src/out.ts")
    assert {"venv", "target", ".tox", ".attackmap-gui"} <= SKIP_DIRS


def test_cli_warns_when_nothing_was_scanned(tmp_path: Path) -> None:
    repo = tmp_path / "docs-only"
    repo.mkdir()
    (repo / "README.md").write_text("# hi\n", encoding="utf-8")
    result = runner.invoke(app, ["analyze", str(repo), "-o", str(tmp_path / "o")])
    assert result.exit_code == 0
    assert "no source files were scanned" in " ".join(_ANSI.sub("", result.output).split())
