"""attackmap.sdk.fs: the shared plugin walker and reader (#253)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from attackmap.safe_fs import OUTPUT_MARKER
from attackmap.sdk import DEFAULT_SKIP_DIRS, iter_repo_files, line_of, line_snippet, read_source, rel

needs_chmod = pytest.mark.skipif(
    sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="chmod 000 is not enforced on Windows or for root",
)


def _names(root: Path, **kw) -> list[str]:
    return [rel(p, root) for p in iter_repo_files(root, **kw)]


def test_repo_under_a_skip_dir_name_is_still_walked(tmp_path: Path) -> None:
    repo = tmp_path / "build" / "out" / "vendor" / "repo"
    (repo / "pkg").mkdir(parents=True)
    (repo / "pkg" / "main.go").write_text("package main\n")
    assert _names(repo, suffixes={".go"}) == ["pkg/main.go"]


def test_skip_dirs_are_pruned_by_relative_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "node_modules" / "dep").mkdir(parents=True)
    (tmp_path / "node_modules" / "dep" / "index.js").write_text("x")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.js").write_text("x")
    entered: list[str] = []
    real_walk = os.walk

    def spy(top, *a, **kw):
        for dirpath, dirnames, filenames in real_walk(top, *a, **kw):
            entered.append(Path(dirpath).name)
            yield dirpath, dirnames, filenames

    monkeypatch.setattr(os, "walk", spy)
    assert _names(tmp_path, suffixes={".js"}) == ["src/app.js"]
    assert "node_modules" not in entered and "dep" not in entered
    assert "node_modules" in DEFAULT_SKIP_DIRS


def test_suffix_and_name_filters(tmp_path: Path) -> None:
    for name in ("go.mod", "main.go", "UTIL.GO", "README.md"):
        (tmp_path / name).write_text("x")
    assert sorted(_names(tmp_path, suffixes={".go"}, names={"go.mod"})) == ["UTIL.GO", "go.mod", "main.go"]


def test_symlink_escape_is_not_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.go").write_text("const KEY = 1\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "linked.go").symlink_to(outside / "secret.go")
    skipped: list[tuple[str, str]] = []
    assert _names(repo, on_skip=lambda p, why: skipped.append((p.name, why))) == []
    assert skipped == [("linked.go", "symlink not followed")]
    assert read_source("linked.go", root=repo) is None


def test_oversized_file_is_skipped(tmp_path: Path) -> None:
    (tmp_path / "big.js").write_bytes(b"a" * (5 * 1024 * 1024))
    (tmp_path / "small.js").write_text("x")
    skipped: list[str] = []
    assert _names(tmp_path, on_skip=lambda p, why: skipped.append(why)) == ["small.js"]
    assert skipped == ["oversized file skipped"]


def test_attackmap_output_dirs_are_skipped(tmp_path: Path) -> None:
    (tmp_path / "reports").mkdir()
    (tmp_path / "reports" / OUTPUT_MARKER).write_text("")
    (tmp_path / "reports" / "attackmap-report.json").write_text("{}")
    (tmp_path / ".attackmap-gui").mkdir()
    (tmp_path / ".attackmap-gui" / "r.json").write_text("{}")
    (tmp_path / "lexicon.json").write_text("{}")
    assert _names(tmp_path, suffixes={".json"}) == ["lexicon.json"]


def test_tests_can_be_excluded(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_app.py").write_text("x")
    (tmp_path / "app.py").write_text("x")
    assert _names(tmp_path, include_tests=False) == ["app.py"]
    assert len(_names(tmp_path)) == 2


@needs_chmod
def test_unreadable_file_returns_none(tmp_path: Path) -> None:
    locked = tmp_path / "locked.php"
    locked.write_text("<?php\n")
    locked.chmod(0)
    try:
        assert _names(tmp_path) == ["locked.php"]
        assert read_source(locked) is None
    finally:
        locked.chmod(0o644)


def test_legacy_encodings_and_binary(tmp_path: Path) -> None:
    (tmp_path / "legacy.php").write_bytes("<?php // café – résumé\n".encode("cp1252"))
    assert read_source(tmp_path / "legacy.php") == "<?php // café – résumé\n"
    (tmp_path / "latin.c").write_bytes(b"/* \x81\x8d */\n")  # undefined in cp1252
    assert read_source(tmp_path / "latin.c") == "/* \x81\x8d */\n"
    (tmp_path / "bom.py").write_bytes(b"\xef\xbb\xbfx = 1\n")
    assert read_source(tmp_path / "bom.py") == "x = 1\n"
    (tmp_path / "blob.bin").write_bytes(b"\x7fELF\x00\x01")
    assert read_source(tmp_path / "blob.bin") is None


def test_line_helpers() -> None:
    content = "a\n  bb  \nccc"
    assert line_of(content, content.index("bb")) == 2
    assert line_snippet(content, 2) == "bb"
    assert line_snippet(content, 9) == ""
    assert line_snippet("x" * 300, 1, max_len=10) == "x" * 9 + "…"
