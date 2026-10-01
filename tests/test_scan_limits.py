"""Hostile file sizes and shapes can't stall a scan (#236)."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from attackmap.scanner import scan_repo
from attackmap.safe_fs import DEFAULT_MAX_FILE_BYTES, max_file_bytes


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/ok')\ndef ok():\n    return 'ok'\n",
        encoding="utf-8",
    )
    return repo


def test_oversized_file_is_skipped_quickly_and_reported(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    with (repo / "huge.py").open("w", encoding="utf-8") as fh:
        chunk = "x = 'A" + "A" * 1_000_000 + "'\n"
        for _ in range(50):  # ~50 MB
            fh.write(chunk)
    start = time.perf_counter()
    scan = scan_repo(repo)
    assert time.perf_counter() - start < 5
    assert any(lim.startswith("oversized file skipped") and lim.endswith("huge.py") for lim in scan.limitations)
    assert [r.path for r in scan.routes] == ["/ok"]


@pytest.mark.parametrize(
    "payload",
    [
        "x = " + "a" * 200_000 + "\n",  # one 200 KB word (the issue's hang)
        "router" + "_" * 200_000 + " = APIRouter(\n",
        "bp = Blueprint(" + "a" * 200_000 + "\n",
        "type Query {\n  " + "f" * 200_000 + "\n}\n",
    ],
    ids=["long_word", "router_assign", "blueprint", "graphql_field"],
)
def test_long_lines_under_the_cap_scan_in_linear_time(tmp_path: Path, payload: str) -> None:
    repo = _repo(tmp_path)
    (repo / "big.py").write_text(payload, encoding="utf-8")
    (repo / "schema.graphql").write_text(payload, encoding="utf-8")
    start = time.perf_counter()
    scan_repo(repo)
    assert time.perf_counter() - start < 5


def test_max_file_bytes_env_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    assert max_file_bytes() == DEFAULT_MAX_FILE_BYTES
    monkeypatch.setenv("ATTACKMAP_MAX_FILE_BYTES", "10")
    assert max_file_bytes() == 10
    repo = _repo(tmp_path)
    scan = scan_repo(repo)
    assert scan.routes == []
    assert any("app.py" in lim for lim in scan.limitations)
    monkeypatch.setenv("ATTACKMAP_MAX_FILE_BYTES", "not-a-number")
    assert max_file_bytes() == DEFAULT_MAX_FILE_BYTES
