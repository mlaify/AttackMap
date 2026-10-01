"""Malformed suppress files never crash the CLI (#225)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from attackmap.cli import app
from attackmap.suppress import load_suppress_file

runner = CliRunner()
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _load(tmp_path: Path, body: str | bytes):
    target = tmp_path / ".attackmap-suppress.yaml"
    target.write_bytes(body if isinstance(body, bytes) else body.encode("utf-8"))
    warnings: list[str] = []
    return load_suppress_file(tmp_path, warnings), warnings


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("suppress:\n  - rule: hardcoded-secret\n    reason: r\n    paths: 5\n", "'paths' must be a string or a list"),
        ("suppress:\n  - rule: x\n    reason: r\n    paths: [a, 3]\n", "'paths' must be a string or a list"),
        ("suppress:\n  rule: x\n  reason: r\n", "'suppress' must be a list"),
        ("suppress:\n  - id: 1234567890123456\n    reason: r\n", "quote it"),
        ("suppress:\n  - id: 0x1f\n    reason: r\n", "quote it"),
        ("suppress:\n  - id: not-an-id\n    reason: r\n", "not a 16-hex finding id"),
        ("suppress:\n  - rule: 42\n    reason: r\n", "'rule' must be a rule id string"),
        ("suppress:\n  - rule: x\n    reason: [a, b]\n", "without a text 'reason'"),
        ("version: 7\nsuppress: []\n", "unknown version 7"),
        ("suppress: [\n", "Failed to parse"),
        ("- just\n- strings\n", "non-mapping entry"),
        ("42\n", "expected a list or a mapping"),
    ],
)
def test_malformed_files_become_warnings(tmp_path: Path, body: str, expected: str) -> None:
    _, warnings = _load(tmp_path, body)
    assert any(expected in w for w in warnings), warnings


def test_non_utf8_file_is_a_warning(tmp_path: Path) -> None:
    sups, warnings = _load(tmp_path, b"suppress:\n  - rule: x\n    reason: caf\xe9\n")
    assert sups == [] and any("not valid UTF-8" in w for w in warnings)


def test_one_bad_entry_does_not_drop_the_good_ones(tmp_path: Path) -> None:
    sups, warnings = _load(
        tmp_path,
        "suppress:\n  - rule: a\n    reason: r\n    paths: 5\n"
        "  - rule: hardcoded-secret\n    reason: ok\n"
        '  - id: "0123456789abcdef"\n    reason: ok\n',
    )
    assert [(s.rule, s.id) for s in sups] == [("hardcoded-secret", None), (None, "0123456789abcdef")]
    assert len(warnings) == 1


def test_symlinked_suppress_file_is_not_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside.yaml"
    outside.write_text("suppress:\n  - rule: hardcoded-secret\n    reason: r\n", encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".attackmap-suppress.yaml").symlink_to(outside)
    warnings: list[str] = []
    assert load_suppress_file(repo, warnings) == []
    assert any("Failed to parse" in w for w in warnings)


@pytest.mark.parametrize(
    "body",
    ["suppress:\n  - paths: 5\n    reason: r\n", "suppress: {a: 1}\n", "suppress:\n  - id: 12345\n    reason: r\n", "\x00\x01garbage: [\n"],
)
def test_cli_never_crashes_on_a_malformed_file(tmp_path: Path, body: str) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    (repo / ".attackmap-suppress.yaml").write_text(body, encoding="utf-8")
    result = runner.invoke(app, ["analyze", str(repo), "-o", str(tmp_path / "o"), "--format", "json"])
    assert result.exit_code == 0, result.output
    assert result.exception is None
    assert "Suppression warning" in _ANSI.sub("", result.output)
