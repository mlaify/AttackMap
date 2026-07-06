"""Tests for test-file exclusion in the heuristic passes (#67)."""

from __future__ import annotations

from pathlib import Path

import pytest

from attackmap.scanner import scan_repo
from attackmap.srcpaths import is_test_file, is_vendored_file


# ---------------------------------------------------------------------------
# is_test_file classification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "rel",
    [
        "tests/test_auth.py",
        "src/__tests__/login.ts",
        "app/spec/models_spec.rb",
        "e2e/checkout.ts",
        "pkg/foo.test.ts",
        "pkg/foo.spec.js",
        "internal/handler_test.go",
        "test_login.py",
        "conftest.py",
        "src/UserServiceTest.java",
        "src/AuthTests.cs",
        "packages/x/fixtures/seed.py",
    ],
)
def test_test_paths_detected(rel: str) -> None:
    assert is_test_file(rel) is True


@pytest.mark.parametrize(
    "rel",
    [
        "src/app.py",
        "services/orders.py",
        "latest.py",          # contains 'test' but not a segment/pattern
        "contest.py",
        "attestation.py",
        "manifest.json",
        "src/protest/view.py",  # 'protest' != 'test' segment
    ],
)
def test_non_test_paths_not_detected(rel: str) -> None:
    assert is_test_file(rel) is False


def test_include_tests_env_disables_exclusion(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ATTACKMAP_INCLUDE_TESTS", "1")
    assert is_test_file("tests/test_auth.py") is False
    assert is_test_file("pkg/foo.test.ts") is False


# ---------------------------------------------------------------------------
# is_vendored_file classification (#95)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "rel",
    [
        "node_modules/lodash/merge.js",
        "UserInterface/External/three.js/three.js",
        "vendor/github.com/x/y.go",
        "third_party/zlib/zlib.js",
        "src/bower_components/jquery/jquery.js",
        "app/static/app.min.js",
        "app/main.bundle.js",
        "sdk/js/types.d.ts",
    ],
)
def test_vendored_paths_detected(rel: str) -> None:
    assert is_vendored_file(rel) is True


@pytest.mark.parametrize(
    "rel",
    [
        "src/app.js",
        "UserInterface/Models/PropertyPath.js",  # not under External/
        "services/external_api.py",              # 'external_api' file, not an 'external' dir
        "vendored_notes.md",                     # not a dir segment
    ],
)
def test_non_vendored_paths_not_detected(rel: str) -> None:
    assert is_vendored_file(rel) is False


def test_include_vendored_env_disables_exclusion(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ATTACKMAP_INCLUDE_VENDORED", "1")
    assert is_vendored_file("node_modules/x/y.js") is False
    assert is_vendored_file("a/b.min.js") is False


def test_weakness_in_vendored_file_excluded_by_default(tmp_path: Path) -> None:
    ext = tmp_path / "External" / "three.js"
    ext.mkdir(parents=True)
    # A ReDoS-shaped regex living in a vendored library.
    (ext / "three.js").write_text(
        "const re = /((?:WC+[\\/:])*)/\n", encoding="utf-8"
    )
    scan = scan_repo(tmp_path)
    assert not [w for w in scan.code_weaknesses if w.kind == "redos"]


def test_weakness_in_vendored_file_included_with_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ATTACKMAP_INCLUDE_VENDORED", "1")
    ext = tmp_path / "External"
    ext.mkdir(parents=True)
    (ext / "lib.js").write_text("const re = /^(a+)+$/\n", encoding="utf-8")
    scan = scan_repo(tmp_path)
    assert any(w.kind == "redos" for w in scan.code_weaknesses)


# ---------------------------------------------------------------------------
# Integration: weakness passes skip test files by default
# ---------------------------------------------------------------------------


def _repo_with_test_weakness(tmp_path: Path) -> Path:
    testdir = tmp_path / "tests"
    testdir.mkdir()
    # A crypto weakness that lives only in a test file.
    (testdir / "crypto_helpers.py").write_text(
        "import hashlib\n"
        "def make(password):\n"
        "    return hashlib.md5(password.encode()).hexdigest()\n",
        encoding="utf-8",
    )
    return tmp_path


def test_crypto_in_test_file_excluded_by_default(tmp_path: Path) -> None:
    scan = scan_repo(_repo_with_test_weakness(tmp_path))
    assert scan.crypto_weaknesses == []


def test_crypto_in_test_file_included_with_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ATTACKMAP_INCLUDE_TESTS", "1")
    scan = scan_repo(_repo_with_test_weakness(tmp_path))
    assert any(w.kind == "weak_password_hash" for w in scan.crypto_weaknesses)


def test_taint_sink_in_test_file_excluded_by_default(tmp_path: Path) -> None:
    testdir = tmp_path / "__tests__"
    testdir.mkdir()
    (testdir / "app.py").write_text(
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/x', methods=['POST'])\n"
        "def x():\n"
        "    return eval(request.get_json()['e'])\n",
        encoding="utf-8",
    )
    scan = scan_repo(tmp_path)
    assert scan.taint_chains == []


def test_production_file_still_scanned(tmp_path: Path) -> None:
    # A non-test sibling in the same repo must still be flagged.
    (tmp_path / "auth.py").write_text(
        "import hashlib\n"
        "def make(password):\n"
        "    return hashlib.md5(password.encode()).hexdigest()\n",
        encoding="utf-8",
    )
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_auth.py").write_text(
        "import hashlib\nx = hashlib.md5(password)\n", encoding="utf-8"
    )
    scan = scan_repo(tmp_path)
    hits = [w for w in scan.crypto_weaknesses if w.kind == "weak_password_hash"]
    assert len(hits) == 1
    assert hits[0].file == "auth.py"
