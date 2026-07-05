"""Tests for the SBOM inventory analyzer (#48, slice 1)."""

from __future__ import annotations

from pathlib import Path

import pytest

from attackmap.models import DependencyHint, ScanResult
from attackmap.sbom import analyze_sbom
from attackmap.scanner import scan_repo


FIXTURES = Path(__file__).parent / "fixtures"
REPO = FIXTURES / "sbom_repo"


def _by_ecosystem(hints: list[DependencyHint]) -> dict[str, list[DependencyHint]]:
    out: dict[str, list[DependencyHint]] = {}
    for h in hints:
        out.setdefault(h.ecosystem, []).append(h)
    return out


# ---------------------------------------------------------------------------
# Missing / empty repo
# ---------------------------------------------------------------------------


def test_missing_path_returns_empty(tmp_path: Path) -> None:
    assert analyze_sbom(tmp_path / "nope") == []


def test_repo_without_manifests_returns_empty(tmp_path: Path) -> None:
    (tmp_path / "readme.md").write_text("hi\n", encoding="utf-8")
    assert analyze_sbom(tmp_path) == []


# ---------------------------------------------------------------------------
# pyproject.toml (PEP 621)
# ---------------------------------------------------------------------------


def test_pyproject_pep621_dependencies() -> None:
    hints = analyze_sbom(REPO)
    py = [h for h in hints if h.ecosystem == "pypi" and h.file.endswith("pyproject.toml")]
    names = {h.name for h in py}
    assert {"flask", "requests", "sqlalchemy", "pytest", "ruff"} <= names


def test_pyproject_dev_group_marks_dev_true() -> None:
    hints = analyze_sbom(REPO)
    py = {h.name: h for h in hints if h.ecosystem == "pypi" and h.file.endswith("pyproject.toml")}
    assert py["flask"].dev is False
    assert py["pytest"].dev is True
    assert py["ruff"].dev is True


def test_pyproject_pep508_marker_stripped_from_version() -> None:
    hints = analyze_sbom(REPO)
    sqla = next(h for h in hints if h.name == "sqlalchemy")
    # Marker `; python_version >= ...` must not end up in version text.
    assert ";" not in sqla.version
    assert "python_version" not in sqla.version


def test_pyproject_extras_stripped_from_name() -> None:
    hints = analyze_sbom(REPO)
    sqla = next(h for h in hints if h.name == "sqlalchemy")
    # `sqlalchemy[asyncio]` — name should be the bare package, not the extras.
    assert sqla.name == "sqlalchemy"


def test_poetry_style_pyproject_supported(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[tool.poetry]\nname = 'x'\nversion = '0.1'\n\n"
        "[tool.poetry.dependencies]\n"
        "python = '^3.11'\n"
        "requests = '^2.28'\n"
        "django = { version = '^5.0', extras = ['bcrypt'] }\n\n"
        "[tool.poetry.dev-dependencies]\n"
        "pytest = '^8.0'\n",
        encoding="utf-8",
    )
    hints = analyze_sbom(tmp_path)
    names = {h.name: h for h in hints}
    assert "python" not in names  # runtime marker, not a dep
    assert names["requests"].dev is False
    assert names["django"].version == "^5.0"
    assert names["pytest"].dev is True


# ---------------------------------------------------------------------------
# requirements.txt
# ---------------------------------------------------------------------------


def test_requirements_txt_pinned_and_ranged_versions() -> None:
    hints = analyze_sbom(REPO)
    req = {h.name: h for h in hints if h.file.endswith("requirements.txt")}
    assert req["gunicorn"].version == "==21.2.0"
    assert req["psycopg2-binary"].version.startswith(">=")


def test_requirements_txt_skips_comments_and_flags() -> None:
    hints = analyze_sbom(REPO)
    req_hints = [h for h in hints if h.file.endswith("requirements.txt")]
    names = {h.name for h in req_hints}
    # `-r ../base-requirements.txt` — the `-r` line must not become a dep.
    assert not any(name.startswith("-") for name in names)


# ---------------------------------------------------------------------------
# package.json
# ---------------------------------------------------------------------------


def test_package_json_dependencies_and_dev_split() -> None:
    hints = analyze_sbom(REPO)
    npm = {h.name: h for h in hints if h.ecosystem == "npm"}
    assert npm["express"].dev is False
    assert npm["typescript"].dev is True
    assert npm["express"].version == "^4.16.0"


def test_package_json_scoped_names_preserved() -> None:
    hints = analyze_sbom(REPO)
    assert any(h.name == "@types/node" for h in hints if h.ecosystem == "npm")


# ---------------------------------------------------------------------------
# go.mod
# ---------------------------------------------------------------------------


def test_go_mod_block_form_and_indirect_flag() -> None:
    hints = analyze_sbom(REPO)
    go = {h.name: h for h in hints if h.ecosystem == "go"}
    assert go["github.com/gin-gonic/gin"].version == "v1.9.1"
    assert go["github.com/jackc/pgx/v5"].version == "v5.5.2"
    # `// indirect` comment → dev=True (we treat indirect as build-time).
    assert go["golang.org/x/text"].dev is True


def test_go_mod_single_line_require_supported() -> None:
    hints = analyze_sbom(REPO)
    go_names = {h.name for h in hints if h.ecosystem == "go"}
    assert "github.com/spf13/cobra" in go_names


# ---------------------------------------------------------------------------
# Cargo.toml
# ---------------------------------------------------------------------------


def test_cargo_dependencies_and_dev_split() -> None:
    hints = analyze_sbom(REPO)
    cargo = {h.name: h for h in hints if h.ecosystem == "cargo"}
    assert cargo["tokio"].version == "1"
    # Object form: `serde = { version = "1.0", features = [...] }` — version
    # is the "1.0" string.
    assert cargo["serde"].version == "1.0"
    assert cargo["criterion"].dev is True


# ---------------------------------------------------------------------------
# composer.json
# ---------------------------------------------------------------------------


def test_composer_dependencies_and_dev_split() -> None:
    hints = analyze_sbom(REPO)
    php = {h.name: h for h in hints if h.ecosystem == "composer"}
    assert php["laminas/laminas-mvc"].dev is False
    assert php["phpunit/phpunit"].dev is True


def test_composer_platform_requirements_skipped() -> None:
    """`php`, `ext-*`, and `lib-*` in composer.json aren't third-party
    packages and should be filtered out of the SBOM."""
    hints = analyze_sbom(REPO)
    names = {h.name for h in hints if h.ecosystem == "composer"}
    assert "php" not in names
    assert not any(n.startswith("ext-") for n in names)


# ---------------------------------------------------------------------------
# Integration: scanner + provenance + dedup
# ---------------------------------------------------------------------------


def test_scan_repo_populates_dependencies_field() -> None:
    scan = scan_repo(REPO)
    assert scan.dependencies
    assert all(isinstance(d, DependencyHint) for d in scan.dependencies)


def test_dependency_source_analyzer_is_sbom() -> None:
    scan = scan_repo(REPO)
    assert scan.dependencies
    assert all(d.source_analyzer == "sbom" for d in scan.dependencies)


def test_dedup_across_files_when_same_name_and_version(tmp_path: Path) -> None:
    """Two identical entries in the same manifest should collapse."""
    (tmp_path / "package.json").write_text(
        '{"name":"x","dependencies":{"express":"^4.16.0"},"peerDependencies":{"express":"^4.16.0"}}',
        encoding="utf-8",
    )
    hints = analyze_sbom(tmp_path)
    express = [h for h in hints if h.name == "express"]
    assert len(express) == 1


def test_malformed_manifest_does_not_sink_scan(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{not json", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\ndependencies=['requests']\n", encoding="utf-8")
    hints = analyze_sbom(tmp_path)
    # bad package.json skipped; pyproject still parsed.
    assert any(h.name == "requests" for h in hints)


def test_ecosystem_coverage_is_all_five() -> None:
    hints = analyze_sbom(REPO)
    seen = {h.ecosystem for h in hints}
    assert seen == {"pypi", "npm", "go", "cargo", "composer"}


# ---------------------------------------------------------------------------
# Unified Signal stream includes dependencies
# ---------------------------------------------------------------------------


def test_all_signals_yields_dependency_signals() -> None:
    scan = scan_repo(REPO)
    kinds = {sig.kind for sig in scan.all_signals()}
    assert "dependency" in kinds


def test_all_signals_dependency_carries_ecosystem_property() -> None:
    scan = ScanResult(
        root="/",
        dependencies=[
            DependencyHint(name="express", version="^4.16.0", ecosystem="npm", file="package.json"),
        ],
    )
    sig = next(s for s in scan.all_signals() if s.kind == "dependency")
    assert sig.properties["ecosystem"] == "npm"
    assert sig.properties["name"] == "express"
    assert "^4.16.0" in sig.label
