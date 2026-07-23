"""Tests for lockfile resolution (#143)."""

from __future__ import annotations

import json
from pathlib import Path

from attackmap.lockfiles import parse_lockfiles
from attackmap.sbom import analyze_sbom


def _by_name(hints):
    return {h.name: h for h in hints}


# --- npm: package-lock.json ------------------------------------------------


def _write_package_lock_v3(root: Path) -> None:
    (root / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {
                        "dependencies": {"express": "^4.18.0"},
                        "devDependencies": {"jest": "^29.0.0"},
                    },
                    "node_modules/express": {
                        "version": "4.18.2",
                        "dependencies": {"body-parser": "1.20.1"},
                    },
                    "node_modules/body-parser": {
                        "version": "1.20.1",
                        "dependencies": {"qs": "6.11.0"},
                    },
                    "node_modules/qs": {"version": "6.11.0"},
                    "node_modules/jest": {"version": "29.5.0", "dev": True},
                },
            }
        ),
        encoding="utf-8",
    )


def test_package_lock_v3_resolves_exact_versions_and_transitive_path(tmp_path: Path) -> None:
    _write_package_lock_v3(tmp_path)
    hints, superseded = parse_lockfiles(tmp_path)
    assert ("npm", ".") in superseded
    by_name = _by_name(hints)

    # Direct, exact version.
    assert by_name["express"].version == "4.18.2"
    assert by_name["express"].direct is True
    assert by_name["express"].resolved is True

    # Transitive with a full resolution path (AC1 + AC2).
    assert by_name["qs"].version == "6.11.0"
    assert by_name["qs"].direct is False
    assert by_name["qs"].via == "express > body-parser > qs"

    # Dev dependency preserved.
    assert by_name["jest"].dev is True


def test_package_lock_v1_nested_dependencies(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 1,
                "dependencies": {
                    "express": {
                        "version": "4.18.2",
                        "requires": {"body-parser": "1.20.1"},
                        "dependencies": {
                            "body-parser": {"version": "1.20.1"},
                        },
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    hints, _ = parse_lockfiles(tmp_path)
    by_name = _by_name(hints)
    assert by_name["express"].version == "4.18.2"
    assert by_name["express"].direct is True
    assert by_name["body-parser"].version == "1.20.1"
    assert by_name["body-parser"].direct is False


# --- pypi: poetry.lock / uv.lock -------------------------------------------


def test_poetry_lock_transitive_path_and_dev(tmp_path: Path) -> None:
    (tmp_path / "poetry.lock").write_text(
        """
[[package]]
name = "flask"
version = "2.3.2"
category = "main"
[package.dependencies]
werkzeug = ">=2.3.0"

[[package]]
name = "werkzeug"
version = "2.3.6"
category = "main"

[[package]]
name = "pytest"
version = "7.4.0"
category = "dev"
""",
        encoding="utf-8",
    )
    hints, superseded = parse_lockfiles(tmp_path)
    assert ("pypi", ".") in superseded
    by_name = _by_name(hints)
    assert by_name["flask"].version == "2.3.2"
    assert by_name["flask"].direct is True
    assert by_name["werkzeug"].version == "2.3.6"
    assert by_name["werkzeug"].direct is False
    assert by_name["werkzeug"].via == "flask > werkzeug"
    assert by_name["pytest"].dev is True


def test_uv_lock_resolves_packages(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(
        """
[[package]]
name = "httpx"
version = "0.25.0"
dependencies = [{ name = "httpcore" }]

[[package]]
name = "httpcore"
version = "0.18.0"
""",
        encoding="utf-8",
    )
    hints, _ = parse_lockfiles(tmp_path)
    by_name = _by_name(hints)
    assert by_name["httpx"].version == "0.25.0"
    assert by_name["httpcore"].version == "0.18.0"
    assert by_name["httpcore"].via == "httpx > httpcore"


# --- cargo: Cargo.lock -----------------------------------------------------


def test_cargo_lock_transitive_path_and_local_crate_excluded(tmp_path: Path) -> None:
    # `myapp` is the workspace crate (no `source`) — it must NOT be emitted,
    # and its dependencies (serde) are the DIRECT deps, not transitive-via-myapp.
    (tmp_path / "Cargo.lock").write_text(
        """
[[package]]
name = "myapp"
version = "0.1.0"
dependencies = ["serde"]

[[package]]
name = "serde"
version = "1.0.190"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = ["serde_derive"]

[[package]]
name = "serde_derive"
version = "1.0.190"
source = "registry+https://github.com/rust-lang/crates.io-index"
""",
        encoding="utf-8",
    )
    hints, superseded = parse_lockfiles(tmp_path)
    assert ("cargo", ".") in superseded
    by_name = _by_name(hints)
    assert "myapp" not in by_name  # local workspace crate not a dependency
    assert by_name["serde"].version == "1.0.190"
    assert by_name["serde"].direct is True  # direct dep of the workspace crate
    assert by_name["serde_derive"].via == "serde > serde_derive"


# --- npm: pnpm-lock.yaml ---------------------------------------------------


def test_pnpm_lock_roots_and_transitive(tmp_path: Path) -> None:
    (tmp_path / "pnpm-lock.yaml").write_text(
        """lockfileVersion: '6.0'
importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.17.0
        version: 4.17.21
packages:
  /lodash@4.17.21:
    resolution: {integrity: sha512-abc}
    dev: false
  /minimist@1.2.5:
    resolution: {integrity: sha512-def}
    dev: false
""",
        encoding="utf-8",
    )
    hints, superseded = parse_lockfiles(tmp_path)
    assert ("npm", ".") in superseded
    by_name = _by_name(hints)
    assert by_name["lodash"].version == "4.17.21"
    assert by_name["lodash"].direct is True
    assert by_name["minimist"].version == "1.2.5"


def test_pnpm_lock_multi_document_merges_all(tmp_path: Path) -> None:
    # Some pnpm-lock.yaml files concatenate several YAML documents with `---`
    # separators (seen in the wild, e.g. bluesky-social/atproto). A single-doc
    # load raises yaml.ComposerError and previously aborted the whole scan
    # (regression). We must parse every document and merge them.
    (tmp_path / "pnpm-lock.yaml").write_text(
        """---
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.17.0
        version: 4.17.21
packages:
  lodash@4.17.21:
    resolution: {integrity: sha512-abc}
---
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      express:
        specifier: ^4.18.0
        version: 4.18.2
packages:
  express@4.18.2:
    resolution: {integrity: sha512-def}
""",
        encoding="utf-8",
    )
    hints, superseded = parse_lockfiles(tmp_path)
    assert ("npm", ".") in superseded
    by_name = _by_name(hints)
    # Both documents contribute their packages and roots.
    assert by_name["lodash"].version == "4.17.21"
    assert by_name["express"].version == "4.18.2"
    assert by_name["lodash"].direct is True
    assert by_name["express"].direct is True


def test_pnpm_lock_malformed_yaml_yields_no_hints_without_crashing(tmp_path: Path) -> None:
    # A lockfile we can't parse must never abort the scan — it just yields
    # no dependency hints.
    (tmp_path / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\npackages:\n  - : : broken\n   bad indent\n",
        encoding="utf-8",
    )
    # The key property: the call returns (a list) instead of raising a
    # yaml.YAMLError that would abort the scan.
    hints, superseded = parse_lockfiles(tmp_path)
    assert isinstance(hints, list)


def test_uv_local_project_excluded_and_deps_direct(tmp_path: Path) -> None:
    # The project package (editable source) is not an SBOM entry; its deps
    # are the direct dependencies.
    (tmp_path / "uv.lock").write_text(
        """
[[package]]
name = "my-project"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "httpx" }]

[[package]]
name = "httpx"
version = "0.25.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "httpcore" }]

[[package]]
name = "httpcore"
version = "0.18.0"
source = { registry = "https://pypi.org/simple" }
""",
        encoding="utf-8",
    )
    hints, _ = parse_lockfiles(tmp_path)
    by_name = _by_name(hints)
    assert "my-project" not in by_name
    assert by_name["httpx"].direct is True
    assert by_name["httpcore"].via == "httpx > httpcore"


def test_npm_multiple_installed_versions_all_preserved(tmp_path: Path) -> None:
    """A hoisted x@2 and a nested x@1 must both survive (no version dropped)."""
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"a": "^1.0.0", "x": "^2.0.0"}},
                    "node_modules/x": {"version": "2.0.0"},
                    "node_modules/a": {"version": "1.0.0", "dependencies": {"x": "1.5.0"}},
                    "node_modules/a/node_modules/x": {"version": "1.5.0"},
                },
            }
        ),
        encoding="utf-8",
    )
    hints, _ = parse_lockfiles(tmp_path)
    x_versions = sorted(h.version for h in hints if h.name == "x")
    assert x_versions == ["1.5.0", "2.0.0"]


def test_go_sum_is_not_parsed(tmp_path: Path) -> None:
    """go.sum is a checksum history, not the build list — Go resolution comes
    from go.mod instead (which is already exact)."""
    (tmp_path / "go.sum").write_text(
        "github.com/gin-gonic/gin v1.9.0 h1:abc=\n", encoding="utf-8"
    )
    hints, superseded = parse_lockfiles(tmp_path)
    assert hints == []
    assert superseded == set()


def test_malformed_lockfile_is_skipped(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text("{ not valid json", encoding="utf-8")
    hints, superseded = parse_lockfiles(tmp_path)
    assert hints == []
    assert superseded == set()


# --- supersede behaviour via analyze_sbom ----------------------------------


def test_lockfile_supersedes_range_manifest(tmp_path: Path) -> None:
    """A package-lock resolves exact versions; the range-only package.json
    hints for npm are dropped in favour of them."""
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"express": "^4.18.0"}}), encoding="utf-8"
    )
    _write_package_lock_v3(tmp_path)
    hints = analyze_sbom(tmp_path)
    express = [h for h in hints if h.name == "express"]
    # Only the resolved (exact) express survives, not the "^4.18.0" range.
    assert len(express) == 1
    assert express[0].version == "4.18.2"
    assert express[0].resolved is True


def test_manifest_kept_when_no_lockfile(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"express": "^4.18.0"}}), encoding="utf-8"
    )
    hints = analyze_sbom(tmp_path)
    express = [h for h in hints if h.name == "express"]
    assert len(express) == 1
    assert express[0].version == "^4.18.0"
    assert express[0].resolved is False


def test_supersession_is_scoped_to_the_lockfile_directory(tmp_path: Path) -> None:
    """A lockfile in service A must not drop service B's un-locked manifest."""
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "package.json").write_text(
        json.dumps({"dependencies": {"express": "^4.18.0"}}), encoding="utf-8"
    )
    _write_package_lock_v3(tmp_path / "a")
    (tmp_path / "b" / "package.json").write_text(
        json.dumps({"dependencies": {"react": "^18.0.0"}}), encoding="utf-8"
    )
    hints = analyze_sbom(tmp_path)
    # Service A's express is resolved (lockfile); service B's react survives
    # as its range-only manifest hint (no lockfile there).
    express = [h for h in hints if h.name == "express"]
    react = [h for h in hints if h.name == "react"]
    assert express and express[0].resolved is True
    assert react and react[0].version == "^18.0.0"
    assert react[0].resolved is False


def test_go_mod_marked_resolved_with_direct_flag(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text(
        "module example.com/app\n\n"
        "go 1.21\n\n"
        "require (\n"
        "\tgithub.com/gin-gonic/gin v1.9.0\n"
        "\tgolang.org/x/sys v0.5.0 // indirect\n"
        ")\n",
        encoding="utf-8",
    )
    hints = analyze_sbom(tmp_path)
    by_name = _by_name(hints)
    assert by_name["github.com/gin-gonic/gin"].resolved is True
    assert by_name["github.com/gin-gonic/gin"].direct is True
    assert by_name["golang.org/x/sys"].direct is False  # // indirect
