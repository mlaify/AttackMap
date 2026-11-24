"""A scan never aborts on malformed input (#199).

Deterministic mutation fuzzing: a seed repo covering every parser family
(lockfiles, manifests, CI workflows, IaC, config, source in each taint
language) is corrupted file by file, and the whole `attackmap analyze`
pipeline must still exit 0, record no analyzer crash and write a report
that validates against its schema. Seeded, so a failure reproduces.
"""

from __future__ import annotations

import json
import random
import shutil
from pathlib import Path

import jsonschema
import pytest
from typer.testing import CliRunner

from attackmap.cli import app
from attackmap.schemas import report_schema

FIXTURES = Path(__file__).parent / "fixtures"

_INLINE_SEEDS = {
    "package-lock.json": '{"name":"a","lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.20"}}}\n',
    "pnpm-lock.yaml": "lockfileVersion: '9.0'\npackages:\n  lodash@4.17.20:\n    resolution: {integrity: sha512-x}\n",
    "yarn.lock": '"lodash@^4.17.0":\n  version "4.17.20"\n  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.20.tgz"\n',
    "poetry.lock": '[[package]]\nname = "requests"\nversion = "2.19.0"\n',
    "Pipfile.lock": '{"default": {"requests": {"version": "==2.19.0"}}}\n',
    "Cargo.lock": '[[package]]\nname = "smallvec"\nversion = "0.6.9"\n',
    "go.sum": "github.com/gin-gonic/gin v1.6.0 h1:abc=\n",
    "composer.lock": '{"packages": [{"name": "laravel/framework", "version": "v8.0.0"}]}\n',
    "Gemfile.lock": "GEM\n  specs:\n    rails (5.2.0)\n",
    "Dockerfile": "FROM node:latest\nADD https://example.com/x.tgz /x\nRUN curl -s https://x.sh | sh\nUSER root\n",
    "docker-compose.yml": "services:\n  web:\n    image: app:latest\n    privileged: true\n    network_mode: host\n",
    "k8s/deploy.yaml": "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          securityContext: {privileged: true}\n",
    "infra/main.tf": 'resource "aws_instance" "web" {\n  metadata_options { http_tokens = "optional" }\n}\n',
    "config/settings.json": '{"db_password": "S3cr3t-Pa55word!", "api_token": "tok_9f8a7b6c5d4e3f2a"}\n',
    ".env": "SECRET_KEY=abcdef0123456789abcdef\n",
}


def _seed_repo(root: Path) -> None:
    shutil.copytree(FIXTURES / "sbom_repo", root, dirs_exist_ok=True)
    shutil.copytree(FIXTURES / "workflows" / "github_script_injection", root / ".github" / "workflows")
    for lang in ("py", "js", "go", "php", "java"):
        shutil.copytree(FIXTURES / "taint_flow" / lang, root / "src" / lang)
    for rel, text in _INLINE_SEEDS.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")


def _mutate(data: bytes, rng: random.Random, choice: int | None = None) -> bytes:
    choice = rng.randrange(7) if choice is None else choice
    if choice == 0:  # truncated mid-token
        return data[: rng.randrange(max(1, len(data)))]
    if choice == 1:  # invalid UTF-8 and NULs spliced in
        cut = rng.randrange(len(data) + 1)
        return data[:cut] + b"\xff\xfe\x00\xc3(\x80\x00" + data[cut:]
    if choice == 2:  # deep nesting
        return b"[" * 3000 + b"{" * 3000 + data  # past the recursive parsers' ~1000-level limit
    if choice == 3:  # one enormous line
        return data + b"a = '" + b"(" * 30_000 + b"\n"
    if choice == 4:  # empty
        return b""
    if choice == 5:  # random bytes
        return bytes(rng.randrange(256) for _ in range(rng.randrange(1, 4096)))
    # repeated slice (huge, repetitive document)
    start = rng.randrange(max(1, len(data)))
    return data + data[start : start + 200] * 500


# Seeds mix mutations per file; the forced rounds apply one mutation (truncate,
# bad UTF-8, deep nesting, a huge line, random bytes) to every file at once.
@pytest.mark.parametrize(("seed", "force"), [(1, None), (2, None), (3, None), (4, None), (5, 0), (6, 1), (7, 2), (8, 3), (9, 5)])
def test_scan_survives_malformed_files(tmp_path: Path, seed: int, force: int | None) -> None:
    rng = random.Random(seed)
    repo = tmp_path / "repo"
    _seed_repo(repo)
    for path in sorted(p for p in repo.rglob("*") if p.is_file()):
        path.write_bytes(_mutate(path.read_bytes(), rng, force))

    out = tmp_path / "out"
    result = CliRunner().invoke(app, ["analyze", str(repo), "--output", str(out)])
    assert result.exit_code == 0, result.output
    report = json.loads((out / "attackmap-report.json").read_text(encoding="utf-8"))
    assert report["scan"]["analyzer_errors"] == [], report["scan"]["analyzer_errors"]
    jsonschema.validate(report, report_schema())
