"""Deeper secret detection (#252): paired/prefix-less credential families,
short password assignments, credential dotfiles, and the opt-in git-history
scan. Every raw value must stay out of every report artifact (#235).

Credential-shaped values are assembled at runtime so the repository never
contains anything a secret scanner (or GitHub push protection) would flag.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from attackmap.cli import app
from attackmap.config_scanner import scan_config_repo
from attackmap.recon_to_analysis import translate_recon
from attackmap.scanner import scan_repo
from attackmap.secrets_history import scan_secret_history
from attackmap.threat_model import rule_catalog

runner = CliRunner()
_ANSI = re.compile(r"\x1b\[[0-9;]*m")

AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYzQ9xLmP4tR"
AZURE_ACCOUNT_KEY = "Zm9vYmFyYmF6cXV4" * 5 + "AB=="
AZURE_SAS_KEY = "c2hhcmVkYWNjZXNza2V5" * 2 + "QWxwaGE="
AZURE_AD = "abc" + "8Q~" + "Xy7_kLmN0pQrStUvWxYz.12345-6789A"
DATADOG = "3f9a1c7e5b2d4f6a" + "8c0e1b3d5f7a9c2e"
HEROKU = "HRKU-AA" + "bC3dE5fG7hJ9kL1mN3pQ5r" + "S7tV9wX1yZ3aB5cD7eF9g" + "H1jK3lM5nP7qR9s"
DIGITALOCEAN = "dop_v1_" + "a1b2c3d4e5f6a7b8" * 4
VAULT = "hvs." + "CAESIJ7xQ2mZpLr8" + "KvTy3NwHb5Ud9FgA" + "sEo1Wc6Ri4Xj0Mn"
NPM_AUTH = "npmAuthT0ken" + "-q8Zr4Xv2Lk9"
DOCKER_AUTH = "dXNlcjpkb2NrZXJodWJQYXNz" + "d29yZDQy"
PEM_BODY = "MIIEvQIBADAN" + "BgkqhkiG9w0B" + "AQEFAASC"
GCP_KEY = "-----BEGIN " + "PRIVATE KEY-----\\n" + PEM_BODY + "BKcwggSj" + "AgEAAoIBAQC7\\n-----END " + "PRIVATE KEY-----\\n"
URL_PASS = "Gh7kP2" + "mQ9xZr"
SHORT_PASS = "Winter" + "2026!"
ENV_PASS = "hunter" + "2"
NETRC_PASS = "n3trc" + "S3cr3t"

RAW = [AWS_SECRET, AZURE_ACCOUNT_KEY, AZURE_SAS_KEY, AZURE_AD, DATADOG, HEROKU, DIGITALOCEAN, VAULT,
       NPM_AUTH, DOCKER_AUTH, PEM_BODY, URL_PASS, SHORT_PASS, NETRC_PASS]

POSITIVE = {
    "src/aws.py": f'aws_secret_access_key = "{AWS_SECRET}"\n',
    "src/azure.py": (
        f'CONN = "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey={AZURE_ACCOUNT_KEY};EndpointSuffix=core.windows.net"\n'
        f'BUS = "Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=Root;SharedAccessKey={AZURE_SAS_KEY}"\n'
        f'client_cred = "{AZURE_AD}"\n'
    ),
    "src/vendors.js": (
        f'const DD_API_KEY = "{DATADOG}";\n'
        f'const heroku = "{HEROKU}";\n'
        f'const doToken = "{DIGITALOCEAN}";\n'
        f'const vault = "{VAULT}";\n'
    ),
    "src/db.py": f'DSN = "postgresql://svc:{URL_PASS}@db.prod.internal:5432/app"\n',
    "src/login.py": f'password = "{SHORT_PASS}"\n',
    ".npmrc": f"//registry.npmjs.org/:_authToken={NPM_AUTH}\n",
    ".dockercfg": json.dumps({"https://index.docker.io/v1/": {"auth": DOCKER_AUTH}}),
    ".netrc": f"machine api.example.net login deploy password {NETRC_PASS}\n",
    ".git-credentials": f"https://deploy:{URL_PASS}@git.example.net\n",
    "deploy/sa.json": json.dumps({"type": "service_account", "project_id": "p", "private_key": GCP_KEY.replace("\\n", "\n")}),
    ".env": f"DB_PASS={ENV_PASS}\n",
    "keys/id_ed25519": "-----BEGIN " + "OPENSSH PRIVATE KEY-----\nb3BlbnNz\n-----END " + "OPENSSH PRIVATE KEY-----\n",
}
EXPECTED_KINDS = {
    ("src/aws.py", "aws_secret_access_key"),
    ("src/azure.py", "azure_storage_account_key"),
    ("src/azure.py", "azure_shared_access_key"),
    ("src/azure.py", "azure_ad_client_secret"),
    ("src/vendors.js", "datadog_key"),
    ("src/vendors.js", "heroku_api_key"),
    ("src/vendors.js", "digitalocean_token"),
    ("src/vendors.js", "vault_token"),
    ("src/db.py", "basic_auth_url"),
    ("src/login.py", "credential_assignment"),
    (".npmrc", "npm_auth_token"),
    (".dockercfg", "docker_registry_auth"),
    (".netrc", "netrc_password"),
    (".git-credentials", "basic_auth_url"),
    ("deploy/sa.json", "gcp_service_account_key"),
    (".env", "config_literal"),
    ("keys/id_ed25519", "pem_private_key"),
}

NEGATIVE = {
    "src/placeholders.py": (
        'password = "changeme123"\n'
        'api_key = "<your-api-key-here>"\n'
        'token = "${API_TOKEN}"\n'
        'secret = "SECRET_KEY_NAME"\n'
        'password_field = "password_hash"\n'
        'password = os.environ["DB_PASSWORD"]\n'
        'token = settings.API_TOKEN\n'
        'password_reset_url = "https://example.com/reset"\n'
        'if password == "irrelevant-compare":\n    pass\n'
        'DSN = "postgresql://user:${DB_PASS}@db/app"\n'
        'LOCAL = "postgresql://postgres:devpass99@localhost:5432/app"\n'
    ),
    ".npmrc": "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n",
    "deploy/not-sa.json": json.dumps({"type": "authorized_user", "client_id": "x"}),
    "tests/test_login.py": f'password = "{SHORT_PASS}"\n',
}


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _hints(root: Path) -> list:
    return scan_repo(root).secret_hints + scan_config_repo(root).secret_hints


def test_every_new_family_is_detected(tmp_path: Path) -> None:
    got = {(h.file, h.kind) for h in _hints(_write(tmp_path, POSITIVE))}
    missing = EXPECTED_KINDS - got
    assert not missing, missing


def test_placeholders_env_lookups_and_test_fixtures_are_not_flagged(tmp_path: Path) -> None:
    hints = _hints(_write(tmp_path, NEGATIVE))
    assert hints == [], [(h.file, h.kind, h.evidence_text) for h in hints]


def test_acceptance_npmrc_and_short_password_are_redacted_hints(tmp_path: Path) -> None:
    _write(tmp_path, {".npmrc": POSITIVE[".npmrc"], "src/login.py": POSITIVE["src/login.py"]})
    hints = {h.kind: h for h in _hints(tmp_path)}
    npmrc, pw = hints["npm_auth_token"], hints["credential_assignment"]
    for hint, raw in ((npmrc, NPM_AUTH), (pw, SHORT_PASS)):
        assert raw not in (hint.evidence_text or "") and raw not in hint.name
    assert npmrc.file == ".npmrc" and pw.file == "src/login.py" and pw.confidence == 0.5


def test_keyword_rule_alone_gives_a_medium_confidence_finding(tmp_path: Path) -> None:
    _write(tmp_path, {"src/login.py": POSITIVE["src/login.py"]})
    finding = next(f for f in translate_recon(scan_repo(tmp_path)).findings if f.rule_id == "hardcoded-secret")
    assert finding.confidence == "medium"


def test_raw_values_never_reach_any_report_artifact(tmp_path: Path) -> None:
    repo = _write(tmp_path / "repo", POSITIVE)
    out = tmp_path / "out"
    result = runner.invoke(app, ["analyze", str(repo), "-o", str(out)])
    assert result.exit_code == 0, result.output
    produced = [p for p in out.rglob("*") if p.is_file()]
    assert any(p.suffix == ".sarif" or p.name.endswith(".sarif.json") for p in produced) or any(
        "sarif" in p.name for p in produced
    )
    report = json.loads((out / "attackmap-report.json").read_text(encoding="utf-8"))
    assert any(f.get("rule_id") == "hardcoded-secret" for f in report["findings"])
    for path in produced:
        text = path.read_text(encoding="utf-8", errors="replace")
        for raw in RAW + [NPM_AUTH, ENV_PASS + "\n"]:
            assert raw not in text, f"{raw[:6]}… leaked into {path.name}"
    assert all(raw not in result.output for raw in RAW)


# --- git history ------------------------------------------------------------


def _git(repo: Path, *args: str) -> str:
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false",
         "-c", "init.defaultBranch=main", *args],
        cwd=repo, env=env, check=True, capture_output=True, text=True,
    ).stdout.strip()


@pytest.fixture
def history_repo(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "hist"
    repo.mkdir()
    _git(repo, "init", "-q")
    _write(repo, {"app/settings.py": f'aws_secret_access_key = "{AWS_SECRET}"\n', "README.md": "x\n"})
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "add settings")
    first = _git(repo, "rev-parse", "HEAD")
    _write(repo, {"app/settings.py": 'aws_secret_access_key = os.environ["AWS_SECRET_ACCESS_KEY"]\n',
                  "app/vault.py": f'VAULT = "{VAULT}"\n'})
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "move key to env; add vault")
    return repo, first


def test_history_reports_removed_secret_with_still_in_head_false(history_repo) -> None:
    repo, first = history_repo
    hits, notes = scan_secret_history(repo, 10)
    by_kind = {h.kind: h for h in hits}
    removed = by_kind["aws_secret_access_key"]
    assert removed.still_in_head is False
    assert removed.introduced_in == first
    assert removed.file == "app/settings.py"
    assert by_kind["vault_token"].still_in_head is True
    assert all(AWS_SECRET not in (h.evidence_text or "") + h.name for h in hits)
    assert notes == []


def test_history_is_bounded(history_repo) -> None:
    repo, _first = history_repo
    hits, notes = scan_secret_history(repo, 1)
    assert {h.kind for h in hits} == {"vault_token"}
    assert any("last 1 commit" in n for n in notes)
    _hits, notes = scan_secret_history(repo, 10, max_output_bytes=10)
    assert any("bytes of patch output" in n for n in notes)


def test_history_does_not_run_repo_config_or_hooks(history_repo, tmp_path: Path) -> None:
    repo, _first = history_repo
    marker = tmp_path / "pwned"
    script = tmp_path / "evil.sh"
    script.write_text(f"#!/bin/sh\ntouch {marker}\ncat \"$@\" 2>/dev/null\n", encoding="utf-8")
    script.chmod(0o755)
    for key in ("core.fsmonitor", "core.pager", "diff.external", "diff.evil.textconv", "core.hooksPath"):
        _git(repo, "config", key, str(script) if key != "core.hooksPath" else str(tmp_path))
    (tmp_path / "post-checkout").write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
    (repo / ".gitattributes").write_text("* diff=evil\n", encoding="utf-8")
    _git(repo, "add", ".gitattributes")
    _git(repo, "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "commit", "-q", "-m", "attrs")
    marker.unlink(missing_ok=True)
    hits, _ = scan_secret_history(repo, 10)
    assert hits  # the scan still works...
    assert not marker.exists()  # ...without running anything from the repo's config


def test_history_on_a_non_git_directory(tmp_path: Path) -> None:
    hits, notes = scan_secret_history(tmp_path, 10)
    assert hits == [] and "not a git repository" in notes[0]


def test_cli_secrets_history_is_opt_in_and_reported(history_repo, tmp_path: Path) -> None:
    repo, _first = history_repo
    out = tmp_path / "out-default"
    assert runner.invoke(app, ["analyze", str(repo), "-o", str(out), "--format", "json"]).exit_code == 0
    report = json.loads((out / "attackmap-report.json").read_text(encoding="utf-8"))
    assert not any(f.get("rule_id") == "secret-in-git-history" for f in report["findings"])

    out = tmp_path / "out-history"
    result = runner.invoke(app, ["analyze", str(repo), "-o", str(out), "--secrets-history", "10"])
    assert result.exit_code == 0, result.output
    report = json.loads((out / "attackmap-report.json").read_text(encoding="utf-8"))
    finding = next(f for f in report["findings"] if f.get("rule_id") == "secret-in-git-history")
    assert any("removed from HEAD" in e for e in finding["evidence"])
    for path in (p for p in out.rglob("*") if p.is_file()):
        text = path.read_text(encoding="utf-8", errors="replace")
        assert AWS_SECRET not in text and VAULT not in text, path.name


def test_cli_rejects_out_of_range_history() -> None:
    result = runner.invoke(app, ["analyze", ".", "--secrets-history", "-1"])
    assert result.exit_code != 0
    assert "--secrets-history" in " ".join(_ANSI.sub("", result.output).split())


def test_history_rule_is_catalogued() -> None:
    assert "secret-in-git-history" in {r for r, _, _ in rule_catalog()}
