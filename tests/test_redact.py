"""No credential from the scanned repo survives into any artifact (#235)."""

from __future__ import annotations

import random
import string
from pathlib import Path

import pytest
from typer.testing import CliRunner

from attackmap.cli import app
from attackmap.config_scanner import scan_config_repo
from attackmap.models import DatabaseHint, ExternalCall, Finding, ScanResult
from attackmap.redact import MASK, SECRET_TOKEN_PATTERNS, mask_secret, redact_text
from attackmap.review_prompts import _code_excerpts
from attackmap.scanner import HARDCODED_SECRET_PATTERNS

# Provider-shaped values are assembled at runtime so the repository never
# contains anything a secret scanner (or GitHub push protection) would flag.
AWS_ID = "AKIA" + "IOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMIK7MDENG" + "bPxRfiCYEXAMPLEKEYzQ9"
JWT = "eyJhbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiJ1c2VyLTEyMyJ9" + ".c2lnbmF0dXJlLXZhbHVlLTk5"
STRIPE_A = "sk_" + "live_" + "abcdef1234567890XYZabcd"
STRIPE_B = "sk_" + "live_" + "ZYXwvu9876543210abcdEFGH"

APP_PY = f"""import psycopg2
import requests
from flask import Flask, request

app = Flask(__name__)

creds = {{"id": "{AWS_ID}", "secret": "{AWS_SECRET}"}}
conn = psycopg2.connect("postgresql://admin:Sup3rS3cretPassw0rd@db.internal:5432/prod")
MONGO_URL = "mongodb://svc:M0ng0Pa55word42@mongo.internal:27017/app"
REDIS_URL = "redis://:R3d1sPa55word99@cache.internal:6379/0"
AMQP_URL = "amqp://worker:Rabb1tPa55word77@mq.internal:5672/"


@app.route("/proxy")
def proxy():
    r = requests.get("https://api.example.com/v1?api_key=hunter2hunter2hunter2")
    h = {{"Authorization": "Bearer {JWT}"}}
    return requests.post("https://hooks.example.com/notify", headers=h).text
"""
SETTINGS_YAML = f"""name: app
api_key: "{STRIPE_A}"
database:
  password: Pr0dDbPassw0rd!
"""
CONFIG_ENV = f"DATABASE_URL=postgres://svc:Zq8xT2pLm9vR@db.prod:5432/app\nSTRIPE_API_KEY={STRIPE_B}\n"

RAW_SECRETS = [
    AWS_ID,
    AWS_SECRET,
    "Sup3rS3cretPassw0rd",
    "M0ng0Pa55word42",
    "R3d1sPa55word99",
    "Rabb1tPa55word77",
    "hunter2hunter2hunter2",
    JWT,
    STRIPE_A,
    "Pr0dDbPassw0rd!",
    "Zq8xT2pLm9vR",
    STRIPE_B,
]


@pytest.fixture
def fixture_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "redaction"
    repo.mkdir()
    (repo / "app.py").write_text(APP_PY, encoding="utf-8")
    (repo / "settings.yaml").write_text(SETTINGS_YAML, encoding="utf-8")
    (repo / "config.env").write_text(CONFIG_ENV, encoding="utf-8")
    return repo


runner = CliRunner()


def _leaks(text: str) -> list[str]:
    # Any 8-char window of a secret beyond its 4-char display prefix is a leak.
    leaked = []
    for secret in RAW_SECRETS:
        tail = secret[4:]
        windows = {tail[i : i + 8] for i in range(max(1, len(tail) - 7))}
        if any(w in text for w in windows if len(w) == 8):
            leaked.append(secret)
    return leaked


def test_no_raw_secret_in_any_artifact(fixture_repo: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    pr = out / "pr-comment.md"
    result = runner.invoke(app, ["analyze", str(fixture_repo), "-o", str(out), "--pr-comment", str(pr)])
    assert result.exit_code == 0, result.output
    artifacts = sorted(out.iterdir())
    assert {a.name for a in artifacts} >= {"attackmap-report.json", "attackmap-report.sarif", "pr-comment.md", "review-context-pack.json"}
    for artifact in artifacts:
        assert _leaks(artifact.read_text(encoding="utf-8")) == [], artifact.name
    assert _leaks(result.output) == []


def test_llm_code_excerpts_are_redacted(fixture_repo: Path) -> None:
    scan = ScanResult(root=str(fixture_repo))
    findings = [Finding(title=f"f{i}", severity="high", mitigation="m", evidence=[f"app.py:{i} — x"]) for i in (7, 8, 16, 17)]
    rendered = "\n".join(_code_excerpts(scan, findings).values())
    assert "Sup3r" not in rendered or MASK in rendered
    assert _leaks(rendered) == []


def test_config_secret_lines_are_correct_and_redacted(fixture_repo: Path) -> None:
    scan = scan_config_repo(fixture_repo)
    lines = {(h.file, h.name): h.line for h in scan.secret_hints if h.kind == "config_literal"}
    assert lines[("settings.yaml", "api_key")] == 2
    assert lines[("config.env", "STRIPE_API_KEY")] == 2
    for hint in scan.secret_hints + scan.databases:
        assert _leaks(hint.evidence_text or "") == [], hint


def test_models_redact_at_construction() -> None:
    call = ExternalCall(target="https://u:p4ssw0rdValue@h.example/x?token=abcd1234efgh", file="a.py",
                        evidence_text='requests.get("https://h.example/x?token=abcd1234efgh")')
    assert "p4ssw0rdValue" not in call.target and "abcd1234efgh" not in call.target
    assert "abcd1234efgh" not in (call.evidence_text or "")
    db = DatabaseHint(kind="postgres", file="a.py", evidence_text="postgresql://admin:Sup3rS3cretPassw0rd@db/x")
    assert db.evidence_text == f"postgresql://admin:{MASK}@db/x"


@pytest.mark.parametrize(
    "text",
    [
        "token = request.headers.get('Authorization')",
        "api_key = os.environ['API_KEY']",
        "secret = settings.SECRET_KEY",
        "password = getenv('DB_PASSWORD')",
        "secret:JWT_SECRET (services/auth/config.py)",
        "Bearer authentication is required",
        "ssh://git@github.com/org/repo.git",
        "@app.route('/users/<int:user_id>')",
        "Content-Type: application/json",
    ],
)
def test_references_and_code_are_left_alone(text: str) -> None:
    assert redact_text(text) == text


def test_every_detection_pattern_is_also_redacted() -> None:
    detection = {p.pattern for p, _ in HARDCODED_SECRET_PATTERNS if "PRIVATE KEY" not in p.pattern}
    redaction = {p.pattern for p, _ in SECRET_TOKEN_PATTERNS}
    assert detection <= redaction


def test_mask_secret_reveals_at_most_four_chars() -> None:
    assert mask_secret(AWS_ID) == "AKIA…"
    assert mask_secret("short") == "…"


def test_redact_text_is_idempotent_and_never_lengthens_secrets() -> None:
    rng = random.Random(235)
    alphabet = string.ascii_letters + string.digits
    templates = [
        'password = "{v}"', "API_KEY={v}", "postgres://u:{v}@h/db", "https://x.io/?api_key={v}",
        "Authorization: Bearer {v}9", 'k = "{v}{v}"', "plain text {v}",
    ]
    for _ in range(500):
        value = "".join(rng.choice(alphabet) for _ in range(rng.randint(8, 48)))
        text = rng.choice(templates).format(v=value)
        once = redact_text(text)
        assert redact_text(once) == once, text
        assert len(once) <= len(text), text
