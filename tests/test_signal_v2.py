"""Tests for the unified Signal model + line-number plumbing through the pipeline."""

from pathlib import Path

import pytest

from attackmap.asset_model import detect_assets
from attackmap.control_model import detect_controls
from attackmap.models import (
    AuthHint,
    DatabaseHint,
    ExternalCall,
    FrameworkHint,
    Route,
    ScanResult,
    SecretHint,
    Signal,
)
from attackmap.scanner import _line_of, _line_snippet, scan_repo
from attackmap.security_overlay import build_security_overlay


# ---------- Backward compatibility ----------


def test_existing_hint_constructors_still_work_without_line_or_evidence() -> None:
    """Pre-Signal-v2 plugin code constructs hints with just (hint, file). It must keep working."""
    hint = AuthHint(hint="login_required", file="app.py")
    assert hint.line is None
    assert hint.evidence_text is None
    assert hint.confidence == 0.7

    secret = SecretHint(name="JWT_SECRET", file="config.py")
    assert secret.line is None
    assert secret.evidence_text is None
    assert secret.confidence == 0.85


# ---------- Signal model ----------


def test_signal_model_location_helper_with_and_without_line() -> None:
    s_with_line = Signal(kind="auth", label="login_required", file="app.py", line=42)
    assert s_with_line.location() == "app.py:42"

    s_without_line = Signal(kind="auth", label="login_required", file="app.py")
    assert s_without_line.location() == "app.py"


def test_all_signals_synthesizes_unified_view_from_typed_lists() -> None:
    scan = ScanResult(
        root=".",
        languages=["python"],
        routes=[Route(path="/login", method="POST", file="app/auth.py", line=12)],
        external_calls=[ExternalCall(target="https://api.x.com", file="app/svc.py", line=5)],
        databases=[DatabaseHint(kind="postgres", file="app/db.py", line=2)],
        auth_hints=[AuthHint(hint="login_required", file="app/auth.py", line=10, confidence=0.85)],
        framework_hints=[FrameworkHint(hint="csurf", file="app/middleware.py", line=3)],
        secret_hints=[SecretHint(name="JWT_SECRET", file="app/config.py", line=8)],
        files_scanned=5,
    )

    signals = scan.all_signals()
    by_kind = {s.kind: s for s in signals}

    assert by_kind["route"].label == "POST /login"
    assert by_kind["route"].file == "app/auth.py"
    assert by_kind["route"].line == 12
    assert by_kind["route"].location() == "app/auth.py:12"
    assert by_kind["route"].properties["method"] == "POST"

    assert by_kind["external_call"].label == "https://api.x.com"
    assert by_kind["database"].label == "postgres"
    assert by_kind["database"].properties["kind"] == "postgres"

    assert by_kind["auth"].confidence == 0.85
    assert by_kind["framework"].label == "csurf"
    assert by_kind["secret"].label == "JWT_SECRET"
    assert by_kind["secret"].confidence == 0.85


def test_all_signals_handles_empty_scan() -> None:
    scan = ScanResult(root=".")
    assert scan.all_signals() == []


# ---------- Scanner line + snippet helpers ----------


def test_line_of_returns_one_indexed_line_numbers() -> None:
    text = "alpha\nbeta\ngamma\ndelta"
    assert _line_of(text, 0) == 1                  # start of file
    assert _line_of(text, text.find("beta")) == 2
    assert _line_of(text, text.find("gamma")) == 3
    assert _line_of(text, text.find("delta")) == 4


def test_line_snippet_returns_stripped_line_around_offset() -> None:
    text = "    line one\n    JWT_SECRET = os.getenv('foo')\n    line three"
    snippet = _line_snippet(text, text.find("JWT_SECRET"))
    assert "JWT_SECRET" in snippet
    assert not snippet.startswith(" ")  # stripped


def test_line_snippet_truncates_long_lines() -> None:
    text = "x" * 500
    snippet = _line_snippet(text, 10, max_chars=80)
    assert len(snippet) <= 80
    assert snippet.endswith("…")


# ---------- Scanner end-to-end: line numbers populated ----------


def test_scanner_populates_line_numbers_on_routes_secrets_and_auth(tmp_path: Path) -> None:
    sample = tmp_path / "app.py"
    sample.write_text(
        "from flask import Flask, Blueprint\n"            # line 1
        "import os\n"                                       # line 2
        "\n"                                                # line 3
        "JWT_SECRET = os.getenv('JWT_SECRET')\n"           # line 4 — secret
        "app = Flask(__name__)\n"                          # line 5
        "\n"                                                # line 6
        "@app.route('/login', methods=['POST'])\n"         # line 7 — route
        "@login_required\n"                                # line 8 — auth
        "def login():\n"                                    # line 9
        "    return 'ok'\n",                               # line 10
        encoding="utf-8",
    )

    scan = scan_repo(tmp_path, suffixes={".py"})

    assert scan.routes
    login = next(r for r in scan.routes if r.path == "/login")
    assert login.line == 7

    assert scan.secret_hints
    jwt = next(s for s in scan.secret_hints if s.name == "JWT_SECRET")
    assert jwt.line == 4
    assert jwt.evidence_text and "JWT_SECRET" in jwt.evidence_text

    assert scan.auth_hints
    login_required = next(h for h in scan.auth_hints if h.hint == "login_required")
    assert login_required.line == 8
    assert login_required.confidence == 0.85  # pattern match → high


# ---------- Plumbed through to insights / assets ----------


def test_shared_secret_blast_radius_evidence_cites_file_colon_line() -> None:
    scan = ScanResult(
        root=".",
        languages=["python"],
        files_scanned=4,
        secret_hints=[
            SecretHint(name="JWT_SECRET", file="services/auth/config.py", line=11),
            SecretHint(name="JWT_SECRET", file="services/api/config.py", line=22),
            SecretHint(name="JWT_SECRET", file="services/billing/config.py", line=33),
        ],
    )
    overlay = build_security_overlay(scan, [], [], [])
    blast = next(i for i in overlay.insights if i.kind == "shared_secret_blast_radius")
    assert any(":11" in e for e in blast.evidence)
    assert any(":22" in e for e in blast.evidence)
    assert any(":33" in e for e in blast.evidence)


def test_asset_evidence_cites_file_colon_line_when_known() -> None:
    scan = ScanResult(
        root=".",
        languages=["python"],
        files_scanned=2,
        secret_hints=[SecretHint(name="JWT_SECRET", file="app/auth.py", line=14)],
    )
    assets = detect_assets(scan)
    session_asset = next(a for a in assets if a.kind == "session")
    assert any("app/auth.py:14" in e for e in session_asset.evidence)


def test_control_evidence_cites_file_colon_line() -> None:
    scan = ScanResult(
        root=".",
        languages=["python"],
        files_scanned=1,
        auth_hints=[AuthHint(hint="bcrypt.hash", file="app/auth.py", line=21, confidence=0.85)],
    )
    controls = detect_controls(scan, [], [])
    bcrypt_control = next(c for c in controls if c.strength == "strong")
    assert any("app/auth.py:21" in e for e in bcrypt_control.evidence)


# ---------- AttackSurface line plumbing ----------


def test_attack_surface_picks_up_route_line() -> None:
    from attackmap.analyzer import identify_attack_surfaces

    scan = ScanResult(
        root=".",
        languages=["python"],
        files_scanned=1,
        routes=[Route(path="/admin/users", method="POST", file="app/admin.py", line=99)],
    )
    surfaces = identify_attack_surfaces(scan)
    assert surfaces[0].line == 99
    assert surfaces[0].location() == "app/admin.py:99"
