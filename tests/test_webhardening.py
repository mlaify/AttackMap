"""Tests for web-hardening gap detection (#71)."""

from __future__ import annotations

from pathlib import Path

import pytest

from attackmap.models import ScanResult, WebHardeningIssue
from attackmap.scanner import scan_repo
from attackmap.threat_model import generate_findings
from attackmap.webhardening import find_web_hardening_issues


def _kinds(content: str) -> set[str]:
    return {i.kind for i in find_web_hardening_issues(content, "f.py")}


# ---------------------------------------------------------------------------
# CORS wildcard + credentials (two-part co-occurrence)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        "CORS(app, origins='*', supports_credentials=True)\n",
        "app.use(cors({ origin: '*', credentials: true }))\n",
        "app.use(cors({ origin: true, credentials: true }))\n",  # reflected
        (
            "res.setHeader('Access-Control-Allow-Origin', '*')\n"
            "res.setHeader('Access-Control-Allow-Credentials', 'true')\n"
        ),
    ],
)
def test_cors_wildcard_with_credentials_flagged(content: str) -> None:
    assert "cors_wildcard_credentials" in _kinds(content)


def test_wildcard_cors_without_credentials_not_flagged() -> None:
    # Wildcard origin alone (no credentials) is a common, acceptable public-API config.
    content = "res.setHeader('Access-Control-Allow-Origin', '*')\n"
    assert "cors_wildcard_credentials" not in _kinds(content)


def test_specific_origin_with_credentials_not_flagged() -> None:
    content = "app.use(cors({ origin: 'https://app.example.com', credentials: true }))\n"
    assert "cors_wildcard_credentials" not in _kinds(content)


# ---------------------------------------------------------------------------
# CSRF disabled
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        "@csrf_exempt\ndef view(request): ...\n",
        "WTF_CSRF_ENABLED = False\n",
        "http.csrf().disable();\n",
        "http.csrf(csrf -> csrf.disable());\n",
        "app.use(csurf({ csrf: false }))\n",
    ],
)
def test_csrf_disabled_flagged(content: str) -> None:
    assert "csrf_disabled" in _kinds(content)


# ---------------------------------------------------------------------------
# Insecure cookies
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        "res.cookie('sid', v, { httpOnly: false })\n",
        "res.cookie('sid', v, { secure: false })\n",
        "res.cookie('sid', v, { sameSite: 'none' })\n",
        "SESSION_COOKIE_SECURE = False\n",
        "SESSION_COOKIE_HTTPONLY = False\n",
    ],
)
def test_insecure_cookie_flagged(content: str) -> None:
    assert "insecure_cookie" in _kinds(content)


def test_samesite_none_with_secure_not_flagged_by_raw_header() -> None:
    # `SameSite=None; Secure` is the correct cross-site cookie config.
    content = "Set-Cookie: sid=x; SameSite=None; Secure\n"
    assert "insecure_cookie" not in _kinds(content)


# ---------------------------------------------------------------------------
# Weak CSP
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        "csp = \"default-src 'self'; script-src 'unsafe-inline'\"\n",
        "\"Content-Security-Policy\": \"script-src 'unsafe-eval'\"\n",
    ],
)
def test_weak_csp_flagged(content: str) -> None:
    assert "weak_csp" in _kinds(content)


def test_strict_csp_not_flagged() -> None:
    content = "csp = \"default-src 'self'; script-src 'self'\"\n"
    assert "weak_csp" not in _kinds(content)


# ---------------------------------------------------------------------------
# Debug enabled
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        "app.run(host='0.0.0.0', debug=True)\n",
        "DEBUG = True\n",
        "management.endpoints.web.exposure.include=*\n",
        "config.consider_all_requests_local = true\n",
    ],
)
def test_debug_enabled_flagged(content: str) -> None:
    assert "debug_enabled" in _kinds(content)


def test_debug_false_not_flagged() -> None:
    assert "debug_enabled" not in _kinds("DEBUG = False\napp.run(debug=False)\n")


# ---------------------------------------------------------------------------
# Metadata + dedup
# ---------------------------------------------------------------------------


def test_issue_carries_metadata() -> None:
    issue = find_web_hardening_issues("SESSION_COOKIE_SECURE = False\n", "settings.py")[0]
    assert issue.file == "settings.py"
    assert issue.line == 1
    assert issue.severity == "medium"
    assert issue.source_analyzer == "webhardening"


# ---------------------------------------------------------------------------
# Findings via threat_model
# ---------------------------------------------------------------------------


def test_cors_finding_high_with_technique() -> None:
    scan = ScanResult(
        root="/",
        web_hardening_issues=[
            WebHardeningIssue(kind="cors_wildcard_credentials", file="app.py", line=5, severity="high")
        ],
    )
    findings = [f for f in generate_findings(scan) if "web-hardening" in f.tags]
    assert findings
    assert findings[0].severity == "high"
    assert findings[0].attack_techniques[0].technique_id == "T1539"


def test_distinct_kinds_yield_distinct_findings() -> None:
    scan = ScanResult(
        root="/",
        web_hardening_issues=[
            WebHardeningIssue(kind="debug_enabled", file="a.py", line=1, severity="medium"),
            WebHardeningIssue(kind="weak_csp", file="b.py", line=2, severity="medium"),
        ],
    )
    titles = {f.title for f in generate_findings(scan) if "web-hardening" in f.tags}
    assert any("Debug" in t for t in titles)
    assert any("Content-Security-Policy" in t for t in titles)


# ---------------------------------------------------------------------------
# End-to-end via scan_repo
# ---------------------------------------------------------------------------


def test_scan_repo_populates_web_hardening(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "if __name__ == '__main__':\n"
        "    app.run(host='0.0.0.0', debug=True)\n",
        encoding="utf-8",
    )
    scan = scan_repo(tmp_path)
    assert any(i.kind == "debug_enabled" for i in scan.web_hardening_issues)
    assert [f for f in generate_findings(scan) if "web-hardening" in f.tags]


def test_scan_repo_clean_config_no_web_findings(tmp_path: Path) -> None:
    (tmp_path / "settings.py").write_text(
        "DEBUG = False\n"
        "SESSION_COOKIE_SECURE = True\n"
        "SESSION_COOKIE_HTTPONLY = True\n",
        encoding="utf-8",
    )
    scan = scan_repo(tmp_path)
    assert scan.web_hardening_issues == []
