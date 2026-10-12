"""OAuth client and session checks (#243, part 2)."""

from __future__ import annotations

from pathlib import Path

import pytest

from attackmap.auth_protocol import find_oauth_session_issues
from attackmap.scanner import scan_repo
from attackmap.taxonomy import taxonomy_for
from attackmap.threat_model import generate_findings

FIXTURES = Path(__file__).parent / "fixtures" / "oauth_session"

KINDS = (
    "oauth_missing_state",
    "oauth_implicit_flow",
    "oauth_redirect_uri_loose",
    "oauth_missing_pkce",
    "session_fixation",
    "session_weak_secret",
)


def _issues(name: str) -> set[tuple[str, int]]:
    weaknesses, _ = find_oauth_session_issues((FIXTURES / name).read_text(encoding="utf-8"), name)
    return {(w.kind, w.line or 0) for w in weaknesses}


def _kinds(content: str, name: str) -> set[str]:
    return {w.kind for w in find_oauth_session_issues(content, name)[0]}


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        (
            "vuln_oauth_express.js",
            {("oauth_missing_state", 9), ("oauth_missing_state", 17), ("oauth_redirect_uri_loose", 24)},
        ),
        (
            "vuln_oauth_spa.tsx",
            {("oauth_implicit_flow", 7), ("oauth_missing_pkce", 12), ("oauth_missing_pkce", 15)},
        ),
        ("vuln_oauth_flask.py", {("oauth_missing_state", 11), ("oauth_redirect_uri_loose", 19)}),
        ("vuln_oauth.go", {("oauth_missing_state", 11), ("oauth_redirect_uri_loose", 18)}),
        (
            "vuln_oauth_session.php",
            {("session_fixation", 6), ("oauth_missing_state", 12), ("oauth_redirect_uri_loose", 20)},
        ),
        ("vuln_session_express.js", {("session_weak_secret", 5), ("session_fixation", 10)}),
        # Fixation here is dropped at repo level (no server-side store); see below.
        ("vuln_cookie_session.js", {("session_weak_secret", 5), ("session_fixation", 8)}),
        ("vuln_session_flask.py", {("session_weak_secret", 6), ("session_weak_secret", 7)}),
        ("vuln_session_gorilla.go", {("session_weak_secret", 5)}),
    ],
)
def test_vulnerable_fixtures(name: str, expected: set[tuple[str, int]]) -> None:
    assert _issues(name) == expected


@pytest.mark.parametrize("name", sorted(p.name for p in FIXTURES.glob("safe_*")))
def test_safe_fixtures(name: str) -> None:
    assert _issues(name) == set()


def test_every_kind_has_a_positive_fixture() -> None:
    found = {kind for path in FIXTURES.glob("vuln_*") for kind, _ in _issues(path.name)}
    assert found == set(KINDS)


def test_server_store_flag() -> None:
    assert find_oauth_session_issues((FIXTURES / "vuln_session_express.js").read_text(), "a.js")[1]
    assert not find_oauth_session_issues((FIXTURES / "vuln_cookie_session.js").read_text(), "a.js")[1]


# ---------------------------------------------------------------------------
# Precision
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("content", "name"),
    [
        # Exact membership in an allow-list is the correct check.
        ("if (ALLOWED_REDIRECT_URIS.includes(redirect_uri)) next()\n", "a.js"),
        ("ok = redirect_uri in REGISTERED_REDIRECT_URIS\n", "a.py"),
        ("ok = 'https://a.example.com/cb' in redirect_uris\n", "a.py"),
        # Reading response_type (an authorization server), not building a request.
        ("const rt = req.query.response_type\nconst cid = req.query.client_id\n", "a.js"),
        ("rt = request.args.get('response_type')\ncid = request.args.get('client_id')\n", "a.py"),
        # A library call that manages state itself (a keyword argument).
        ("return oauth.google.authorize_redirect(request, uri, response_type='code', client_id=CID)\n", "a.py"),
        # response_type without an OAuth client nearby.
        ("const opts = { response_type: 'json' }\n", "a.js"),
        # React state isn't the OAuth `state` parameter; this request has one.
        (
            "const [user, setUser] = useState(null)\n"
            "const url = `https://id.example.com/authorize?response_type=code&client_id=${id}&state=${s}`\n",
            "a.ts",
        ),
        # A confidential (server-side) client doesn't need PKCE to be flagged.
        (
            "const secret = process.env.CLIENT_SECRET\n"
            "res.redirect(`https://id.example.com/authorize?response_type=code&client_id=${id}&state=${s}`)\n",
            "server.js",
        ),
        # Session secrets from the environment, or long enough.
        ("const session = require('express-session')\napp.use(session({ secret: process.env.S }))\n", "a.js"),
        (
            "const session = require('express-session')\n"
            "app.use(session({ secret: 'a-placeholder-secret-that-is-long-enough' }))\n",
            "a.js",
        ),
        # Logout / clearing the session isn't a login.
        ("req.session.user = null\nreq.session.userId = undefined\n", "a.js"),
        ("<?php\n$_SESSION['user_id'] = null;\n", "a.php"),
        # SECRET_KEY outside a Flask file is not judged here.
        ("SECRET_KEY = 'dev'\n", "settings.py"),
        # Commented out.
        ("// app.use(session({ secret: 'keyboard cat' }))\nconst session = require('express-session')\n", "a.js"),
    ],
)
def test_not_flagged(content: str, name: str) -> None:
    assert not _kinds(content, name)


def test_a_url_on_the_line_is_not_a_comment() -> None:
    content = "location.href = `https://id.example.com/authorize?response_type=token&client_id=${cid}&state=${s}`\n"
    assert _kinds(content, "a.ts") == {"oauth_implicit_flow"}


def test_plain_pkce_is_flagged() -> None:
    url = "const u = `https://id.example.com/authorize?response_type=code&client_id=${c}&state=${s}&code_challenge=${x}&code_challenge_method=plain`\n"
    assert _kinds(url, "server.js") == {"oauth_missing_pkce"}
    assert _kinds(url.replace("plain", "S256"), "server.js") == set()


def test_fastify_session_registration() -> None:
    content = "app.register(require('@fastify/session'), { secret: 'short', cookie: { secure: true } })\n"
    assert _kinds(content, "app.js") == {"session_weak_secret"}


# ---------------------------------------------------------------------------
# Repo level: session fixation needs a server-side session store (JS)
# ---------------------------------------------------------------------------


def _fixation(scan) -> list[tuple[str, int | None]]:
    return [(w.file, w.line) for w in scan.code_weaknesses if w.kind == "session_fixation"]


def test_cookie_session_repo_has_no_fixation(tmp_path: Path) -> None:
    root = _write(tmp_path, {"app.js": (FIXTURES / "vuln_cookie_session.js").read_text()})
    scan = scan_repo(root)
    assert _fixation(scan) == []
    assert any(w.kind == "session_weak_secret" for w in scan.code_weaknesses)


def test_server_store_in_another_file_keeps_fixation(tmp_path: Path) -> None:
    root = _write(
        tmp_path,
        {
            "app.js": "const session = require('express-session')\napp.use(session({ secret: process.env.S }))\n",
            "routes/login.js": "router.post('/login', (req, res) => { req.session.userId = user.id })\n",
        },
    )
    assert _fixation(scan_repo(root)) == [("routes/login.js", 1)]


def test_php_fixation_needs_no_store(tmp_path: Path) -> None:
    root = _write(tmp_path, {"login.php": (FIXTURES / "vuln_oauth_session.php").read_text()})
    assert _fixation(scan_repo(root)) == [("login.php", 6)]


# ---------------------------------------------------------------------------
# Findings, tags, taxonomy
# ---------------------------------------------------------------------------


def test_findings_carry_their_bench_class(tmp_path: Path) -> None:
    root = _write(
        tmp_path,
        {
            "app.js": (FIXTURES / "vuln_session_express.js").read_text(),
            "oauth.js": (FIXTURES / "vuln_oauth_express.js").read_text(),
        },
    )
    tags = {f.rule_id: f.tags for f in generate_findings(scan_repo(root))}
    assert "token-auth" in tags["oauth-missing-state"]
    assert "token-auth" in tags["oauth-redirect-uri-loose"]
    assert "session-auth" in tags["session-fixation"]
    assert "session-auth" in tags["session-weak-secret"]


@pytest.mark.parametrize("kind", KINDS)
def test_rules_are_registered(kind: str) -> None:
    entry = taxonomy_for(kind.replace("_", "-"))
    assert entry is not None and entry.cwe and entry.owasp
