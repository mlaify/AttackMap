"""JWT verification checks (#243, part 1): library-aware JWT weaknesses and the
`jwt_verified` hint that alone credits the "JWT verification" control."""

from __future__ import annotations

from pathlib import Path

import pytest

from attackmap.auth_protocol import find_jwt_issues
from attackmap.control_model import detect_controls
from attackmap.scanner import scan_repo
from attackmap.taxonomy import taxonomy_for
from attackmap.threat_model import generate_findings

FIXTURES = Path(__file__).parent / "fixtures" / "auth_protocol"

JWT_KINDS = ("jwt_alg_confusion", "jwt_unverified_decode", "jwt_claims_unchecked", "jwt_header_trust", "jwt_weak_secret")


def _issues(name: str) -> tuple[set[tuple[str, int]], bool]:
    """(kind, line) pairs for a fixture, and whether it verifies tokens."""
    weaknesses, verified = find_jwt_issues((FIXTURES / name).read_text(encoding="utf-8"), name)
    return {(w.kind, w.line or 0) for w in weaknesses}, bool(verified)


def _kinds(content: str, name: str) -> set[str]:
    return {w.kind for w in find_jwt_issues(content, name)[0]}


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


# ---------------------------------------------------------------------------
# Positive fixtures: one per kind per library
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected", "verified"),
    [
        (
            "vuln_jsonwebtoken.js",
            {
                ("jwt_weak_secret", 5),
                ("jwt_alg_confusion", 9),
                ("jwt_claims_unchecked", 13),
                ("jwt_header_trust", 17),
                ("jwt_header_trust", 21),
            },
            False,
        ),
        ("vuln_jsonwebtoken_decode.js", {("jwt_unverified_decode", 4)}, False),
        ("vuln_jose.ts", {("jwt_weak_secret", 3), ("jwt_unverified_decode", 10)}, False),
        (
            "vuln_pyjwt.py",
            {
                ("jwt_weak_secret", 5),
                ("jwt_alg_confusion", 9),
                ("jwt_claims_unchecked", 13),
                ("jwt_header_trust", 17),
                ("jwt_header_trust", 22),
            },
            # `lenient` pins algorithms; it is only the expiry that's off.
            True,
        ),
        ("vuln_python_jose.py", {("jwt_unverified_decode", 5)}, False),
        ("vuln_authlib.py", {("jwt_claims_unchecked", 5)}, False),
        (
            "vuln_golang_jwt.go",
            {
                ("jwt_weak_secret", 9),
                ("jwt_alg_confusion", 12),
                ("jwt_header_trust", 13),
                ("jwt_alg_confusion", 18),
                ("jwt_claims_unchecked", 18),
            },
            False,
        ),
        ("vuln_golang_jwt_unverified.go", {("jwt_unverified_decode", 6)}, False),
    ],
)
def test_vulnerable_fixtures(name: str, expected: set[tuple[str, int]], verified: bool) -> None:
    assert _issues(name) == (expected, verified)


# ---------------------------------------------------------------------------
# Negative fixtures: the correct forms are clean and credit verification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["safe_jsonwebtoken.js", "safe_jose.ts", "safe_pyjwt.py", "safe_authlib.py", "safe_golang_jwt.go"],
)
def test_safe_fixtures(name: str) -> None:
    assert _issues(name) == (set(), True)


def test_every_kind_has_a_positive_fixture() -> None:
    found = {kind for path in FIXTURES.glob("vuln_*") for kind, _ in _issues(path.name)[0]}
    assert found == set(JWT_KINDS)


# ---------------------------------------------------------------------------
# Library gating and precision
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("content", "name"),
    [
        # No JWT library imported: `jwt` is someone else's object.
        ("const jwt = makeHelper()\njwt.decode(token)\n", "a.js"),
        ("jwt.decode(token, public_key)\n", "a.py"),
        ("token, _ := parser.Parse(s, keyFunc)\n", "a.go"),
        # A commented-out call.
        ("const jwt = require('jsonwebtoken')\n// jwt.decode(token)\n", "a.js"),
        # PyJWT with verification off is jwt_weakness's to report, not ours.
        ("import jwt\njwt.decode(t, key, options={'verify_signature': False})\n", "a.py"),
        # HMAC verification can't be confused with a public key.
        ("const jwt = require('jsonwebtoken')\njwt.verify(t, process.env.JWT_SECRET)\n", "a.js"),
        ("import jwt\njwt.decode(t, settings.SECRET_KEY)\n", "a.py"),
        # Secrets long enough, or not literals.
        ("const jwt = require('jsonwebtoken')\njwt.sign(p, 'a-placeholder-secret-that-is-long-enough')\n", "a.js"),
        ("const jwt = require('jsonwebtoken')\njwt.sign(p, `${prefix}-key`)\n", "a.js"),
        ("import \"github.com/golang-jwt/jwt/v5\"\nw.Write([]byte(\"ok\"))\n", "a.go"),
    ],
)
def test_not_flagged(content: str, name: str) -> None:
    assert not _kinds(content, name)


def test_named_imports_and_aliases_are_followed() -> None:
    js = "import { verify as check, decode } from 'jsonwebtoken'\ncheck(token, pubKey)\n"
    assert _kinds(js, "a.ts") == {"jwt_alg_confusion"}
    py = "import jwt as pyjwt\npyjwt.decode(token, public_key)\n"
    assert _kinds(py, "a.py") == {"jwt_alg_confusion"}
    go = 'import (\n\tgojwt "github.com/golang-jwt/jwt/v4"\n)\nt, _ := gojwt.Parse(s, func(t *gojwt.Token) (interface{}, error) { return k, nil })\n'
    assert _kinds(go, "a.go") == {"jwt_alg_confusion"}


def test_options_by_name_trust_a_pinned_list_elsewhere_in_the_file() -> None:
    content = (
        "const jwt = require('jsonwebtoken')\n"
        "const opts = { algorithms: ['RS256'] }\n"
        "jwt.verify(token, publicKey, opts)\n"
    )
    weaknesses, verified = find_jwt_issues(content, "a.js")
    assert not weaknesses and verified


def test_decode_beside_verify_is_not_flagged() -> None:
    content = (
        "const jwt = require('jsonwebtoken')\n"
        "const { header } = jwt.decode(token, { complete: true })\n"
        "jwt.verify(token, keys[header.kid], { algorithms: ['RS256'] })\n"
    )
    assert not _kinds(content, "a.js")


def test_key_helpers_without_a_jwt_import_need_a_header_qualified_kid() -> None:
    helper = "const fs = require('fs')\nconst k = fs.readFileSync(`keys/${header.kid}.pem`)\n"
    assert _kinds(helper, "keys.js") == {"jwt_header_trust"}
    assert _kinds("with open(f\"keys/{token_header['kid']}\") as f:\n    pass\n", "keys.py") == {"jwt_header_trust"}
    assert _kinds("with open(f\"keys/{header['kid']}\") as f:\n    pass\n", "keys.py") == {"jwt_header_trust"}
    assert _kinds('b, _ := os.ReadFile("keys/" + t.Header["kid"].(string))\n', "keys.go") == {"jwt_header_trust"}
    # A child record is not a key id.
    assert not _kinds("const p = path.join(root, 'kids', user.kid)\n", "family.js")


def test_rules_follow_the_library_that_owns_the_name() -> None:
    # saleor: PyJWT is imported for its exception only; `jwt` is authlib's.
    content = (
        "from authlib.jose import JWTClaims, jwt\n"
        "from jwt import PyJWTError\n"
        "def get_decoded_token(token, keys, claims_cls=None):\n"
        "    return jwt.decode(token, keys, claims_cls=claims_cls)\n"
    )
    assert _kinds(content, "utils.py") == {"jwt_claims_unchecked"}
    assert not _kinds(content + "def check(c):\n    c.validate()\n", "utils.py")


def test_decode_without_identity_use_is_not_flagged() -> None:
    # juice-shop: the server's own stored token, decoded for its `iat`.
    content = (
        "import { decode } from 'jsonwebtoken'\n"
        "const parsedToken = decode(userToken, { json: true })\n"
        "lastLoginTime = parsedToken ? parsedToken.iat : null\n"
    )
    assert not _kinds(content, "authenticatedUsers.ts")
    assert _kinds(content.replace(".iat", ".role"), "authenticatedUsers.ts") == {"jwt_unverified_decode"}


def test_unrelated_languages_are_ignored() -> None:
    assert find_jwt_issues("jwt.decode(token)\n", "a.php") == ([], [])


# ---------------------------------------------------------------------------
# Scan → control → finding (the #243 acceptance case)
# ---------------------------------------------------------------------------


def test_decode_only_repo_has_no_jwt_control_and_gets_a_finding(tmp_path: Path) -> None:
    root = _write(tmp_path, {"src/auth.js": (FIXTURES / "vuln_jsonwebtoken_decode.js").read_text(encoding="utf-8")})
    scan = scan_repo(root)
    controls = detect_controls(scan, [], [])
    assert not [c for c in controls if c.name == "JWT verification"]
    findings = [f for f in generate_findings(scan) if f.rule_id == "jwt-unverified-decode"]
    assert len(findings) == 1
    assert "src/auth.js:4" in findings[0].evidence[0]
    assert "token-auth" in findings[0].tags


def test_pinned_verify_credits_the_jwt_control(tmp_path: Path) -> None:
    root = _write(tmp_path, {"src/auth.js": (FIXTURES / "safe_jsonwebtoken.js").read_text(encoding="utf-8")})
    controls = [c for c in detect_controls(scan_repo(root), [], []) if c.name == "JWT verification"]
    assert len(controls) == 1
    assert controls[0].placements == ["src/auth.js"]


def test_route_paths_and_sign_no_longer_credit_the_jwt_control(tmp_path: Path) -> None:
    root = _write(
        tmp_path,
        {
            "app.js": (
                "const express = require('express')\n"
                "const jwt = require('jsonwebtoken')\n"
                "const app = express()\n"
                "app.post('/jwt/verify', (req, res) => res.json({ t: jwt.sign({}, process.env.K) }))\n"
            )
        },
    )
    controls = detect_controls(scan_repo(root), [], [])
    assert not [c for c in controls if c.name == "JWT verification"]


def test_test_files_are_skipped(tmp_path: Path) -> None:
    root = _write(tmp_path, {"tests/auth.test.js": (FIXTURES / "vuln_jsonwebtoken.js").read_text(encoding="utf-8")})
    scan = scan_repo(root)
    assert not [w for w in scan.code_weaknesses if w.kind in JWT_KINDS]


@pytest.mark.parametrize("kind", JWT_KINDS)
def test_rules_are_registered(kind: str) -> None:
    entry = taxonomy_for(kind.replace("_", "-"))
    assert entry is not None and "API2:2023" in entry.owasp
