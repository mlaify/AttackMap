"""Token-authentication protocol checks (#243, part 1: JWT).

Per-file finder, like ``weaknesses``, for JWT handling that the library calls
make unsafe. Every check is gated on the file importing the library it judges,
so ``jwt.decode`` is only read with ``jsonwebtoken`` / PyJWT / python-jose /
authlib / golang-jwt semantics in a file that imports that library.

    jwt_alg_confusion       verification without a pinned algorithm list
                            (jsonwebtoken ``verify`` without ``algorithms``,
                            PyJWT ``decode`` without ``algorithms=``, a
                            golang-jwt keyfunc that never checks ``t.Method``)
    jwt_unverified_decode   identity claims read off a token that the file
                            only decodes and never verifies (jsonwebtoken
                            ``decode``, jose ``decodeJwt``, python-jose
                            ``get_unverified_claims``, golang-jwt
                            ``ParseUnverified``)
    jwt_claims_unchecked    expiry/claims validation switched off
                            (``ignoreExpiration: true``, ``verify_exp: False``,
                            ``WithoutClaimsValidation``) or authlib claims
                            never ``validate()``d
    jwt_header_trust        the token header's ``kid`` built into a file path or
                            SQL string, or its ``jku``/``x5u`` URL fetched
    jwt_weak_secret         a short HMAC secret hard-coded at the sign/verify
                            call

The explicit cases (``alg: none``, signature verification switched off) stay
with ``jwt_weakness`` in ``weaknesses``; nothing here re-flags them.

A verifying call with a pinned algorithm list (or jose ``jwtVerify``, which
binds the algorithm to the key type) is returned as a ``jwt_verified`` auth
hint. That hint, and only that, credits the "JWT verification" control.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from .models import AuthHint, CodeWeakness
from .srcpaths import JS_TS_SUFFIXES, line_number

# HMAC secrets shorter than this are brute-forceable offline from one token.
_MIN_SECRET_LEN = 32
_CALL_SCAN_LIMIT = 4000


def _rx(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, re.MULTILINE | flags)


# --- library imports ---------------------------------------------------------

_JS_JWT_DEFAULT = _rx(
    r"(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*['\"]jsonwebtoken['\"]\s*\)"
    r"|import\s+(?:\*\s+as\s+)?(\w+)\s*(?:,\s*\{[^}]*\})?\s*from\s+['\"]jsonwebtoken['\"]"
)
_JS_JWT_NAMED = _rx(
    r"(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*['\"]jsonwebtoken['\"]\s*\)"
    r"|import\s+(?:\w+\s*,\s*)?\{([^}]*)\}\s*from\s+['\"]jsonwebtoken['\"]"
)
_JS_JOSE = _rx(r"(?:from\s+|require\(\s*)['\"]jose['\"]")

# Which library a name is bound to decides the rules: saleor imports
# `PyJWTError` from PyJWT but calls authlib's `jwt.decode`.
_PY_JWT_MODULE = _rx(r"^\s*import\s+jwt\s*(?:#.*)?$|^\s*from\s+jose\s+import\s+[^\n]*\bjwt\b")
_PY_JWT_ALIAS = _rx(r"^\s*import\s+jwt\s+as\s+(\w+)")
_PY_AUTHLIB_JWT = _rx(r"^\s*from\s+authlib\.jose\s+import\s+[^\n]*\bjwt\b|^\s*jwt\s*=\s*JsonWebToken\s*\(")
_PY_JWT_NAMED = _rx(r"^\s*from\s+jwt\s+import\s+\(?([^\n)]*)")
_PY_JOSE = _rx(r"^\s*from\s+jose\s+import\s+[^\n]*\bjwt\b")

_GO_JWT = _rx(
    r"^\s*(?:import\s+)?(\w+\s+)?\"github\.com/(?:golang-jwt/jwt|dgrijalva/jwt-go|form3tech-oss/jwt-go)[^\"]*\""
)

# --- shared patterns ---------------------------------------------------------

# `kid` / `jku` / `x5u` read off a header. In a file that imports a JWT library
# any `.kid` counts; elsewhere (a key-lookup helper) only a header-qualified
# read, so a `user.kid` child record isn't mistaken for a key id.
_KID_ANY = r"(?:\.kid\b|\[\s*['\"]kid['\"]\s*\])"
_KID_HEADER = r"(?:\b\w*[hH]eader\s*(?:\.kid\b|\[\s*['\"]kid['\"]\s*\]))"
_JKU_ANY = r"(?:\.(?:jku|x5u)\b|\[\s*['\"](?:jku|x5u)['\"]\s*\])"
_JKU_HEADER = r"(?:\b\w*[hH]eader\s*(?:\.(?:jku|x5u)\b|\[\s*['\"](?:jku|x5u)['\"]\s*\]))"


def _header_trust_patterns(kid: str, jku: str) -> tuple[re.Pattern[str], ...]:
    return (
        # kid into a file read / path join.
        _rx(
            r"(?:readFileSync|readFile|createReadStream|path\.(?:join|resolve)|\bopen"
            r"|os\.path\.join|filepath\.Join|os\.ReadFile|ioutil\.ReadFile|os\.Open)\s*\([^\n]*" + kid
        ),
        # kid interpolated into SQL (a bound parameter is fine, so require
        # interpolation: ${...kid}, f"...{...kid}", "..." + ...kid).
        _rx(
            r"\b(?:SELECT|DELETE|UPDATE|INSERT)\b[^\n]*?"
            r"(?:\$\{[^}\n]*" + kid + r"|\{[^}\n]*" + kid + r"[^}\n]*\}|['\"]\s*\+\s*[\w.\[\]'\"]*" + kid + r")",
            re.IGNORECASE,
        ),
        _rx(r"Sprintf\s*\(\s*\"[^\"\n]*\b(?:SELECT|DELETE|UPDATE|INSERT)\b[^\n]*" + kid, re.IGNORECASE),
        # jku / x5u URL fetched or handed to a JWKS client.
        _rx(
            r"(?:\bfetch|\baxios(?:\.get)?|\bgot|\brequests\.get|\burlopen|\bhttp\.Get|\bjwksUri\s*:"
            r"|\bJwksClient|\bjwksClient|\bcreateRemoteJWKSet|\bPyJWKClient)\s*\(?[^\n]*" + jku
        ),
    )


_HEADER_TRUST = _header_trust_patterns(_KID_ANY, _JKU_ANY)
_HEADER_TRUST_STRICT = _header_trust_patterns(_KID_HEADER, _JKU_HEADER)

# Claims that carry identity or privilege, read off a decoded token: `x.sub`,
# `x?.role`, `x["user_id"]`, `x.Claims.GetSubject()`.
_CLAIMS = r"(?:sub|subject|role|roles|user|userId|user_id|uid|email|username|scope|scopes|permissions|isAdmin|is_admin|admin)"
_IDENTITY_READ = (
    r"(?:\??\.(?:Claims\.)?(?:" + _CLAIMS + r"\b|GetSubject\s*\()|\[\s*['\"]" + _CLAIMS + r"['\"]\s*\])"
)
_IDENTITY_WINDOW = 1500

_GO_METHOD_CHECK = re.compile(r"\.Method\b|SigningMethod|\.Alg\s*\(|WithValidMethods")
_GO_SHORT_BYTES = _rx(r"\[\]byte\(\s*\"([^\"\n]*)\"\s*\)")
_GO_SECRET_CONTEXT = re.compile(r"SignedString|\breturn\b|key|secret", re.IGNORECASE)
_JOSE_SHORT_KEY = _rx(r"new\s+TextEncoder\(\s*\)\s*\.encode\(\s*(['\"`])([^'\"`\n$]*)\1\s*\)")
_JS_FUNCTION_ARG = re.compile(r"^(?:async\s+)?(?:function\b|\([^)]*\)\s*=>|\w+\s*=>)")
_PY_STRING = re.compile(r"^[rRbBuU]{0,2}(['\"])(.*)\1$", re.DOTALL)
_JS_STRING = re.compile(r"^(['\"`])(.*)\1$", re.DOTALL)


class _Collector:
    def __init__(self, content: str, rel_file: str, comment: str) -> None:
        self.content = content
        self.rel_file = rel_file
        self.comment = comment
        self.weaknesses: list[CodeWeakness] = []
        self.verified: list[AuthHint] = []
        self._seen: set[tuple[str, int]] = set()

    def commented(self, offset: int) -> bool:
        line_start = self.content.rfind("\n", 0, offset) + 1
        return self.comment in self.content[line_start:offset]

    def weakness(self, kind: str, severity: str, offset: int, note: str | None = None) -> None:
        line = line_number(self.content, offset)
        if (kind, line) in self._seen:
            return
        self._seen.add((kind, line))
        snippet = _snippet(self.content, offset)
        self.weaknesses.append(
            CodeWeakness(
                kind=kind,  # type: ignore[arg-type]
                file=self.rel_file,
                line=line,
                evidence_text=f"{snippet} ({note})" if note else snippet,
                severity=severity,  # type: ignore[arg-type]
                source_analyzer="auth_protocol",
            )
        )

    def unverified_decode(self, offset: int) -> None:
        """Report a decode with no verify in the file, when the claims it
        returns are read for identity nearby. Reading `iat`/`exp` off the
        server's own stored token (juice-shop's user list) is not trust."""
        if _reads_identity(self.content, offset):
            self.weakness("jwt_unverified_decode", "high", offset, "decoded but never verified in this file")

    def verified_at(self, offset: int) -> None:
        if self.verified:
            return  # one hint per file is enough to credit the control
        self.verified.append(
            AuthHint(
                hint="jwt_verified",
                file=self.rel_file,
                line=line_number(self.content, offset),
                evidence_text=_snippet(self.content, offset),
                confidence=0.9,
                source_analyzer="auth_protocol",
            )
        )

    def header_trust(self, patterns: tuple[re.Pattern[str], ...] = _HEADER_TRUST) -> None:
        for pattern in patterns:
            for match in pattern.finditer(self.content):
                if not self.commented(match.start()):
                    self.weakness("jwt_header_trust", "high", match.start())


def find_jwt_issues(content: str, rel_file: str) -> tuple[list[CodeWeakness], list[AuthHint]]:
    """JWT weaknesses in one file, plus a ``jwt_verified`` hint when the file
    verifies tokens with a pinned algorithm."""
    suffix = PurePosixPath(rel_file).suffix.lower()
    if suffix in JS_TS_SUFFIXES:
        collector = _Collector(content, rel_file, "//")
        _check_js(collector)
    elif suffix == ".py":
        collector = _Collector(content, rel_file, "#")
        _check_python(collector)
    elif suffix == ".go":
        collector = _Collector(content, rel_file, "//")
        _check_go(collector)
    else:
        return [], []
    return collector.weaknesses, collector.verified


# --- Node: jsonwebtoken + jose ------------------------------------------------


def _check_js(c: _Collector) -> None:
    content = c.content
    defaults = {m.group(1) or m.group(2) for m in _JS_JWT_DEFAULT.finditer(content)}
    named: dict[str, str] = {}
    for m in _JS_JWT_NAMED.finditer(content):
        for part in (m.group(1) or m.group(2) or "").split(","):
            pieces = re.split(r"\s+as\s+|\s*:\s*", part.strip())
            if pieces and pieces[0] in {"verify", "decode", "sign"}:
                named[pieces[-1]] = pieces[0]
    uses_jose = _JS_JOSE.search(content) is not None
    if not defaults and not named and not uses_jose:
        c.header_trust(_HEADER_TRUST_STRICT)
        return

    calls: list[tuple[str, int, list[str]]] = []  # (method, offset, args)
    if defaults:
        member = _rx(r"\b(?:" + "|".join(map(re.escape, sorted(defaults))) + r")\.(verify|decode|sign)\s*\(")
        for m in member.finditer(content):
            calls.append((m.group(1), m.start(), _call_args(content, m.end())))
    if named:
        bare = _rx(r"(?<![\w.])(" + "|".join(map(re.escape, sorted(named))) + r")\s*\(")
        for m in bare.finditer(content):
            calls.append((named[m.group(1)], m.start(), _call_args(content, m.end())))
    calls = [call for call in calls if not c.commented(call[1])]

    verifies = [call for call in calls if call[0] == "verify"]
    for method, offset, args in calls:
        if method in {"verify", "sign"} and len(args) > 1 and _short_literal(args[1], _JS_STRING):
            c.weakness("jwt_weak_secret", "high", offset, f"{method} with a hard-coded secret under {_MIN_SECRET_LEN} chars")
        if method != "verify" or len(args) < 2:
            continue
        options = args[2] if len(args) > 2 and not _JS_FUNCTION_ARG.match(args[2]) else ""
        if options.startswith("{"):
            pinned = re.search(r"\balgorithms\s*:", options) is not None
        elif options:
            # Options passed by name: give the benefit of the doubt when the
            # file pins algorithms anywhere.
            pinned = re.search(r"\balgorithms\s*:", content) is not None
        else:
            pinned = False
        if pinned:
            c.verified_at(offset)
        elif not _looks_like_hmac_secret(args[1], _JS_STRING):
            # An HMAC secret can't be swapped for a public key, so confusion
            # only applies to keys that may be asymmetric.
            c.weakness("jwt_alg_confusion", "high", offset, "no `algorithms` allow-list")

    jose_verify = _rx(r"(?<![\w.])jwtVerify\s*\(") if uses_jose else None
    jose_verifies = [m for m in jose_verify.finditer(content) if not c.commented(m.start())] if jose_verify else []
    for m in jose_verifies:
        c.verified_at(m.start())

    if not verifies and not jose_verifies:
        for method, offset, _ in calls:
            if method == "decode":
                c.unverified_decode(offset)
        if uses_jose:
            for m in _rx(r"(?<![\w.])decodeJwt\s*\(").finditer(content):
                if not c.commented(m.start()):
                    c.unverified_decode(m.start())

    if defaults or named:
        for m in _rx(r"\bignoreExpiration\s*:\s*true\b").finditer(content):
            if not c.commented(m.start()):
                c.weakness("jwt_claims_unchecked", "medium", m.start(), "expiry not checked")
    if uses_jose:
        for m in _JOSE_SHORT_KEY.finditer(content):
            if len(m.group(2)) < _MIN_SECRET_LEN and not c.commented(m.start()):
                c.weakness("jwt_weak_secret", "high", m.start(), f"hard-coded secret under {_MIN_SECRET_LEN} chars")
    c.header_trust()


# --- Python: PyJWT, python-jose, authlib -------------------------------------


def _check_python(c: _Collector) -> None:
    content = c.content
    names = {m.group(1) for m in _PY_JWT_ALIAS.finditer(content)}
    uses_authlib = _PY_AUTHLIB_JWT.search(content) is not None
    if _PY_JWT_MODULE.search(content) and not uses_authlib:
        names.add("jwt")
    bare: dict[str, str] = {}
    for m in _PY_JWT_NAMED.finditer(content):
        for part in m.group(1).split(","):
            pieces = part.strip().split(" as ")
            if pieces[0].strip() in {"decode", "encode"}:
                bare[pieces[-1].strip()] = pieces[0].strip()
    if not names and not bare and not uses_authlib:
        c.header_trust(_HEADER_TRUST_STRICT)
        return
    if uses_authlib:
        _check_authlib(c)
    if not names and not bare:
        c.header_trust()
        return

    calls: list[tuple[str, int, list[str]]] = []
    if names:
        member = _rx(r"\b(?:" + "|".join(map(re.escape, sorted(names))) + r")\.(decode|encode)\s*\(")
        for m in member.finditer(content):
            calls.append((m.group(1), m.start(), _call_args(content, m.end())))
    if bare:
        for m in _rx(r"(?<![\w.])(" + "|".join(map(re.escape, sorted(bare))) + r")\s*\(").finditer(content):
            calls.append((bare[m.group(1)], m.start(), _call_args(content, m.end())))

    verifies = False
    for method, offset, args in calls:
        if c.commented(offset):
            continue
        positional = [a for a in args if not re.match(r"^\*{0,2}\w+\s*=(?!=)|^\*\*", a)]
        keywords = {a.split("=", 1)[0].strip(): a.split("=", 1)[1].strip() for a in args if re.match(r"^\w+\s*=(?!=)", a)}
        key = positional[1] if len(positional) > 1 else keywords.get("key", "")
        if key and _short_literal(key, _PY_STRING):
            c.weakness("jwt_weak_secret", "high", offset, f"{method} with a hard-coded secret under {_MIN_SECRET_LEN} chars")
        if method != "decode":
            continue
        call_text = ", ".join(args)
        if re.search(r"verify\s*=\s*False|verify_signature['\"]?\s*:\s*False", call_text):
            continue  # jwt_weakness already reports it
        verifies = True
        if re.search(r"['\"]verify_exp['\"]\s*:\s*False", call_text):
            c.weakness("jwt_claims_unchecked", "medium", offset, "expiry not checked")
        if "algorithms" in keywords:
            c.verified_at(offset)
        elif not any(a.startswith("**") for a in args) and not _looks_like_hmac_secret(key, _PY_STRING):
            c.weakness("jwt_alg_confusion", "high", offset, "no `algorithms=` allow-list")

    if _PY_JOSE.search(content) and not verifies:
        for m in _rx(r"\bjwt\.get_unverified_claims\s*\(").finditer(content):
            if not c.commented(m.start()):
                c.unverified_decode(m.start())
    c.header_trust()


def _check_authlib(c: _Collector) -> None:
    """authlib's ``jwt.decode`` checks the signature but not the claims: they
    are only validated by an explicit ``claims.validate()``."""
    content = c.content
    decodes = [m for m in _rx(r"\bjwt\.decode\s*\(").finditer(content) if not c.commented(m.start())]
    if not decodes:
        return
    if re.search(r"\.validate\s*\(", content):
        c.verified_at(decodes[0].start())
        return
    for m in decodes:
        c.weakness("jwt_claims_unchecked", "medium", m.start(), "authlib claims never validate()d")


# --- Go: golang-jwt / jwt-go --------------------------------------------------


def _check_go(c: _Collector) -> None:
    content = c.content
    imports = list(_GO_JWT.finditer(content))
    if not imports:
        c.header_trust(_HEADER_TRUST_STRICT)
        return
    names = {(m.group(1) or "jwt").strip() for m in imports}
    alias = "|".join(map(re.escape, sorted(names)))

    parses = [
        m for m in _rx(r"\b(?:" + alias + r")\.(Parse|ParseWithClaims)\s*\(").finditer(content)
        if not c.commented(m.start())
    ]
    for m in parses:
        args = _call_args(content, m.end())
        # An inline keyfunc is judged on its own body; a named one (or options
        # like WithValidMethods) could be anywhere in the file.
        keyfunc = next((a for a in args if a.startswith("func")), None)
        if _GO_METHOD_CHECK.search(keyfunc or content) or "WithValidMethods" in ", ".join(args):
            c.verified_at(m.start())
        else:
            c.weakness("jwt_alg_confusion", "high", m.start(), "keyfunc never checks token.Method")
    # A parser built with WithValidMethods and used as p.Parse(...).
    valid_methods = re.search(r"\bWithValidMethods\s*\(", content)
    if not parses and valid_methods:
        c.verified_at(valid_methods.start())

    if not parses and not valid_methods:
        for m in _rx(r"\.ParseUnverified\s*\(").finditer(content):
            if not c.commented(m.start()):
                c.unverified_decode(m.start())
    for m in _rx(r"\bWithoutClaimsValidation\s*\(|\bSkipClaimsValidation\s*:\s*true\b").finditer(content):
        if not c.commented(m.start()):
            c.weakness("jwt_claims_unchecked", "medium", m.start(), "claims validation disabled")
    for m in _GO_SHORT_BYTES.finditer(content):
        if len(m.group(1)) >= _MIN_SECRET_LEN or c.commented(m.start()):
            continue
        line_start = content.rfind("\n", 0, m.start()) + 1
        line_end = content.find("\n", m.end())
        line = content[line_start : line_end if line_end != -1 else len(content)]
        if _GO_SECRET_CONTEXT.search(line):
            c.weakness("jwt_weak_secret", "high", m.start(), f"hard-coded secret under {_MIN_SECRET_LEN} chars")
    c.header_trust()


# --- helpers ------------------------------------------------------------------


def _reads_identity(content: str, offset: int) -> bool:
    """True if identity claims are read off the decode call at ``offset``:
    chained on the call itself, or off the variable it is assigned to."""
    open_paren = content.find("(", offset)
    args_end = open_paren + 1 + len(", ".join(_call_args(content, open_paren + 1)))
    close = content.find(")", args_end)
    if close != -1 and re.match(_IDENTITY_READ, content[close + 1 : close + 40]):
        return True
    var = _assigned_name(content[content.rfind("\n", 0, offset) + 1 : offset])
    if var is None:
        return False
    var = re.escape(var)
    window = content[offset : offset + _IDENTITY_WINDOW]
    return re.search(r"\b" + var + _IDENTITY_READ, window) is not None


def _assigned_name(prefix: str) -> str | None:
    """The first name assigned from the expression ending ``prefix``:
    ``claims`` in ``const claims = jwt.``, ``token`` in ``token, _, err :=
    jwt.NewParser().``. A right-to-left scan, not a regex: an anchored pattern
    retried at every offset of a long minified line is quadratic (#236)."""
    i = len(prefix)
    while i and (prefix[i - 1].isalnum() or prefix[i - 1] in "_.() \t"):
        i -= 1  # the receiver chain, `await`, spaces
    if prefix[i - 1 : i] != "=" or prefix[i - 2 : i - 1] in {"=", "!", "<", ">"}:
        return None
    i -= 2 if prefix[i - 2 : i - 1] == ":" else 1
    lhs = prefix[:i].rstrip().rsplit(";", 1)[-1]
    first = lhs.split(",")[0].split()
    name = first[-1] if first else ""
    return name if name.isidentifier() else None


def _call_args(content: str, offset: int) -> list[str]:
    """Top-level arguments of the call whose ``(`` ends at ``offset``. Bounded,
    and string-aware enough that commas in literals don't split."""
    args: list[str] = []
    depth = 0
    quote: str | None = None
    start = offset
    end = min(len(content), offset + _CALL_SCAN_LIMIT)
    i = offset
    while i < end:
        ch = content[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif ch == "," and depth == 0:
            args.append(content[start:i].strip())
            start = i + 1
        i += 1
    tail = content[start:i].strip()
    if tail:
        args.append(tail)
    return args


def _literal(arg: str, pattern: re.Pattern[str]) -> str | None:
    m = pattern.match(arg.strip())
    if m is None or "${" in m.group(2) or "\n" in m.group(2):
        return None
    return m.group(2)


def _short_literal(arg: str, pattern: re.Pattern[str]) -> bool:
    value = _literal(arg, pattern)
    return value is not None and len(value) < _MIN_SECRET_LEN


def _looks_like_hmac_secret(arg: str, pattern: re.Pattern[str]) -> bool:
    return _literal(arg, pattern) is not None or re.search(r"secret", arg, re.IGNORECASE) is not None


def _snippet(content: str, offset: int, radius: int = 120) -> str:
    start = content.rfind("\n", 0, offset) + 1
    end = content.find("\n", offset)
    line = content[start : end if end != -1 else len(content)].strip()
    return line[:radius] + ("…" if len(line) > radius else "")


__all__ = ["find_jwt_issues"]
