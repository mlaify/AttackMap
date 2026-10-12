"""Web-hardening gap detection (#71).

A per-file pass (invoked from the built-in scanner's existing read loop)
that flags *positively-present* web misconfigurations rather than
hard-to-judge absences:

    cors_wildcard_credentials  wildcard/reflected origin WITH credentials
    cors_wildcard_origin       wildcard/reflected origin, no credentials (low)
    cors_untrusted_origin      origin allow-list that admits attacker origins:
                               unanchored regex, suffix/substring match, or
                               `null` (high with credentials, else medium)
    csrf_disabled              CSRF explicitly disabled or exempted
    csrf_unprotected_session   cookie-session auth with no CSRF middleware or
                               SameSite=Strict/Lax anywhere in the repo (#244)
    insecure_cookie            httpOnly/secure=false, SameSite=None, etc.
    weak_csp                   CSP allowing 'unsafe-inline' / 'unsafe-eval'
    debug_enabled              debug mode / actuator wildcard exposure

Pure-absence checks ("no CSP header anywhere") are intentionally out of
scope — they're noisy without whole-app reasoning. Everything here keys
off a concrete risky construct in the source.
"""

from __future__ import annotations

import re

from pathlib import Path

from .models import WebHardeningIssue
from .safe_fs import is_oversized, walk_repo
from .srcpaths import is_skipped_dir, is_test_file, is_vendored_file, line_number


def _rx(pattern: str) -> re.Pattern[str]:
    # MULTILINE so `^`-anchored patterns (e.g. Django's `DEBUG = True`)
    # match at each line start, not just the start of the file.
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE)


# CORS is a two-signal model (#244): the origin policy (wildcard, reflected,
# unanchored regex, suffix/substring match, `null`, or an exact allow-list)
# times whether credentials are allowed. Detected via file-level co-occurrence
# so argument order and framework don't matter.
_CORS_WILD_ORIGIN = _rx(
    r"access-control-allow-origin['\"]?\s*\]?\s*[:,=]\s*['\"]?\*"
    r"|origins?\s*[:=]\s*['\"]\*['\"]"
    r"|origin\s*:\s*true\b"
    r"|allow_origins\s*=\s*[\[(]\s*['\"]\*['\"]"
    r"|^\s*CORS_(?:ORIGIN_ALLOW_ALL|ALLOW_ALL_ORIGINS)\s*=\s*True"
)
# The request's own Origin echoed back, or an origin callback that accepts
# everything. Guarded forms (an allow-list check nearby) are filtered below.
_CORS_REFLECTED = _rx(
    r"access-control-allow-origin['\"]?\s*\]?\s*[,:=]\s*(?:req|request|ctx|c)\b[^\n;]{0,60}?origin"
    r"|\borigin\s*:\s*(?:async\s+)?(?:function\b|\(|\w+\s*=>)[^\n]{0,80}?\(\s*null\s*,\s*true\s*\)"
)
_CORS_CREDENTIALS = _rx(
    r"access-control-allow-credentials['\"]?\s*\]?\s*[:,=]\s*['\"]?true"
    r"|credentials\s*:\s*true"
    r"|supports_credentials\s*=\s*True"
    r"|allow_credentials\s*=\s*True"
    r"|^\s*CORS_ALLOW_CREDENTIALS\s*=\s*True"
)
# An allow-list check near a reflected origin: `if (allowed.includes(o))`.
_ORIGIN_GUARD = re.compile(r"\bif\b|\?(?![.:])|\.includes\s*\(|\.has\s*\(|\.test\s*\(|indexOf\s*\(|\bin\s+\w", re.IGNORECASE)
# Origin values that admit attacker-controlled origins.
_CORS_JS_ORIGIN_VALUE = _rx(r"\borigin\s*:\s*(\[[^\]\n]{0,300}\]?|/[^\n]{0,300})")
_JS_REGEX_LITERAL = re.compile(r"/((?:\\.|[^/\\\n]){1,200})/[a-z]{0,6}")
_QUOTED = re.compile(r"'[^'\n]{0,300}'|\"[^\"\n]{0,300}\"")
_CORS_DJANGO_REGEXES = _rx(r"^\s*CORS_(?:ALLOWED_ORIGIN_REGEXES|ORIGIN_REGEX_WHITELIST)\s*=\s*[\[(]([^\])]{0,1000})")
_CORS_STARLETTE_REGEX = _rx(r"\ballow_origin_regex\s*=\s*r?(?:'([^'\n]{1,300})'|\"([^\"\n]{1,300})\")")
_ORIGIN_PARTIAL_MATCH = _rx(
    r"\b\w{0,20}?origin(?:header)?\s*\??\.\s*(endsWith|endswith|includes|indexOf|contains)\s*\(\s*(?:'([^'\n]{1,100})'|\"([^\"\n]{1,100})\")"
    r"|(?:'([^'\n]{1,100})'|\"([^\"\n]{1,100})\")\s+in\s+(?:request\.headers\.get\(\s*['\"]origin['\"]\s*\)|origin\b)"
)
_CORS_NULL_ORIGIN = _rx(
    r"\b(?:origins?|allow_origins|CORS_ALLOWED_ORIGINS|CORS_ORIGIN_WHITELIST|allowedOrigins)['\"]?\s*[:=]\s*[\[(][^\])]{0,300}?['\"]null['\"]"
    r"|access-control-allow-origin['\"]?\s*\]?\s*[,:=]\s*['\"]null['\"]"
)
# `.*example\.com` / `.+example` — a wildcard run straight into a label, so
# `evilexample.com` matches.
_WILDCARD_INTO_LABEL = re.compile(r"\.[*+]\??[A-Za-z0-9]")

# CSRF inference (#244): cookie-session auth with no CSRF defence. A file
# configuring session-cookie auth is a candidate; the scanner drops all
# candidates when any file carries a CSRF marker (`has_csrf_protection`), and
# the finding needs a state-changing route.
_SESSION_COOKIE_AUTH = _rx(
    r"require\s*\(\s*['\"](?:express-session|cookie-session)['\"]\s*\)"
    r"|\bfrom\s+['\"](?:express-session|cookie-session)['\"]"
    r"|\bimport\s+\w+\s*=\s*require\s*\(\s*['\"](?:express-session|cookie-session)['\"]"
    r"|['\"]django\.contrib\.sessions\.middleware\.SessionMiddleware['\"]"
    r"|\bLoginManager\s*\("
)
_CSRF_PROTECTION = _rx(
    r"\bcsurf\b|\blusca\b|csrf-csrf|tiny-csrf|@fastify/csrf|csrf-sync|\bdoubleCsrf\b|\bcsrfSync\b"
    r"|\bcsrf\s*\(|CsrfViewMiddleware|\bcsrf_protect\b|\bCSRFProtect\b|\bCsrfProtect\b|\bCSRFMiddleware\b"
    r"|\bFlaskForm\b|\bcsrf_token\b|\bcsrfToken\b"
    r"|same_?site['\"]?\s*[:=]\s*(?:['\"]?(?:strict|lax)\b|true\b)"
    r"|SESSION_COOKIE_SAMESITE\s*=\s*['\"](?:Strict|Lax)"
)


def has_csrf_protection(content: str) -> bool:
    """True if ``content`` carries a CSRF defence (token middleware, a CSRF
    decorator, or a SameSite=Strict/Lax session cookie) outside a comment —
    a commented-out `CsrfViewMiddleware` is the classic way to disable it.
    The scanner uses this to drop `csrf_unprotected_session` candidates
    repo-wide."""
    for match in _CSRF_PROTECTION.finditer(content):
        start = content.rfind("\n", 0, match.start()) + 1
        if not content[start:match.start()].lstrip().startswith(("#", "//")):
            return True
    return False


# Spring Security turning CSRF protection off. The builder forms are method
# calls on the security config (`csrf().disable()`, `csrf(c -> c.disable())`,
# `csrf(AbstractHttpConfigurer::disable)`, Kotlin `.csrf { it.disable() }`);
# the Kotlin DSL `csrf { disable() }` (#341) only counts inside an `http { }`
# block. Core's per-file pass doesn't read .java/.kt files, so
# `find_jvm_csrf_disabled` runs these over them.
_SPRING_CSRF_BUILDER = _rx(
    r"\.csrf\s*\(\s*\)\s*\.\s*disable\s*\("
    r"|csrf\s*\(\s*(?:[\w.]+\s*->\s*[\w.]+\s*\.\s*disable\s*\(\)|[\w.:]+::disable)\s*\)"
    r"|\.\s*csrf\s*\{\s*(?:it|\w+\s*->\s*\w+)\s*\.\s*disable\s*\(\s*\)\s*\}"
)
_KOTLIN_CSRF_DSL = _rx(r"\bcsrf\s*\{\s*disable\s*\(\s*\)\s*\}")
_SPRING_CSRF_DISABLED = _rx(_SPRING_CSRF_BUILDER.pattern + "|" + _KOTLIN_CSRF_DSL.pattern)
# The opener of a Kotlin security DSL block: `http {` (HttpSecurity and
# ServerHttpSecurity both use it) or `http.invoke {`.
_HTTP_DSL_OPENER = re.compile(r"\bhttp\s*(?:\.\s*invoke\s*)?\Z")
_JVM_SUFFIXES = frozenset({".java", ".kt"})
_STATELESS_SESSION = _rx(r"SessionCreationPolicy\s*\.\s*STATELESS\b")


# Single-pattern families: (kind, severity, pattern).
_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    # --- CSRF explicitly disabled ---------------------------------------
    (
        "csrf_disabled",
        "medium",
        _rx(
            r"@?csrf_exempt\b"
            r"|WTF_CSRF_ENABLED\s*=\s*False"
            r"|\bcsrf\s*:\s*false"
        ),
    ),
    (
        "csrf_disabled",
        "medium",
        _SPRING_CSRF_DISABLED,
    ),
    # --- insecure cookie flags ------------------------------------------
    (
        "insecure_cookie",
        "medium",
        _rx(
            r"httpOnly\s*:\s*false"
            r"|\bsecure\s*:\s*false"
            r"|sameSite\s*:\s*['\"]?none"
            r"|SESSION_COOKIE_SECURE\s*=\s*False"
            r"|SESSION_COOKIE_HTTPONLY\s*=\s*False"
            r"|SESSION_COOKIE_SAMESITE\s*=\s*['\"]?None"
            r"|;\s*samesite=none(?!.*;\s*secure)"
        ),
    ),
    # --- weak CSP -------------------------------------------------------
    (
        "weak_csp",
        "medium",
        # 'unsafe-inline' / 'unsafe-eval' only appear in a CSP context.
        _rx(r"['\"]unsafe-(?:inline|eval)['\"]|(?<![\w-])unsafe-(?:inline|eval)(?![\w-])"),
    ),
    # --- debug enabled --------------------------------------------------
    (
        "debug_enabled",
        "medium",
        _rx(
            r"app\.run\s*\([^)]*debug\s*=\s*True"
            r"|^\s*DEBUG\s*=\s*True"
            r"|\bapp\.debug\s*=\s*true"
            r"|FLASK_DEBUG\s*=\s*1"
            r"|consider_all_requests_local\s*=\s*true"
            r"|management\.endpoints\.web\.exposure\.include\s*=\s*\*"
            r"|exposure\.include['\"]?\s*[:=]\s*['\"]\*['\"]"
        ),
    ),
)


def find_web_hardening_issues(content: str, rel_file: str) -> list[WebHardeningIssue]:
    """Return web-hardening issues in one file's ``content`` (deduped by
    (kind, line))."""
    seen: set[tuple[str, int]] = set()
    out: list[WebHardeningIssue] = []

    def _add(kind: str, severity: str, offset: int) -> None:
        line = line_number(content, offset)
        key = (kind, line)
        if key in seen:
            return
        seen.add(key)
        out.append(
            WebHardeningIssue(
                kind=kind,  # type: ignore[arg-type]
                file=rel_file,
                line=line,
                evidence_text=_snippet(content, offset),
                severity=severity,  # type: ignore[arg-type]
                source_analyzer="webhardening",
            )
        )

    # CORS (#244): origin policy x credentials.
    credentials = _CORS_CREDENTIALS.search(content) is not None
    permissive = _permissive_origin_offset(content)
    if permissive is not None:
        _add(
            "cors_wildcard_credentials" if credentials else "cors_wildcard_origin",
            "high" if credentials else "low",
            permissive,
        )
    for offset in _untrusted_origin_offsets(content):
        _add("cors_untrusted_origin", "high" if credentials else "medium", offset)

    # CSRF inference (#244): session-cookie auth without a CSRF defence in
    # this file. Cross-file defences are applied by the scanner.
    session = _SESSION_COOKIE_AUTH.search(content)
    if session is not None and not has_csrf_protection(content):
        _add("csrf_unprotected_session", "medium", session.start())

    for kind, severity, pattern in _PATTERNS:
        for match in pattern.finditer(content):
            _add(kind, severity, match.start())

    return out


def mask_jvm_comments_and_strings(text: str) -> str:
    """``text`` with Java/Kotlin comments, string and char literals replaced
    by spaces (newlines kept), so offsets and line numbers are unchanged.
    Handles `//`, nested `/* */` (Kotlin nests them; Java code doesn't), `"…"`
    with escapes, `\"\"\"…\"\"\"` text blocks and `'c'`. Never raises; an
    unterminated construct masks to the end of the text."""
    out = list(text)
    n = len(text)
    i = 0

    def blank(a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            end = text.find("\n", i)
            end = n if end == -1 else end
            blank(i, end)
            i = end
        elif ch == "/" and nxt == "*":
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif text.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            blank(i, j)
            i = j
        elif text.startswith('"""', i):
            end = text.find('"""', i + 3)
            end = n if end == -1 else end + 3
            blank(i, end)
            i = end
        elif ch in "\"'":
            j = i + 1
            while j < n and text[j] != ch and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            end = min(j + 1, n)
            blank(i, end)
            i = end
        else:
            i += 1
    return "".join(out)


def _inside_http_dsl(masked: str, offset: int, limit: int = 20_000) -> bool:
    """Whether ``offset`` sits inside a block opened by `http {` (walking
    out through enclosing braces, at most ``limit`` characters back)."""
    depth = 0
    floor = max(0, offset - limit)
    for k in range(offset - 1, floor - 1, -1):
        ch = masked[k]
        if ch == "}":
            depth += 1
        elif ch == "{":
            if depth:
                depth -= 1
            elif _HTTP_DSL_OPENER.search(masked, max(floor, k - 40), k):
                return True
    return False


def _enclosing_block(masked: str, offset: int, limit: int = 20_000) -> tuple[int, int]:
    """Span of the innermost `{ … }` block around ``offset`` (the method
    body or DSL block holding the CSRF call); the whole text if none is found
    within ``limit`` characters."""
    depth = 0
    start = -1
    for k in range(offset - 1, max(0, offset - limit) - 1, -1):
        if masked[k] == "}":
            depth += 1
        elif masked[k] == "{":
            if not depth:
                start = k
                break
            depth -= 1
    if start < 0:
        return 0, len(masked)
    depth = 0
    for k in range(start, min(len(masked), start + 2 * limit)):
        if masked[k] == "{":
            depth += 1
        elif masked[k] == "}":
            depth -= 1
            if not depth:
                return start, k + 1
    return start, len(masked)


def find_jvm_csrf_disabled(root: str | Path) -> list[WebHardeningIssue]:
    """`csrf_disabled` in Spring Security config written in Java or Kotlin
    (#341). Whole-repo pass: core's per-file scan covers Python/JS/TS/Go/PHP
    only, so without it the Spring forms above were never checked. Test and
    vendored files are skipped; comments and string literals are masked
    before matching; the Kotlin DSL form needs an enclosing `http { }`."""
    root_path = Path(root)
    out: list[WebHardeningIssue] = []
    for path in walk_repo(root_path, prune=is_skipped_dir):
        if path.suffix not in _JVM_SUFFIXES or is_oversized(path):
            continue
        rel = path.relative_to(root_path).as_posix()
        if is_test_file(rel) or is_vendored_file(rel):
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "csrf" not in content:
            continue
        out.extend(_jvm_csrf_issues(content, rel))
    return out


def _jvm_csrf_issues(content: str, rel: str) -> list[WebHardeningIssue]:
    masked = mask_jvm_comments_and_strings(content)
    offsets = [m.start() for m in _SPRING_CSRF_BUILDER.finditer(masked)]
    offsets += [m.start() for m in _KOTLIN_CSRF_DSL.finditer(masked) if _inside_http_dsl(masked, m.start())]
    stateless_offsets = [m.start() for m in _STATELESS_SESSION.finditer(masked)]
    out: list[WebHardeningIssue] = []
    seen: set[int] = set()
    for offset in sorted(offsets):
        line = line_number(content, offset)
        if line in seen:
            continue
        seen.add(line)
        # A stateless session policy in the same config block (method body or
        # DSL block), not merely somewhere in the file.
        lo, hi = _enclosing_block(masked, offset) if stateless_offsets else (0, 0)
        stateless = any(lo <= other < hi for other in stateless_offsets)
        out.append(
            WebHardeningIssue(
                kind="csrf_disabled",
                file=rel,
                line=line,
                evidence_text=_snippet(content, offset)
                + (" [stateless session policy in this config]" if stateless else ""),
                severity="low" if stateless else "medium",
                source_analyzer="webhardening",
            )
        )
    return out


def _line_at(content: str, offset: int) -> tuple[int, int]:
    start = content.rfind("\n", 0, offset) + 1
    end = content.find("\n", offset)
    return start, (len(content) if end == -1 else end)


def _permissive_origin_offset(content: str) -> int | None:
    """Offset of a wildcard or reflected origin, or None. A reflected origin
    with an allow-list check on its line or the 3 lines before is guarded."""
    wild = _CORS_WILD_ORIGIN.search(content)
    if wild is not None:
        return wild.start()
    for match in _CORS_REFLECTED.finditer(content):
        start, end = _line_at(content, match.start())
        window_start = start
        for _ in range(3):
            if window_start == 0:
                break
            window_start = content.rfind("\n", 0, window_start - 1) + 1
        if _ORIGIN_GUARD.search(content, window_start, end):
            continue
        return match.start()
    return None


def _js_regex_unsafe(body: str) -> bool:
    """A JS origin regex used with `.test()` (unanchored): unsafe without a
    trailing `$`, when it starts straight into a domain label without `^`,
    or when a wildcard runs into a label."""
    if not body.endswith("$"):
        return True
    if not body.startswith("^") and body[:1].isalnum():
        return True
    return _WILDCARD_INTO_LABEL.search(body) is not None


def _untrusted_origin_offsets(content: str) -> list[int]:
    out: list[int] = []
    for match in _CORS_JS_ORIGIN_VALUE.finditer(content):
        value = _QUOTED.sub("''", match.group(1))
        if any(_js_regex_unsafe(rx.group(1)) for rx in _JS_REGEX_LITERAL.finditer(value)):
            out.append(match.start())
    for match in _CORS_DJANGO_REGEXES.finditer(content):
        # django-cors-headers uses re.match: anchored at the start only.
        for quoted in _QUOTED.finditer(match.group(1)):
            body = quoted.group(0)[1:-1]
            if not body.endswith("$") or _WILDCARD_INTO_LABEL.search(body):
                out.append(match.start())
                break
    for match in _CORS_STARLETTE_REGEX.finditer(content):
        # Starlette uses re.fullmatch, so only a wildcard into a label leaks.
        if _WILDCARD_INTO_LABEL.search(match.group(1) or match.group(2) or ""):
            out.append(match.start())
    for match in _ORIGIN_PARTIAL_MATCH.finditer(content):
        method = (match.group(1) or "").lower()
        arg = match.group(2) or match.group(3) or match.group(4) or match.group(5) or ""
        if "." not in arg:
            continue  # not a host name
        if method == "endswith" and arg.startswith("."):
            continue  # `.endsWith('.example.com')` is a sound subdomain check
        out.append(match.start())
    for match in _CORS_NULL_ORIGIN.finditer(content):
        out.append(match.start())
    return out


def _snippet(content: str, offset: int, radius: int = 120) -> str:
    start = max(0, content.rfind("\n", 0, offset) + 1)
    end = content.find("\n", offset)
    if end == -1:
        end = len(content)
    line = content[start:end].strip()
    return line[:radius] + ("…" if len(line) > radius else "")


__all__ = [
    "find_jvm_csrf_disabled",
    "find_web_hardening_issues",
    "has_csrf_protection",
    "mask_jvm_comments_and_strings",
]
