"""Handler-level session checks in JS/TS route handlers (#348).

`unauth-state-change` resolves auth on a route's middleware chain. Many
JS/TS handlers authenticate in their own body instead::

    const session = await getSession(c);
    if (!session.user) {
      throw new AppError(AppErrorCode.UNAUTHORIZED);
    }

This module recognises that shape structurally, and nothing looser, because
keyword proximity can't tell a rejecting check from a log line (the lesson of
#374):

1. Strings and comments are masked before any test.
2. A *session lookup* is a declaration whose initializer calls a session API
   (`getSession(`, `getServerSession(`, `auth()`, `currentUser(`,
   `supabase.auth.getUser(`, …) or looks a credential from the request up
   (`users.get(req.cookies.token)`). Its declared names (including
   destructured ones) are tracked. A later reassignment of a tracked name
   stops tracking it.
3. A *gate* is an `if` whose condition, parsed with balanced parentheses, is
   exactly `!name` or `!name.member…` (optional chaining allowed), where
   `name` is tracked.
4. The gate's then-branch (a braced block or a single statement) must reject:
   its first statement is a `return` (not `return next()`), a `throw`, or a
   bare `redirect(...)` (Next/Remix redirects throw). An Express-style
   `next(err)` or `res.status(401|403)…` counts only when the next statement
   is a `return`.

Anything else is not a gate, so the finding stays.
"""

from __future__ import annotations

import re

_SESSION_CALL = re.compile(
    r"(?<![\w$.])(?:getSession|getServerSession|getServerAuthSession|getAuthSession|getUserSession"
    r"|validateSession|validateRequest|requireSession|currentUser|getCurrentUser|getToken|auth)\s*+\("
    r"|\.\s*auth\s*+\.\s*getUser\s*+\(|\bauthenticatedUsers\s*+\.\s*get\s*+\("
)
# A lookup keyed by the request's own credential (cookie, session, auth header).
_CREDENTIAL_ARG = re.compile(
    r"\b(?:req|request|c\s*\.\s*req)\s*\.\s*(?:cookies?|signedCookies|session)\b"
    r"|\bheaders?\s*\.\s*authorization\b"
)
_DECLARATION = re.compile(
    r"(?<![\w$])(?:const|let|var)\s++(?:\{(?P<names>[^{}]{1,300})\}|(?P<name>[A-Za-z_$][\w$]{0,80}+))"
    r"\s*+(?::[^=;\n]{1,120})?=(?![=>])"
)
_IDENT = re.compile(r"[A-Za-z_$][\w$]{0,80}")
_IF = re.compile(r"(?<![\w$.])if\s*+\(")
_GATE_CONDITION = re.compile(r"\A\s*!\s*(?P<name>[A-Za-z_$][\w$]{0,80})(?:\s*\??\.\s*[A-Za-z_$][\w$]{0,80})*\s*\Z")
_REJECTING_FIRST = re.compile(r"\A\s*(?:throw\b|redirect\s*\()")
_RETURN = re.compile(r"\A\s*return\b(?P<rest>.*)\Z", re.DOTALL)
_BARE_NEXT = re.compile(r"\A\s*next\s*\(\s*\)\s*\Z")
_NEXT_WITH_ERROR = re.compile(r"\A\s*next\s*\(\s*\S")
_STATUS_REJECT = re.compile(r"\A\s*(?:res|response|reply|ctx)\s*\.\s*(?:status|code)\s*\(\s*(?:401|403)\s*\)")
_MAX_SPAN_CHARS = 20_000
_MAX_IFS = 200
_MAX_CONDITION_CHARS = 400
_MAX_BRANCH_CHARS = 4_000


def mask(text: str) -> str:
    """``text`` with string literals and comments replaced by spaces (same length)."""
    out = list(text)
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c in "'\"`":
            j = i + 1
            while j < n and text[j] != c:
                if text[j] == "\\":
                    j += 1
                elif text[j] == "\n" and c != "`":
                    break
                j += 1
            for k in range(i + 1, min(j, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = j + 1
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
            continue
        i += 1
    return "".join(out)


def _balanced(text: str, start: int, open_ch: str, close_ch: str, limit: int) -> int | None:
    """Index of the ``close_ch`` matching ``text[start] == open_ch``, within ``limit`` chars."""
    depth = 0
    for i in range(start, min(len(text), start + limit)):
        if text[i] == open_ch:
            depth += 1
        elif text[i] == close_ch:
            depth -= 1
            if depth == 0:
                return i
    return None


def _statements(block: str) -> list[str]:
    """Top-level statements of a block body, split on `;` and newlines at depth 0."""
    out: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in block:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if depth == 0 and ch in ";\n":
            stmt = "".join(current).strip()
            if stmt:
                out.append(stmt)
            current = []
            continue
        current.append(ch)
    stmt = "".join(current).strip()
    if stmt:
        out.append(stmt)
    return out


def _rejects(statements: list[str]) -> bool:
    if not statements:
        return False
    first = statements[0]
    second = statements[1] if len(statements) > 1 else ""
    if _REJECTING_FIRST.match(first):
        return True
    returned = _RETURN.match(first)
    if returned:
        return not _BARE_NEXT.match(returned.group("rest"))
    if (_NEXT_WITH_ERROR.match(first) or _STATUS_REJECT.match(first)) and re.match(r"\A\s*return\b", second):
        return True
    return False


def _then_branch(code: str, after_paren: int) -> list[str] | None:
    i = after_paren
    while i < len(code) and code[i] in " \t\r\n":
        i += 1
    if i >= len(code):
        return None
    if code[i] == "{":
        end = _balanced(code, i, "{", "}", _MAX_BRANCH_CHARS)
        if end is None:
            return None
        return _statements(code[i + 1 : end])
    # A single statement: up to `;` or a newline at depth 0.
    return _statements(code[i : i + _MAX_BRANCH_CHARS])[:1]


def session_gate(handler: str) -> str | None:
    """The gate line (masked text) if ``handler`` rejects a request whose
    session lookup comes back empty; else None."""
    code = mask(handler[:_MAX_SPAN_CHARS])
    tracked: dict[str, int] = {}  # name → offset where it became a session value
    for decl in _DECLARATION.finditer(code):
        rest = code[decl.end() : decl.end() + 400].split(";", 1)[0]
        raw_rest = handler[decl.end() : decl.end() + 400].split(";", 1)[0]
        if not (_SESSION_CALL.search(rest) or _CREDENTIAL_ARG.search(raw_rest)):
            continue
        names = [decl.group("name")] if decl.group("name") else _IDENT.findall(decl.group("names") or "")
        for name in names:
            if name not in tracked:
                tracked[name] = decl.end()
    if not tracked:
        return None
    for count, match in enumerate(_IF.finditer(code)):
        if count >= _MAX_IFS:
            break
        open_paren = match.end() - 1
        close = _balanced(code, open_paren, "(", ")", _MAX_CONDITION_CHARS)
        if close is None:
            continue
        condition = _GATE_CONDITION.match(code[open_paren + 1 : close])
        if condition is None:
            continue
        name = condition.group("name")
        if name not in tracked or tracked[name] > match.start():
            continue
        # A reassignment between the lookup and the gate stops tracking it.
        between = code[tracked[name] : match.start()]
        if re.search(rf"(?<![\w$.]){re.escape(name)}\s*=(?![=>])", between):
            continue
        branch = _then_branch(code, close + 1)
        if branch is not None and _rejects(branch):
            line_start = code.rfind("\n", 0, match.start()) + 1
            line_end = code.find("\n", match.start())
            return handler[line_start : line_end if line_end >= 0 else len(handler)].strip()
    return None


__all__ = ["mask", "session_gate"]
