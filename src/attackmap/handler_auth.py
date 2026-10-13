"""Handler-level session checks in JS/TS route handlers (#348).

`unauth-state-change` resolves auth on a route's middleware chain. Many
JS/TS handlers authenticate in their own body instead::

    const session = await getSession(c);
    if (!session.user) {
      throw new AppError(AppErrorCode.UNAUTHORIZED);
    }

This module recognises that shape structurally, and nothing looser. When in
doubt, the finding stays.

1. Strings and comments are masked before any test.
2. The handler body is the brace block of the route's handler function (the
   first `{` after `=>` or a parameter list), clamped to its closing brace.
3. A *session lookup* is a declaration whose initializer resolves the
   caller's identity: `getSession(`, `getServerSession(`,
   `getServerAuthSession(`, a zero-argument `auth()`, `currentUser(` /
   `getCurrentUser(`, `supabase.auth.getUser(`, or `req.session.user` /
   `req.session.userId` / `req.user` (passport). A later reassignment
   (`=`, `||=`, `??=`, destructuring) of a tracked name stops tracking it.
4. A *gate* is an `if` whose condition, parsed with balanced parentheses, is
   exactly `!name[.member…]` for a tracked name, or `!req.user`,
   `!req.session.user[Id]`, `!req.isAuthenticated()`.
5. The gate must be a top-level statement of the handler body: not inside a
   branch, loop, callback or nested function. A `try { … }` block is
   transparent only if its `catch` rethrows or returns (or there is none);
   an immediately-invoked function wrapping the whole body (`void (async
   () => { … })()`) is transparent. No state-changing call may come before it.
   A lookup with a fallback (`?? {…}`, `|| {…}`, a ternary) doesn't count,
   and assigning `req.user` / `req.session…` before a direct check
   disqualifies it.
6. Its then-branch (a braced block or a single statement) must start with a
   `return` (not `return next()` / `return void next()`), a `throw`, or a
   bare `redirect(...)` (Next/Remix redirects throw). An Express-style
   `next(err)` or `res.status(401|403)…` counts only when the next statement
   is a `return`.
"""

from __future__ import annotations

import re

_SESSION_CALL = re.compile(
    r"(?<![\w$.])(?:getSession|getServerSession|getServerAuthSession|currentUser|getCurrentUser)\s*+\("
    r"|(?<![\w$.])auth\s*+\(\s*+\)"
    r"|\.\s*auth\s*+\.\s*getUser\s*+\("
    r"|(?<![\w$.])(?:req|request)\s*+\.\s*+(?:user\b|session\s*+\.\s*+(?:user|userId)\b)"
)
_DECLARATION = re.compile(
    r"(?<![\w$])(?:const|let|var)\s++(?:\{(?P<names>[^{}]{1,300})\}|(?P<name>[A-Za-z_$][\w$]{0,80}+))"
    r"\s*+(?::[^=;\n]{1,120})?=(?![=>])"
)
_IDENT = re.compile(r"[A-Za-z_$][\w$]{0,80}")
_IF = re.compile(r"(?<![\w$.])if\s*+\(")
_GATE_CONDITION = re.compile(
    r"\A\s*!\s*(?:(?P<direct>(?:req|request)\s*\.\s*(?:user|session\s*\.\s*(?:user|userId)|isAuthenticated\s*\(\s*\)))"
    r"|(?P<name>[A-Za-z_$][\w$]{0,80})(?:\s*\??\.\s*[A-Za-z_$][\w$]{0,80})*)\s*\Z"
)
_REJECTING_FIRST = re.compile(r"\A\s*(?:throw\b|redirect\s*\()")
_RETURN = re.compile(r"\A\s*return\b(?P<rest>.*)\Z", re.DOTALL)
_BARE_NEXT = re.compile(r"\A\s*(?:void\s+)?next\s*\(\s*\)\s*\Z")
_NEXT_WITH_ERROR = re.compile(r"\A\s*next\s*\(\s*\S")
_STATUS_REJECT = re.compile(r"\A\s*(?:res|response|reply|ctx)\s*\.\s*(?:status|code)\s*\(\s*(?:401|403)\s*\)")
# The handler function's body: the first `{` after `=>` or a parameter list.
_BODY_OPEN = re.compile(r"(?:=>|\))\s*+(?::[^{};=\n]{1,120})?\s*+\{")
# A state-changing call: persistence or an outbound write.
_MUTATION = re.compile(
    r"\.\s*(?:create|createMany|update|updateMany|upsert|delete|deleteMany|insert|insertOne|insertMany"
    r"|save|remove|destroy|execute|exec|query|write|enqueue|publish)\w{0,40}\s*\("
)
_TRY_OPEN = re.compile(r"\btry\s*\Z")
# A fallback in a session initializer: `??`, `||`, or a ternary (not `?.`).
_FALLBACK = re.compile(r"\?\?|\|\||\?(?![.?])")
# Assigning the request identity directly: `req.user = …`, `req.session.user ||= …`.
_DIRECT_ASSIGN = re.compile(
    r"(?<![\w$.])(?:req|request)\s*\.\s*(?:user|session)(?:\s*\.\s*(?:user|userId))?\s*(?:\|\||&&|\?\?)?=(?![=>])"
)
_IIFE_HEAD = re.compile(r"\A\s*(?:async\s+)?(?:\([^()]{0,200}\)|[A-Za-z_$][\w$]{0,80})\s*=>\s*\{|\A\s*(?:async\s+)?function\b")
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


def _matches(code: str) -> dict[int, int]:
    """Opening bracket offset → its closing offset (unbalanced ones omitted)."""
    pairs: dict[int, int] = {}
    stack: list[int] = []
    closer = {")": "(", "]": "[", "}": "{"}
    for i, ch in enumerate(code):
        if ch in "([{":
            stack.append(i)
        elif ch in closer:
            while stack and code[stack[-1]] != closer[ch]:
                stack.pop()
            if stack:
                pairs[stack.pop()] = i
    return pairs


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


def _then_branch(code: str, after_paren: int, pairs: dict[int, int]) -> list[str] | None:
    i = after_paren
    while i < len(code) and code[i] in " \t\r\n":
        i += 1
    if i >= len(code):
        return None
    if code[i] == "{":
        end = pairs.get(i)
        if end is None or end - i > _MAX_BRANCH_CHARS:
            return None
        return _statements(code[i + 1 : end])
    return _statements(code[i : i + _MAX_BRANCH_CHARS])[:1]


def handler_body(text: str) -> tuple[int, int] | None:
    """``(open, close)`` offsets of the handler function's body braces in
    ``text`` (which starts at the route registration or function header)."""
    code = mask(text[:_MAX_SPAN_CHARS])
    match = _BODY_OPEN.search(code)
    if match is None:
        return None
    close = _matches(code).get(match.end() - 1)
    return (match.end() - 1, close) if close is not None else None


def _transparent(code: str, open_at: int, pairs: dict[int, int]) -> bool:
    """A bracket an `if` may sit inside and still be top-level: a `try` block,
    or the body (and wrapping parenthesis) of an immediately-invoked function."""
    ch = code[open_at]
    if ch == "{":
        before = code[max(0, open_at - 40) : open_at]
        if _TRY_OPEN.search(before.rstrip()):
            return _catch_rejects(code, open_at, pairs)
        close = pairs.get(open_at)
        if close is not None and re.match(r"\s*\)\s*\(", code[close + 1 : close + 20]) and re.search(r"=>\s*\Z", before):
            return True
        return False
    if ch == "(":
        close = pairs.get(open_at)
        return (
            close is not None
            and _IIFE_HEAD.match(code[open_at + 1 : open_at + 300]) is not None
            and re.match(r"\s*\(", code[close + 1 : close + 20]) is not None
        )
    return False


_CATCH_HEAD = re.compile(r"\A\s*catch\s*(?:\([^()]{0,200}\))?\s*\{")
_FINALLY_HEAD = re.compile(r"\A\s*finally\s*\{")


def _catch_rejects(code: str, try_open: int, pairs: dict[int, int]) -> bool:
    """A `try` is see-through only if its `catch` rethrows or returns at its
    top level (so a `throw` in the try still rejects), or there is no catch."""
    try_close = pairs.get(try_open)
    if try_close is None:
        return False
    after = code[try_close + 1 : try_close + 260]
    head = _CATCH_HEAD.match(after)
    if head is None:
        return _FINALLY_HEAD.match(after) is not None  # try/finally doesn't swallow
    catch_open = try_close + head.end()
    catch_close = pairs.get(catch_open)
    if catch_close is None:
        return False
    for stmt in _statements(code[catch_open + 1 : catch_close]):
        if re.match(r"\A\s*throw\b", stmt):
            return True
        returned = _RETURN.match(stmt)
        if returned and not _BARE_NEXT.match(returned.group("rest")):
            return True
    return False


def _top_level(code: str, body_open: int, pos: int, pairs: dict[int, int]) -> bool:
    """``pos`` sits directly in the handler body, only inside transparent brackets."""
    for open_at, close in pairs.items():
        if body_open < open_at < pos < close and not _transparent(code, open_at, pairs):
            return False
    return True


def _reassigned(name: str, text: str) -> bool:
    plain = re.search(rf"(?<![\w$.]){re.escape(name)}\s*(?:\|\||&&|\?\?)?=(?![=>])", text)
    destructured = re.search(rf"(?<![\w$.]){re.escape(name)}(?![\w$])[^;=\n]{{0,80}}?[}}\]]\s*=(?![=>])", text)
    return bool(plain or destructured)


_CONTINUATION = ("??", "||", "&&", "?", ":", ".", "+")


def _initializer(window: str) -> str:
    """The declaration's initializer: its first line plus any lines that
    continue it (a formatter wraps `getSession(req)\\n  ?? fallback`)."""
    lines = window.split("\n")
    out = [lines[0]]
    for line in lines[1:]:
        if not line.lstrip().startswith(_CONTINUATION):
            break
        out.append(line)
    return "\n".join(out)


def session_gate(text: str) -> str | None:
    """The gate line if the handler in ``text`` rejects a request whose
    session lookup comes back empty; else None."""
    text = text[:_MAX_SPAN_CHARS]
    code = mask(text)
    body = handler_body(text)
    if body is None:
        return None
    body_open, body_close = body
    pairs = _matches(code)
    tracked: dict[str, int] = {}
    for decl in _DECLARATION.finditer(code, body_open, body_close):
        window = code[decl.end() : min(body_close, decl.end() + 400)].split(";", 1)[0]
        rest = window.split("\n", 1)[0]
        if not _SESSION_CALL.search(rest) or not _top_level(code, body_open, decl.start(), pairs):
            continue
        if _FALLBACK.search(_initializer(window)):
            continue  # `getSession(c) ?? { user: guest }`: never empty, so the gate proves nothing
        if decl.group("names") and "=" in decl.group("names"):
            continue  # `const { user = guest } = await getSession(req)`: a default, never empty
        names = [decl.group("name")] if decl.group("name") else _IDENT.findall(decl.group("names") or "")
        for name in names:
            tracked.setdefault(name, decl.end())
    for count, match in enumerate(_IF.finditer(code, body_open, body_close)):
        if count >= _MAX_IFS:
            break
        open_paren = match.end() - 1
        close = pairs.get(open_paren)
        if close is None or close - open_paren > _MAX_CONDITION_CHARS:
            continue
        condition = _GATE_CONDITION.match(code[open_paren + 1 : close])
        if condition is None:
            continue
        name = condition.group("name")
        if name is not None:
            if name not in tracked or tracked[name] > match.start():
                continue
            if _reassigned(name, code[tracked[name] : match.start()]):
                continue
        elif _DIRECT_ASSIGN.search(code, body_open, match.start()):
            continue  # `req.user = req.user || { id: 0 }` before the check
        if not _top_level(code, body_open, match.start(), pairs):
            continue
        # No state change may happen before the check.
        if _MUTATION.search(code, body_open, match.start()):
            continue
        branch = _then_branch(code, close + 1, pairs)
        if branch is not None and _rejects(branch):
            line_start = code.rfind("\n", 0, match.start()) + 1
            line_end = code.find("\n", match.start())
            return text[line_start : line_end if line_end >= 0 else len(text)].strip()
    return None


__all__ = ["handler_body", "mask", "session_gate"]
