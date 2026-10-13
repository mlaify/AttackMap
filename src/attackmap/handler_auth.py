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
   `req.session.userId` / `req.user` (passport). The initializer must be the
   lookup itself (after an optional `await`), not an expression mentioning
   one (`!req.user`, `findFirst({ authorId: req.user.id })`); a destructured
   alias binds its alias (`{ user: me }` tracks `me`). A later reassignment
   (`=`, `||=`, `??=`, destructuring) of a tracked name stops tracking it.
4. A *gate* is an `if` whose condition, parsed with balanced parentheses, is
   exactly `!name[.member…]` for a tracked name, or `!req.user`,
   `!req.session.user[Id]`, `!req.isAuthenticated()`. A destructured `data`
   or `error` is not tracked (supabase v2 always returns a `data` object),
   and a whole `auth()` / `.auth.getUser()` / Remix or h3 `getSession(…)`
   result needs a member test (`data` alone doesn't count). A
   member test must name identity (`user`, `id`, `email`, …), not a property
   of it (`!session.user.isGuest`).
5. The gate must be a top-level statement of the handler body: not inside a
   branch, loop, callback or nested function, not an `else if`, and not the
   body of a braceless `if` / loop. A `try { … }` block is transparent only
   if its `catch` rethrows or returns (or there is none); an
   immediately-invoked function that is the body's last statement (`void
   (async () => { … })()`) is transparent. Nothing that may act for an
   anonymous caller may come before it: a state-changing call (a persistence
   method, a plain `createX(` / `deleteX(` call, `$executeRaw`), an awaited
   call other than the lookup or a request read (`req.json()`, `parse…`), or
   a `return` that hands off rather than responds. A lookup with a fallback (`?? {…}`, `|| {…}`, a
   ternary, `.catch(…)`) doesn't count, a later write to the name or one of
   its members (`session.user ||= guest`) disqualifies it, and so does
   assigning `req.user` / `req.session…` before a direct check.
6. Its then-branch (a braced block or a single statement) must start with a
   `return` of nothing, a literal, a response, a redirect or an error (not a
   hand-off like `return createGuestOrder(req, res)`, and not `return next()`, `return next(null)`, `return await
   next()` or `return void next()`) or a `throw`. A bare `redirect(...)`
   doesn't count: it throws in Next, but Remix and SvelteKit 1 return it. An
   Express-style `next(err)` or `res.status(401|403)…` counts only when the
   next statement is a `return`.
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
    r"|(?P<name>[A-Za-z_$][\w$]{0,80})(?P<members>(?:\s*\??\.\s*[A-Za-z_$][\w$]{0,80})*))\s*\Z"
)
# Members a gate may test: identity, not a property of it (`!session.user.isGuest`).
_IDENTITY_MEMBERS = frozenset(
    {"user", "id", "userid", "uid", "sub", "email", "account", "accountid", "session", "sessionid", "identity", "profile"}
)
# `data` is an envelope (supabase `{ data: { user } }`): fine on the way to an
# identity member, never as the member tested.
_ENVELOPE_MEMBERS = frozenset({"data"})
_MEMBER_NAME = re.compile(r"[A-Za-z_$][\w$]{0,80}")
# Lookups that never come back falsy as a whole: supabase's `{ data, error }`,
# Clerk's `auth()` object. A bare `!x` on them never fires; a member test does.
# Remix (`getSession(request.headers.get("Cookie"))`) and h3 (`getSession(event, …)`)
# session stores always return a session object too.
_ALWAYS_OBJECT = re.compile(
    r"(?<![\w$.])auth\s*+\(\s*+\)|\.\s*auth\s*+\.\s*getUser\s*+\("
    r"|(?<![\w$.])getSession\s*+\(\s*+(?:event\b|[^()\n]{0,200}(?:\([^()\n]{0,200}\))?[^()\n]{0,200}(?i:cookie|headers))"
)
# The initializer is the lookup itself (`await getSession(req)`,
# `supabase.auth.getUser()`), not an expression that mentions one.
# Only a member lookup (`.auth.getUser(`) may have a receiver before it.
_LOOKUP_PREFIX = re.compile(r"\s*+(?:await\s++)?")
_RECEIVER_PREFIX = re.compile(r"\s*+(?:await\s++)?[A-Za-z_$][\w$]{0,80}+(?:\s*+\??\.\s*+[A-Za-z_$][\w$]{0,80}+){0,6}+\s*+")
_REJECTING_FIRST = re.compile(r"\A\s*throw\b")
_RETURN = re.compile(r"\A\s*return\b(?P<rest>.*)\Z", re.DOTALL)
# What a rejecting `return` may return: nothing, a literal, a response, a
# redirect or an error. `return createGuestOrder(req, res)` doesn't count.
_RETURN_VALUE = re.compile(
    r"\A\s*+(?:\Z|[;{\['\"`\d]|null\b|false\b|undefined\b|new\s++\w{0,40}(?:Response|Error|Exception)\b"
    r"|(?:void\s++)?(?:res|response|reply|ctx|c|context|h|event)\s*+\."
    r"|(?:Next)?Response\s*+\.|NextResponse\b"
    r"|(?:await\s++)?(?i:(?:send|respond(?:with)?|make|create|throw|to)?_?"
    r"(?:unauthori[sz]ed|forbidden|error|json|redirect|status|login|sign_?in|abort|den(?:y|ied)|reject(?:ed)?"
    r"|fail(?:ure|ed)?|not_?allowed)(?:_?(?:response|error|page))?)\s*+\("
    r"|next\s*+\(\s*+(?!['\"`])[^\s)])"
)
# `next()` continues the chain, as do `next(null)` / `next(undefined)`.
_BARE_NEXT = re.compile(r"\A\s*(?:(?:void|await)\s+)?next\s*\(\s*(?:null|undefined)?\s*\)\s*\Z")
# `next('route')` / `next('router')` skip to the next route: a hand-off, not a
# rejection. Strings are masked by then, so no string argument counts.
_NEXT_WITH_ERROR = re.compile(r"\A\s*next\s*\(\s*(?!(?:null|undefined)\s*\)|['\"`])\S")
_STATUS_REJECT = re.compile(r"\A\s*(?:res|response|reply|ctx)\s*\.\s*(?:status|code)\s*\(\s*(?:401|403)\s*\)")
# The handler function's body: the first `{` after `=>` or a parameter list.
_BODY_OPEN = re.compile(r"(?:=>|\))\s*+(?::[^{};=\n]{1,120})?\s*+\{")
# A state-changing call: persistence or an outbound write.
_MUTATION = re.compile(
    r"\$(?:execute|query)Raw"
    r"|(?:\.\s*|(?<![\w$.]))(?:create|createMany|update|updateMany|upsert|delete|deleteMany|insert|insertOne|insertMany"
    r"|save|remove|destroy|execute|exec|query|write|enqueue|publish|add|set|del|unlink|rm|post|put|patch"
    r"|send|push|append|incr|decr|hset|lpush|rpush|sadd|zadd|expire|rename|copy|mkdir|fetch|charge|transfer)\w{0,40}\s*\("
)
_TRY_OPEN = re.compile(r"\btry\s*\Z")
# A fallback in a session initializer: `??`, `||`, a ternary (not `?.`), or
# a `.catch(...)` that resolves to something.
_FALLBACK = re.compile(r"\?\?|\|\||\?(?![.?])|\.\s*catch\s*\(|\.\s*then\s*\(")
# Assigning the request identity directly: `req.user = …`, `req.session.user ||= …`.
_DIRECT_ASSIGN = re.compile(
    r"(?<![\w$.])(?:req|request)\s*\.\s*(?:user|session)(?:\s*\.\s*(?:user|userId))?\s*(?:\|\||&&|\?\?)?=(?![=>])"
)
_ENVELOPE_NAMES = frozenset({"data", "error"})


def _bindings(pattern: str) -> list[str]:
    """Names bound by a flat object pattern: `{ user: me, session }` binds
    `me` and `session`. Keys of the response envelope (`data`, `error`, which
    supabase always returns) and `...rest` objects are not tracked."""
    names: list[str] = []
    for element in pattern.split(","):
        key, _, alias = element.partition(":")
        key = key.strip()
        if not key or key.startswith("...") or key in _ENVELOPE_NAMES:
            continue
        bound = (alias or key).strip()
        if _IDENT.fullmatch(bound):
            names.append(bound)
    return names
_IIFE_HEAD = re.compile(r"\A\s*(?:async\s+)?(?:\([^()]{0,200}\)|[A-Za-z_$][\w$]{0,80})\s*=>\s*\{|\A\s*(?:async\s+)?function\b")
_MAX_SPAN_CHARS = 20_000
_MAX_IFS = 200
_MAX_CONDITION_CHARS = 400
_MAX_BRANCH_CHARS = 4_000


def mask(text: str) -> str:
    """``text`` with string literals and comments replaced by spaces (same length).

    Template-literal interpolations (`${…}`) stay visible as code. A regex
    literal is skipped unmasked, so a quote or backtick inside it can't start
    a string that hides the code after it."""
    out = list(text)
    n = len(text)

    def blank(a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    stack: list[int] = []  # brace depth inside each open `${`
    prev = ""  # last code character that isn't whitespace
    i = 0
    while i < n:
        c = text[i]
        if c == "`" or (c == "}" and stack and stack[-1] == 0):
            if c == "}":
                stack.pop()
            j = i + 1
            while j < n and text[j] != "`" and not text.startswith("${", j):
                j += 2 if text[j] == "\\" else 1
            blank(i + 1, j)
            if text.startswith("${", j):
                stack.append(0)
                i, prev = j + 2, "{"
            else:
                i, prev = j + 1, "`"
            continue
        if stack and c in "{}":
            stack[-1] += 1 if c == "{" else -1
        if c in "'\"":
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            blank(i + 1, j)
            i, prev = j + 1, c
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            blank(i, j)
            i = j
            continue
        if c == "/" and prev in _REGEX_PREV:
            j = i + 1
            in_class = False
            while j < n and text[j] != "\n":
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == "[":
                    in_class = True
                elif text[j] == "]":
                    in_class = False
                elif text[j] == "/" and not in_class:
                    break
                j += 1
            i, prev = j + 1, "/"
            continue
        if not c.isspace():
            prev = c
        i += 1
    return "".join(out)


# A `/` after one of these (or at the start) begins a regex literal, not a division.
_REGEX_PREV = frozenset(["", *"(,=:[!&|?{};+-*%<>~^"])


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
        rest = returned.group("rest")
        return not _BARE_NEXT.match(rest) and _RETURN_VALUE.match(rest) is not None
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


def _transparent(code: str, open_at: int, pairs: dict[int, int], body_close: int) -> bool:
    """A bracket an `if` may sit inside and still be top-level: a `try` block,
    or the body (and wrapping parenthesis) of an immediately-invoked function
    that is the handler's last statement (a `return` in it ends the handler)."""
    ch = code[open_at]
    if ch == "{":
        before = code[max(0, open_at - 40) : open_at]
        if _TRY_OPEN.search(before.rstrip()):
            return _catch_rejects(code, open_at, pairs)
        close = pairs.get(open_at)
        if close is None or not re.search(r"=>\s*\Z", before):
            return False
        call = _IIFE_CALL.match(code, close + 1, min(body_close, close + 20))
        return call is not None and _ends_body(code, call.end() - 1, pairs, body_close)
    if ch == "(":
        close = pairs.get(open_at)
        if close is None or _IIFE_HEAD.match(code[open_at + 1 : open_at + 300]) is None:
            return False
        call = _CALL_OPEN.match(code, close + 1, min(body_close, close + 20))
        return call is not None and _ends_body(code, call.end() - 1, pairs, body_close)
    return False


# Anchored after a non-space so a search() over hostile whitespace stays linear.
_IIFE_CALL = re.compile(r"(?<!\s)\s*+\)\s*+\(")
_CALL_OPEN = re.compile(r"(?<!\s)\s*+\(")
_BODY_TAIL = re.compile(r"[\s;]*")


def _ends_body(code: str, call_open: int, pairs: dict[int, int], body_close: int) -> bool:
    """The call whose `(` is at ``call_open`` is the last statement of the body."""
    call_close = pairs.get(call_open)
    if call_close is None or call_close >= body_close:
        return False
    return _BODY_TAIL.match(code, call_close + 1, body_close).end() == body_close


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
        if returned and not _BARE_NEXT.match(returned.group("rest")) and _RETURN_VALUE.match(returned.group("rest")):
            return True
    return False


def _top_level(code: str, body_open: int, body_close: int, pos: int, pairs: dict[int, int]) -> bool:
    """``pos`` sits directly in the handler body, only inside transparent brackets."""
    for open_at, close in pairs.items():
        if body_open < open_at < pos < close and not _transparent(code, open_at, pairs, body_close):
            return False
    return True


_CONTROL_HEAD = re.compile(r"(?<![\w$.])(?:if|for|while|with|switch|catch)\s*\Z")
_DANGLING_KEYWORD = re.compile(r"(?<![\w$.])(?:else|do)\s*\Z")


def _starts_statement(code: str, pos: int, pairs: dict[int, int]) -> bool:
    """``pos`` starts a statement of its block, not the body of a braceless
    `if` / `for` / `while`, nor an `else if`."""
    before = code[max(0, pos - 400) : pos]
    stripped = before.rstrip()
    if not stripped or stripped[-1] in "{};":
        return True
    if _DANGLING_KEYWORD.search(stripped):
        return False
    if stripped[-1] == ")":
        close = pos - (len(before) - len(stripped)) - 1
        opener = next((o for o, c in pairs.items() if c == close), None)
        if opener is None or _CONTROL_HEAD.search(code[max(0, opener - 40) : opener]):
            return False
    # A statement ended without `;` (ASI) only at a line break.
    return "\n" in before[len(stripped) :]


def _reassigned(name: str, text: str) -> bool:
    # `session = …`, `session.user ||= guest`, `session["user"] ??= …`
    plain = re.search(
        rf"(?<![\w$.]){re.escape(name)}(?:\s*+(?:\??\.\s*+[A-Za-z_$][\w$]{{0,80}}+|\[[^\[\]\n]{{0,80}}\]))*+"
        rf"\s*+(?:\|\||&&|\?\?)?=(?![=>])",
        text,
    )
    destructured = re.search(rf"(?<![\w$.]){re.escape(name)}(?![\w$])[^;=\n]{{0,80}}?[}}\]]\s*=(?![=>])", text)
    assigned = re.search(rf"\bObject\s*\.\s*assign\s*\(\s*{re.escape(name)}(?![\w$])", text)
    return bool(plain or destructured or assigned)


# Awaits that only read the request: body parsing and validation, Next's
# `cookies()` / `headers()` / `params`.
_READ_AWAIT = re.compile(
    r"(?:[A-Za-z_$][\w$]{0,80}+\s*+\.\s*+){0,6}+"
    r"(?:(?:json|text|formData|arrayBuffer|blob|parse\w{0,20}|safeParse\w{0,20}|validate\w{0,20})\s*+\("
    r"|(?:cookies|headers)\s*+\(\s*+\)|(?:params|searchParams)\b)"
)
_AWAIT = re.compile(r"(?<![\w$.])await\s++")
_EARLY_RETURN = re.compile(r"(?<![\w$.])return\b")


def _unsafe_before(code: str, body_open: int, gate: int) -> bool:
    """Anything before the gate that may act for an anonymous caller: a write
    (`_MUTATION`), any awaited call other than the session lookup or a request
    read (`await processOrder(req.body)`), or an earlier `return` that hands
    off (`if (req.query.guest) return handleGuest(req, res)`)."""
    if _MUTATION.search(code, body_open, gate):
        return True
    for match in _AWAIT.finditer(code, body_open, gate):
        after = code[match.end() : min(gate, match.end() + 300)]
        lookup = _SESSION_CALL.search(after)
        if lookup is not None:
            prefix = _RECEIVER_PREFIX if after[lookup.start()] == "." else _LOOKUP_PREFIX
            if prefix.fullmatch(after, 0, lookup.start()) is None:
                lookup = None
        if lookup is None and _READ_AWAIT.match(after) is None:
            return True
    for match in _EARLY_RETURN.finditer(code, body_open, gate):
        stmt = _statements(code[match.end() : min(gate, match.end() + 400)])
        if not _RETURN_VALUE.match(stmt[0] if stmt else ""):
            return True
    return False


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
    needs_member: set[str] = set()
    for decl in _DECLARATION.finditer(code, body_open, body_close):
        window = code[decl.end() : min(body_close, decl.end() + 400)].split(";", 1)[0]
        rest = window.split("\n", 1)[0]
        lookup = _SESSION_CALL.search(rest)
        if lookup is None or not _top_level(code, body_open, body_close, decl.start(), pairs):
            continue
        prefix = _RECEIVER_PREFIX if rest[lookup.start()] == "." else _LOOKUP_PREFIX
        if prefix.fullmatch(rest, 0, lookup.start()) is None:
            continue  # `!req.user`, `typeof req.user`, `findFirst({ authorId: req.user.id })`
        if _FALLBACK.search(_initializer(window)):
            continue  # `getSession(c) ?? { user: guest }`: never empty, so the gate proves nothing
        if decl.group("names") and "=" in decl.group("names"):
            continue  # `const { user = guest } = await getSession(req)`: a default, never empty
        if decl.group("name"):
            names = [decl.group("name")]
            if _ALWAYS_OBJECT.search(rest):
                needs_member.add(decl.group("name"))
        else:
            names = _bindings(decl.group("names") or "")
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
            members = [m.lower() for m in _MEMBER_NAME.findall(condition.group("members") or "")]
            if any(m not in _IDENTITY_MEMBERS | _ENVELOPE_MEMBERS for m in members) or (
                members and members[-1] in _ENVELOPE_MEMBERS
            ):
                continue  # `!session.user.isGuest`: a property of the identity, not its absence
            if name in needs_member and not members:
                continue  # `!res` on supabase's `{ data, error }`: never falsy
            if _reassigned(name, code[tracked[name] : match.start()]):
                continue
        elif _DIRECT_ASSIGN.search(code, body_open, match.start()):
            continue  # `req.user = req.user || { id: 0 }` before the check
        if not _top_level(code, body_open, body_close, match.start(), pairs):
            continue
        if not _starts_statement(code, match.start(), pairs):
            continue  # `else if`, or the body of a braceless `if` / loop
        # Nothing may act for an anonymous caller before the check.
        if _unsafe_before(code, body_open, match.start()):
            continue
        branch = _then_branch(code, close + 1, pairs)
        if branch is not None and _rejects(branch):
            line_start = code.rfind("\n", 0, match.start()) + 1
            line_end = code.find("\n", match.start())
            return text[line_start : line_end if line_end >= 0 else len(text)].strip()
    return None


__all__ = ["handler_body", "mask", "session_gate"]
