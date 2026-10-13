"""Handler-level session checks for `unauth-state-change` (#348).

Only a check that gates a rejection counts: the condition must be exactly a
negated session value, and the then-branch must start with return / throw
(or `next(err)` / `res.status(401)` followed by `return`).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from attackmap.handler_auth import mask, session_gate
from attackmap.scanner import scan_repo
from attackmap.threat_model import generate_findings

GATED = [
    # documenso (Hono): throw inside the handler
    "const session = await getSession(c);\nif (!session.user) {\n  throw new AppError(AppErrorCode.UNAUTHORIZED, { message: 'x' });\n}",
    # juice-shop: next(err) then return
    "const loggedInUser = security.authenticatedUsers.get(req.cookies.token)\nif (!loggedInUser) {\n  next(new Error('Blocked'))\n  return\n}",
    "const session = await getServerSession(req, res, authOptions);\nif (!session) return res.status(401).json({ error: 'no' });",
    "const { user } = await supabase.auth.getUser();\nif (!user) {\n  return new Response('Unauthorized', { status: 401 });\n}",
    "const user = await currentUser();\nif (!user) return redirect('/login');",
    "const user = await currentUser();\nif (!user) throw redirect('/login');",
    # no semicolons (ASI)
    "const session = await getSession(req)\nif (!session) return res.status(401).end()",
    "const session = await auth();\nif (!session?.user?.id) {\n  res.status(401).send('no');\n  return;\n}",
    "const s = await getSession(req);\nif (!s) { throw new UnauthorizedException(); }",
    # destructuring aliases, members of an always-object lookup
    "const { user: me } = await getSession(req);\nif (!me) return res.status(401).end();",
    "const r = await supabase.auth.getUser();\nif (!r.data.user) return res.status(401).end();",
    # rejecting return values
    "const session = await getSession(req);\nif (!session) return sendUnauthorized(res);",
    "const session = await getSession(req);\nif (!session) return c.json({ error: 'no' }, 401);",
    "const session = await getSession(req);\nif (!session) return;",
]

NOT_GATED = [
    # reads a session but never rejects
    "const session = await getSession(c);\nawait save(session?.user?.id, body);",
    # the gate only logs
    "const session = await getSession(c);\nif (!session) console.warn('Unauthorized');",
    "const session = await getSession(c);\nif (!session) {\n  log('Unauthorized');\n}",
    # Express: status without return keeps going
    "const session = await getSession(req);\nif (!session) {\n  res.status(401).send('no');\n}\nawait save(req.body);",
    # `return next()` continues the chain
    "const session = await getSession(req);\nif (!session) return next();",
    # positive condition, compound condition, unrelated variable
    "const session = await getSession(req);\nif (session) return res.status(401).end();",
    "const session = await getSession(req);\nif (!session && debug) return res.status(401).end();",
    "const session = await getSession(req);\nconst body = req.body;\nif (!body) return res.status(400).end();",
    # not a session lookup: a bare mention of `user`
    "const user = await db.user.findFirst({ where: { id } });\nif (!user) return res.status(404).end();",
    # reassigned before the gate
    "let session = await getSession(req);\nsession = { user: 'anon' };\nif (!session) return res.status(401).end();",
    # in a string or comment only
    "// const session = await getSession(req); if (!session) return res.status(401).end();\nawait save(req.body);",
    "const s = 'const session = await getSession(req); if (!session) return 1';\nawait save(req.body);",
    # the gate is in an else-branch-free unrelated position: else returns
    "const session = await getSession(req);\nif (!session) {\n  console.log('anon');\n} else {\n  return res.status(403).end();\n}",
]


def _wrap(body: str) -> str:
    return "app.post('/api/x', async (req, res, next) => {\n" + body + "\n  await Order.create(req.body);\n});\n"


# juice-shop's `security.authenticatedUsers.get(req.cookies.token)` is an
# app-specific lookup, not a recognised identity call (review of #379).
GATED = [g for g in GATED if "authenticatedUsers" not in g]
NOT_GATED = NOT_GATED + [
    "const loggedInUser = security.authenticatedUsers.get(req.cookies.token)\nif (!loggedInUser) {\n  next(new Error('Blocked'))\n  return\n}",
    # a generic cookie or session value is not the caller's identity
    "const token = req.cookies.token;\nif (!token) return res.status(401).end();",
    "const cart = req.session.cart;\nif (!cart) return res.status(401).end();",
    # `auth(opts)` configures; only a zero-argument `auth()` resolves the session
    "const session = await auth(options);\nif (!session) return res.status(401).end();",
    # reassignment forms
    "let session = await getSession(req);\nsession ||= anon;\nif (!session) return res.status(401).end();",
    "let session = await getSession(req);\n({ session } = fallback);\nif (!session) return res.status(401).end();",
    # `return void next()` continues the chain
    "const session = await getSession(req);\nif (!session) return void next();",
    # the gate nested in a branch, a loop or a callback is not top-level
    "const session = await getSession(req);\nif (req.body.strict) {\n  if (!session) return res.status(401).end();\n}",
    "const session = await getSession(req);\nitems.forEach((item) => {\n  if (!session) return;\n});",
    "const session = await getSession(req);\nfunction inner() {\n  if (!session) return res.status(401).end();\n}",
    # a state change before the check
    "const session = await getSession(req);\nawait Audit.create({ at: Date.now() });\nif (!session) return res.status(401).end();",
]
NOT_GATED = NOT_GATED + [
    # a `try` whose catch swallows the rejection
    "try {\n  const session = await getSession(req);\n  if (!session) {\n    throw new Error('no');\n  }\n} catch (err) {\n  console.error(err);\n}",
    # a lookup with a fallback is never empty
    "const session = (await getSession(req)) ?? { user: guest };\nif (!session.user) return res.status(401).end();",
    "const user = (await currentUser()) || anonymousUser;\nif (!user) return res.status(401).end();",
    "const session = ok ? await getSession(req) : demo;\nif (!session) return res.status(401).end();",
    # direct form reassigned before the check
    "req.user = req.user || { id: 0 };\nif (!req.user) return res.status(401).end();",
    "req.session.userId ??= 'guest';\nif (!req.session.userId) return res.status(401).end();",
]
GATED = GATED + [
    # optional chaining is not a fallback
    "const session = await getSession(req);\nif (!session?.user) return res.status(401).end();",
    # try/finally doesn't swallow
    "try {\n  const session = await getSession(req);\n  if (!session) throw new Error('no');\n} finally {\n  done();\n}",
    # passport / express-session identity
    "if (!req.user) return res.status(401).end();",
    "if (!req.session.userId) {\n  return res.redirect('/login');\n}",
    "if (!req.isAuthenticated()) return res.sendStatus(401);",
    # inside a `try` block (documenso's shape)
    "try {\n  const session = await getSession(req);\n  if (!session.user) {\n    throw new AppError('UNAUTHORIZED');\n  }\n} catch (err) {\n  return res.status(500).end();\n}",
]
NOT_GATED = NOT_GATED + [
    # `next(null)` / `return await next()` continue the chain too
    "const session = await getSession(req);\nif (!session) {\n  next(null)\n  return\n}",
    "const session = await getSession(req);\nif (!session) return next(null);",
    "const session = await getSession(req);\nif (!session) return await next();",
    # a bare redirect() throws only in Next; Remix / SvelteKit 1 return it
    "const user = await currentUser();\nif (!user) redirect('/login');",
    # not a statement of the body: else-if, braceless loop or if
    "const session = await getSession(req);\nif (req.body.public) { log(1) } else if (!session) return res.status(401).end();",
    "const session = await getSession(req);\nfor (const i of req.body.items) if (!session) return res.status(401).end();",
    "const session = await getSession(req);\nif (req.body.x) if (!session) return res.status(401).end();",
    "const session = await getSession(req);\nwhile (false) if (!session) return 1;",
    # an IIFE that isn't the whole body: its return only leaves the IIFE
    "const session = await getSession(req);\n(() => { if (!session) return res.status(401).end(); })();",
    "void (async () => {\n  const session = await getSession(req);\n  if (!session) {\n    next(new Error('no'))\n    return\n  }\n})()",
    # a state change before the gate: plain call, raw tagged template
    "const session = await getSession(req);\nawait deleteUser(req.params.id);\nif (!session) return res.status(401).end();",
    "const session = await getSession(req);\nawait prisma.$executeRaw`DELETE FROM t`;\nif (!session) return res.status(401).end();",
    # member reassignment before the gate
    "const session = await getSession(req);\nsession.user ||= guest;\nif (!session.user) return res.status(401).end();",
    # supabase v2: `data` is always an object
    "const { data, error } = await supabase.auth.getUser();\nif (!data) return res.status(401).end();",
    # a `.catch` fallback
    "const session = await getSession(req).catch(() => guest);\nif (!session) return res.status(401).end();",
    # the initializer mentions a lookup but isn't one
    "const anonymous = !req.user;\nif (!anonymous) return res.redirect('/');",
    "const anonymous = typeof req.user === 'undefined';\nif (!anonymous) return res.redirect('/');",
    "const post = await db.post.findFirst({ where: { id, authorId: req.user?.id } });\nif (!post) return res.status(404).end();",
    # a destructuring key isn't a binding
    "const user = await db.user.findUnique({ where: { id } });\nconst { user: me } = await getSession(req);\nif (!user) return res.status(404).end();",
    "const { data: d } = await supabase.auth.getUser();\nif (!d) return res.status(401).end();",
    # lookups that are never falsy as a whole
    "const r = await supabase.auth.getUser();\nif (!r) return res.status(401).end();",
    "const a = auth();\nif (!a) return res.status(401).end();",
    # a return that hands off to a writing flow
    "const session = await getSession(req);\nif (!session) return createGuestOrder(req, res);",
    # writes the mutation list now covers
    "const session = await getSession(req);\nawait queue.add('job', req.body);\nif (!session) return res.status(401).end();",
    "const session = await getSession(req);\nawait axios.post(url, req.body);\nif (!session) return res.status(401).end();",
    "const session = await getSession(req);\nawait redis.del(req.params.key);\nif (!session) return res.status(401).end();",
    "const session = await getSession(req);\nawait fs.unlink(req.query.path);\nif (!session) return res.status(401).end();",
    "const session = await getSession(req);\nawait fetch(url, { method: 'POST' });\nif (!session) return res.status(401).end();",
    # a property of the identity, not its absence
    "const session = await getSession(req);\nif (!session.user.isGuest) return res.json({ ok: 1 });",
    # code after a regex literal holding a backtick, or inside an interpolation
    "const session = await getSession(req);\nconst re = /`/;\nawait db.user.deleteMany();\nconst s = /`/;\nif (!session) return res.status(401).end();",
    "const session = await getSession(req);\nlog(`${await db.user.deleteMany()}`);\nif (!session) return res.status(401).end();",
]


@pytest.mark.parametrize("handler", GATED)
def test_rejecting_session_checks_are_gates(handler: str) -> None:
    assert session_gate(_wrap(handler)) is not None


@pytest.mark.parametrize("handler", NOT_GATED)
def test_non_rejecting_or_unrelated_checks_are_not_gates(handler: str) -> None:
    assert session_gate(_wrap(handler)) is None


def test_mask_keeps_interpolations_and_skips_regex_literals() -> None:
    masked = mask("a(`x ${b(`y`)} z`); const r = /['`]/g; c()")
    assert "b(" in masked and "x" not in masked and "z" not in masked and masked.endswith("c()")
    assert len(masked) == len("a(`x ${b(`y`)} z`); const r = /['`]/g; c()")


def test_mask_keeps_shape() -> None:
    text = "a('x;y') // c\n/* d */ b"
    masked = mask(text)
    assert len(masked) == len(text) and "x" not in masked and "c" not in masked and masked.endswith("b")


def _unauth_findings(root: Path) -> list:
    scan = scan_repo(root)
    return [f for f in generate_findings(scan) if f.rule_id == "unauth-state-change"]


def test_express_handler_with_session_gate_is_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "const app = require('express')();\n"
        "app.post('/api/orders', async (req, res) => {\n"
        "  const session = await getSession(req);\n"
        "  if (!session) return res.status(401).json({ error: 'Unauthorized' });\n"
        "  await Order.create(req.body);\n"
        "  res.sendStatus(201);\n"
        "});\n"
    )
    assert _unauth_findings(tmp_path) == []


def test_express_handler_that_only_reads_the_session_is_flagged(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "const app = require('express')();\n"
        "app.post('/api/orders', async (req, res) => {\n"
        "  const session = await getSession(req);\n"
        "  await Order.create({ ...req.body, owner: session?.user?.id });\n"
        "  res.sendStatus(201);\n"
        "});\n"
    )
    assert len(_unauth_findings(tmp_path)) == 1


def test_gate_in_a_delegated_handler_counts(tmp_path: Path) -> None:
    (tmp_path / "handlers.js").write_text(
        "async function createOrder(req, res) {\n"
        "  const session = await getSession(req);\n"
        "  if (!session) {\n"
        "    return res.status(401).end();\n"
        "  }\n"
        "  await Order.create(req.body);\n"
        "}\n"
        "module.exports = { createOrder };\n"
    )
    (tmp_path / "app.js").write_text(
        "const app = require('express')();\n"
        "const { createOrder } = require('./handlers');\n"
        "app.post('/api/orders', createOrder);\n"
    )
    assert _unauth_findings(tmp_path) == []


def test_parser_never_raises_and_is_bounded() -> None:
    import random
    import time

    rng = random.Random(348)
    alphabet = list("(){}[];!?.=\n '\"`/*") + ["if", "if (", "return", "throw", "const ", "session", "getSession(", "await "]
    start = time.perf_counter()
    for _ in range(300):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 300)))
        session_gate(text)
        mask(text)
    for payload in ("if (" * 6000, "{" * 20000, "const session = getSession(x);\n" + "if (!session) {" * 3000, "'" * 20000, "/*" * 10000):
        session_gate(payload)
    assert time.perf_counter() - start < 10.0


def test_span_is_clamped_to_the_handler(tmp_path: Path) -> None:
    # A gate in the *next* route's handler must not count for this one.
    (tmp_path / "app.js").write_text(
        "const app = require('express')();\n"
        "app.post('/api/orders', async (req, res) => {\n"
        "  await Order.create(req.body);\n"
        "  res.sendStatus(201);\n"
        "});\n"
        "app.post('/api/admin-note', async (req, res) => {\n"
        "  const session = await getSession(req);\n"
        "  if (!session) return res.status(401).end();\n"
        "  await Note.create(req.body);\n"
        "});\n"
    )
    flagged = {loc.line for f in _unauth_findings(tmp_path) for loc in f.locations}
    assert 2 in flagged and 6 not in flagged


def test_only_the_routes_own_handler_reference_is_followed(tmp_path: Path) -> None:
    # The handler calls a helper that has a gate; that helper isn't the handler.
    (tmp_path / "helpers.js").write_text(
        "async function requireUser(req, res) {\n"
        "  const session = await getSession(req);\n"
        "  if (!session) return res.status(401).end();\n"
        "}\n"
        "module.exports = { requireUser };\n"
    )
    (tmp_path / "app.js").write_text(
        "const app = require('express')();\n"
        "const { requireUser } = require('./helpers');\n"
        "app.post('/api/orders', async (req, res) => {\n"
        "  requireUser(req, res);\n"
        "  await Order.create(req.body);\n"
        "});\n"
    )
    assert len(_unauth_findings(tmp_path)) == 1


def test_wrapped_fallback_and_destructuring_default_are_not_gates() -> None:
    """Review round 3: a fallback on the next line (formatter wrapping) or a
    destructuring default means the lookup is never empty."""
    from attackmap.handler_auth import session_gate

    wrapped = (
        "app.post('/x', async (req, res) => {\n"
        "  const session = await getSession(req)\n"
        "    ?? { user: guest };\n"
        "  if (!session) return res.status(401).end();\n"
        "  await db.delete(x);\n"
        "})\n"
    )
    default = (
        "app.post('/x', async (req, res) => {\n"
        "  const { user = guest } = await getSession(req);\n"
        "  if (!user) return res.status(401).end();\n"
        "  await db.delete(x);\n"
        "})\n"
    )
    plain = wrapped.replace("\n    ?? { user: guest };", ";")
    assert session_gate(wrapped) is None
    assert session_gate(default) is None
    assert session_gate(plain) is not None


def test_iife_wrapping_the_whole_body_is_transparent() -> None:
    # juice-shop's shape: the IIFE is the handler's last statement, so its
    # `return` ends the handler.
    handler = (
        "app.post('/api/x', (req, res, next) => {\n"
        "  void (async () => {\n"
        "    const session = await getSession(req);\n"
        "    if (!session) {\n      next(new Error('no'))\n      return\n    }\n"
        "    await Order.create(req.body);\n"
        "  })();\n"
        "});\n"
    )
    assert session_gate(handler) is not None


def test_unicode_line_separators_dont_shift_routes(tmp_path: Path) -> None:
    # Route.line counts `\n` only: a U+2028 (or a lone `\r`) above must not
    # make the open route borrow the gated handler above it.
    for sep in ("\u2028", "\r", "\f"):
        (tmp_path / "app.js").write_text(
            "const app = require('express')();\n"
            f"// note{sep}more\n"
            "app.post('/api/a', async (req, res) => { const session = await getSession(req); "
            "if (!session) return res.status(401).end(); await Order.create(req.body); });\n"
            "app.post('/api/b', async (req, res) => { await Order.create(req.body); });\n",
            newline="",
        )
        findings = _unauth_findings(tmp_path)
        assert len(findings) == 1, sep
        evidence = " ".join(findings[0].evidence)
        assert "/api/b" in evidence and "/api/a" not in evidence, (sep, evidence)


def test_unimported_object_reference_is_not_resolved_locally(tmp_path: Path) -> None:
    # `ctl.create` with `ctl` not imported must not pick up a local `create`.
    (tmp_path / "app.js").write_text(
        "const app = require('express')();\n"
        "async function create(req, res) {\n"
        "  const session = await getSession(req);\n"
        "  if (!session) return res.status(401).end();\n"
        "  await Order.create(req.body);\n"
        "}\n"
        "app.post('/api/b', ctl.create);\n"
    )
    assert len(_unauth_findings(tmp_path)) == 1


def test_only_a_sole_handler_reference_is_followed(tmp_path: Path) -> None:
    # `post(path, wipe, onError)`: a gate in the last function runs after `wipe` wrote.
    (tmp_path / "app.js").write_text(
        "const app = require('express')();\n"
        "async function wipe(req, res, next) { await Order.deleteMany({}); next(); }\n"
        "async function onError(req, res) {\n"
        "  const session = await getSession(req);\n"
        "  if (!session) return res.status(401).end();\n"
        "}\n"
        "app.post('/api/wipe', wipe, onError);\n"
    )
    assert len(_unauth_findings(tmp_path)) == 1
