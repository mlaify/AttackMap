"""Handler-level session checks for `unauth-state-change` (#348).

Only a check that gates a rejection counts: the condition must be exactly a
negated session value, and the then-branch must start with return / throw /
redirect (or `next(err)` / `res.status(401)` followed by `return`).
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
    "const user = await currentUser();\nif (!user) redirect('/login');",
    "const session = await auth();\nif (!session?.user?.id) {\n  res.status(401).send('no');\n  return;\n}",
    "const s = await getSession(req);\nif (!s) { throw new UnauthorizedException(); }",
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


@pytest.mark.parametrize("handler", GATED)
def test_rejecting_session_checks_are_gates(handler: str) -> None:
    assert session_gate(handler) is not None


@pytest.mark.parametrize("handler", NOT_GATED)
def test_non_rejecting_or_unrelated_checks_are_not_gates(handler: str) -> None:
    assert session_gate(handler) is None


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
