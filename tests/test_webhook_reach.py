"""Webhook verification reach (#366): TS `.js` specifiers, curried middleware
factories and multi-line parameter lists, a second hop, `timingSafeCompare`-
style helpers, `export { default } from` re-exports and 404 stubs."""

from __future__ import annotations

from pathlib import Path

from attackmap.analyzer import identify_attack_surfaces
from attackmap.authz import _block_from, _HopResolver
from attackmap.models import Route, ScanResult
from attackmap.threat_model import generate_findings

HMAC_UTIL = """\
import crypto from 'node:crypto'

export const validateSignature = (
  key: string,
  data: string,
  signature: string,
) => {
  const expected = crypto.createHmac('sha256', key).update(data).digest('hex')
  if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature))) {
    throw new Error('Signature mismatch')
  }
}
"""

MIDDLEWARE = """\
import type { RequestHandler } from 'express'
import { validateSignature } from './util.js'

export const webhookAuth =
  ({ secret }: { secret: string }): RequestHandler =>
  (req, res, next) => {
    const sig = req.headers['x-acme-signature'] as string
    validateSignature(secret, String(req.body), sig)
    next()
  }
"""

ROUTER = """\
import { Router } from 'express'
import { webhookAuth } from './webhook.js'

export const createRouter = (secret: string) => {
  const router = Router()
  router.post(
    '/acme/webhook',
    webhookAuth({ secret }),
    (req, res) => res.sendStatus(204),
  )
  return router
}
"""


def _write(root: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)


def _webhook(root: Path, route: str, file: str, line: int, method: str = "POST"):
    scan = ScanResult(root=str(root), routes=[Route(path=route, method=method, file=file, line=line)])
    (surface,) = identify_attack_surfaces(scan)
    return scan, surface


def test_ts_js_specifier_curried_factory_and_second_hop(tmp_path: Path) -> None:
    _write(tmp_path, {"api/util.ts": HMAC_UTIL, "api/webhook.ts": MIDDLEWARE, "api/index.ts": ROUTER})
    _, surface = _webhook(tmp_path, "/acme/webhook", "api/index.ts", 6)
    v = surface.webhook_verification
    assert v is not None and v.state == "verified"
    assert v.evidence == "api/util.ts:9"


def test_hop_resolver_maps_js_specifiers_to_ts(tmp_path: Path) -> None:
    _write(tmp_path, {"api/webhook.ts": MIDDLEWARE, "api/index.ts": ROUTER})
    hop = _HopResolver(tmp_path, {})
    imports = hop._import_map("api/index.ts", ROUTER)
    assert imports["webhookAuth"] == "api/webhook.ts"


def test_block_from_keeps_curried_and_multiline_definitions() -> None:
    curried = MIDDLEWARE.splitlines()
    assert "validateSignature(secret" in _block_from(curried, 3)
    multiline = HMAC_UTIL.splitlines()
    assert "timingSafeEqual" in _block_from(multiline, 2)
    # A one-liner and a definition that never opens a body stay one line.
    assert _block_from(["const f = (id) => find(id);", "other()"], 0) == "const f = (id) => find(id);"
    assert _block_from(["export const X = a", "b", "c", "d", "e"], 0) == "export const X = a"


def test_timing_safe_compare_helper_is_constant_time(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "hook.js": (
                "app.post('/hooks/webhook', (req, res) => {\n"
                "  const expected = crypto.createHmac('sha256', secret).update(req.rawBody).digest('hex')\n"
                "  if (!timingSafeCompare(expected, req.headers['x-hub-signature-256'])) return res.sendStatus(401)\n"
                "  res.sendStatus(204)\n"
                "})\n"
            )
        },
    )
    _, surface = _webhook(tmp_path, "/hooks/webhook", "hook.js", 1)
    assert surface.webhook_verification.state == "verified"
    assert surface.webhook_verification.evidence == "hook.js:3"


def test_default_reexport_is_followed_into_a_workspace_package(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "packages/app-store/package.json": '{\n  "name": "@acme/app-store",\n  "version": "1.0.0"\n}\n',
            "packages/app-store/btc/api/webhook.ts": (
                "export default async function handler(req, res) {\n"
                "  const computed = crypto.createHmac('sha256', secret).update(raw).digest('hex')\n"
                "  if (!crypto.timingSafeEqual(Buffer.from(computed), Buffer.from(sig))) throw new Error('bad')\n"
                "  res.status(200).end()\n"
                "}\n"
            ),
            "apps/web/pages/api/integrations/btc/webhook.ts": (
                'export { default } from "@acme/app-store/btc/api/webhook";\n\n'
                "export const config = { api: { bodyParser: false } };\n"
            ),
        },
    )
    _, surface = _webhook(tmp_path, "/api/integrations/btc/webhook", "apps/web/pages/api/integrations/btc/webhook.ts", 1, "ANY")
    assert surface.webhook_verification.state == "verified"
    assert surface.webhook_verification.evidence == "packages/app-store/btc/api/webhook.ts:3"


def test_relative_default_reexport_without_verification_is_absent(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "lib/hook.ts": "export default function handler(req, res) {\n  save(req.body)\n  res.end()\n}\n",
            "pages/api/webhook.ts": 'export { default } from "../../lib/hook";\n',
        },
    )
    _, surface = _webhook(tmp_path, "/api/webhook", "pages/api/webhook.ts", 1, "ANY")
    assert surface.webhook_verification.state == "absent"


def test_not_found_stub_is_inert_and_not_a_public_webhook(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "pages/api/stripe/webhook.ts": (
                'import type { NextApiRequest, NextApiResponse } from "next";\n\n'
                "export const config = { api: { bodyParser: false } };\n\n"
                "export default function handler(_req: NextApiRequest, res: NextApiResponse) {\n"
                '  res.status(404).json({ message: "Billing webhooks are not available in community edition" });\n'
                "}\n"
            )
        },
    )
    scan, surface = _webhook(tmp_path, "/api/stripe/webhook", "pages/api/stripe/webhook.ts", 5, "ANY")
    assert surface.webhook_verification.inert is True
    scan.databases = []
    assert not [f for f in generate_findings(scan, [surface]) if f.rule_id == "public-webhook"]


def test_handler_that_sometimes_answers_404_is_not_a_stub(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "hook.js": (
                "app.post('/orders/webhook', async (req, res) => {\n"
                "  const order = await db.orders.find(req.body.id)\n"
                "  if (!order) return res.status(404).end()\n"
                "  await db.orders.update(order.id, req.body)\n"
                "  res.sendStatus(204)\n"
                "})\n"
            )
        },
    )
    _, surface = _webhook(tmp_path, "/orders/webhook", "hook.js", 1)
    assert surface.webhook_verification.inert is False
    assert surface.webhook_verification.state == "absent"
