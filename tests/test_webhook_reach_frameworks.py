"""Webhook verification reach, part 2 (#366): NestJS guards, Laravel
controller-constructor middleware, PayPal's verify-webhook-signature API,
instance methods and constant-time shared secrets."""

from __future__ import annotations

from pathlib import Path

from attackmap.analyzer import identify_attack_surfaces
from attackmap.authz import _block_from
from attackmap.models import Route, ScanResult


def _write(root: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)


def _verification(root: Path, route: str, file: str, line: int, method: str = "POST"):
    scan = ScanResult(root=str(root), routes=[Route(path=route, method=method, file=file, line=line)])
    (surface,) = identify_attack_surfaces(scan)
    return surface.webhook_verification


GUARD = """\
import { CanActivate, ExecutionContext, Injectable } from "@nestjs/common";
import crypto from "crypto";

@Injectable()
export class VercelWebhookGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const signature = request.headers["x-vercel-signature"];
    const expected = crypto.createHmac("sha1", secret).update(request.rawBody).digest("hex");
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
  }
}
"""

NOOP_GUARD = """\
export class LoggingGuard {
  canActivate(context) {
    console.log("hit");
    return true;
  }
}
"""


def test_nestjs_method_guard_is_followed(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "src/vercel.guard.ts": GUARD,
            "src/vercel.controller.ts": (
                'import { VercelWebhookGuard } from "./vercel.guard";\n'
                '@Controller({ path: "/v2/webhooks/vercel" })\n'
                "export class VercelController {\n"
                '  @Post("deployment-promoted")\n'
                "  @UseGuards(VercelWebhookGuard)\n"
                "  async promoted(@Body() body: unknown) {\n"
                "    return this.service.handle(body);\n"
                "  }\n"
                "}\n"
            ),
        },
    )
    v = _verification(tmp_path, "/v2/webhooks/vercel/deployment-promoted", "src/vercel.controller.ts", 4)
    assert (v.state, v.evidence) == ("verified", "src/vercel.guard.ts:10")


def test_nestjs_class_level_guard_is_followed(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "src/vercel.guard.ts": GUARD,
            "src/vercel.controller.ts": (
                'import { VercelWebhookGuard } from "./vercel.guard";\n'
                '@Controller({ path: "/v2/webhooks/vercel" })\n'
                "@UseGuards(VercelWebhookGuard)\n"
                "export class VercelController {\n"
                '  @Post("deployment-promoted")\n'
                "  async promoted(@Body() body: unknown) {\n"
                "    return this.service.handle(body);\n"
                "  }\n"
                "}\n"
            ),
        },
    )
    v = _verification(tmp_path, "/v2/webhooks/vercel/deployment-promoted", "src/vercel.controller.ts", 5)
    assert v.state == "verified"


def test_guard_that_verifies_nothing_stays_absent(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "src/log.guard.ts": NOOP_GUARD,
            "src/c.controller.ts": (
                'import { LoggingGuard } from "./log.guard";\n'
                "export class C {\n"
                '  @Post("hooks/webhook")\n'
                "  @UseGuards(LoggingGuard)\n"
                "  async receive(@Body() body) {\n"
                "    await this.db.save(body);\n"
                "  }\n"
                "}\n"
            ),
        },
    )
    assert _verification(tmp_path, "/hooks/webhook", "src/c.controller.ts", 3).state == "absent"


CONTROLLER = """\
<?php

namespace App\\Http\\Controllers;

use App\\Http\\Middleware\\VerifyWebhookSignature;

class WebhookController extends Controller
{
    public function __construct()
    {
        {CTOR}
    }

    public function handleWebhook(Request $request)
    {
        $payload = json_decode($request->getContent(), true);
        return $this->dispatch($payload);
    }
}
"""

MIDDLEWARE = """\
<?php

namespace App\\Http\\Middleware;

use Stripe\\WebhookSignature;

class VerifyWebhookSignature
{
    public function handle($request, Closure $next)
    {
        WebhookSignature::verifyHeader(
            $request->getContent(),
            $request->header('Stripe-Signature'),
            config('services.stripe.webhook_secret'),
            300
        );

        return $next($request);
    }
}
"""


def _laravel(tmp_path: Path, ctor: str):
    _write(
        tmp_path,
        {
            "app/Http/Controllers/WebhookController.php": CONTROLLER.replace("{CTOR}", ctor),
            "app/Http/Middleware/VerifyWebhookSignature.php": MIDDLEWARE,
            "routes/web.php": "<?php\nRoute::post('stripe/webhook', 'WebhookController@handleWebhook');\n",
        },
    )
    return _verification(tmp_path, "/stripe/webhook", "routes/web.php", 2)


def test_laravel_constructor_middleware_is_followed(tmp_path: Path) -> None:
    v = _laravel(tmp_path, "$this->middleware(VerifyWebhookSignature::class);")
    assert (v.state, v.provider) == ("verified", "stripe")
    assert v.evidence == "app/Http/Middleware/VerifyWebhookSignature.php:11"


def test_conditional_laravel_middleware_is_unknown(tmp_path: Path) -> None:
    # Laravel Cashier: verification only when a secret is configured.
    v = _laravel(
        tmp_path, "if (config('services.stripe.webhook_secret')) {\n            $this->middleware(VerifyWebhookSignature::class);\n        }"
    )
    assert v.state == "unknown"
    assert any("only when a condition holds" in note for note in v.notes)


def test_laravel_controller_without_middleware_is_absent(tmp_path: Path) -> None:
    assert _laravel(tmp_path, "// nothing").state == "absent"


PAYPAL = """\
class Paypal {
  async verifyWebhook(options) {
    const body = `${JSON.stringify(options).slice(0, -1)},"webhook_event":${options.event}}`;
    const response = await this.fetcher(`/v1/notifications/verify-webhook-signature`, { method: "POST", body });
    const data = await response.json();
    {CHECK}
  }
}
export default Paypal;
"""


def _paypal(tmp_path: Path, check: str):
    _write(
        tmp_path,
        {
            "lib/Paypal.ts": PAYPAL.replace("{CHECK}", check),
            "api/webhook.ts": (
                'import Paypal from "../lib/Paypal";\n'
                "export default async function handler(req, res) {\n"
                "  const paypalClient = new Paypal(credentials);\n"
                "  await paypalClient.verifyWebhook({ headers: req.headers, event: req.body });\n"
                "  await handlePayment(req.body);\n"
                "}\n"
            ),
        },
    )
    return _verification(tmp_path, "/api/paypal/webhook", "api/webhook.ts", 2, "ANY")


def test_paypal_verify_api_with_success_check_is_verified(tmp_path: Path) -> None:
    v = _paypal(tmp_path, 'if (data.verification_status !== "SUCCESS") throw data;')
    assert (v.state, v.provider, v.evidence) == ("verified", "paypal", "lib/Paypal.ts:6")


def test_paypal_verify_api_without_a_status_check_is_not_verified(tmp_path: Path) -> None:
    assert _paypal(tmp_path, "return data;").state != "verified"


def test_braces_in_template_literals_do_not_end_a_block() -> None:
    lines = PAYPAL.replace("{CHECK}", "return data;").splitlines()
    assert "verify-webhook-signature" in _block_from(lines, 1)


SECRET = """\
function verifyWorkerSecret(req) {
  const auth = req.headers.get("authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice("Bearer ".length) : "";
  return {COMPARE};
}

export async function POST(req) {
  if (!verifyWorkerSecret(req)) return new Response("Unauthorized", { status: 401 });
  await processUpload(await req.json());
  return new Response("ok");
}
"""


def test_constant_time_shared_secret_is_verified_with_a_note(tmp_path: Path) -> None:
    _write(tmp_path, {"route.ts": SECRET.replace("{COMPARE}", "timingSafeCompare(token, process.env.WORKER_SECRET)")})
    v = _verification(tmp_path, "/api/cloudflare/webhook/r2", "route.ts", 7)
    assert (v.state, v.provider) == ("verified", "shared_secret")
    assert v.notes and "not a payload signature" in v.notes[0]


def test_shared_secret_compared_with_equality_is_not_verified(tmp_path: Path) -> None:
    _write(tmp_path, {"route.ts": SECRET.replace("{COMPARE}", "token === process.env.WORKER_SECRET")})
    assert _verification(tmp_path, "/api/cloudflare/webhook/r2", "route.ts", 7).state != "verified"


def test_constant_time_compare_without_a_secret_header_is_not_a_shared_secret(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "route.ts": (
                "export async function POST(req) {\n"
                "  const body = await req.json();\n"
                "  if (!timingSafeCompare(body.kind, 'upload')) return new Response('', { status: 400 });\n"
                "  await processUpload(body);\n"
                "}\n"
            )
        },
    )
    assert _verification(tmp_path, "/api/r2/webhook", "route.ts", 1).state == "absent"


def test_paypal_class_imported_from_a_workspace_package(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "packages/app-store/package.json": '{"name": "@acme/app-store"}\n',
            "packages/app-store/paypal/lib/Paypal.ts": PAYPAL.replace(
                "{CHECK}", 'if (data.verification_status !== "SUCCESS") throw data;'
            ),
            "packages/app-store/paypal/api/webhook.ts": (
                'import Paypal from "@acme/app-store/paypal/lib/Paypal";\n'
                "export default async function handler(req, res) {\n"
                "  const paypalClient = new Paypal(credentials);\n"
                "  await paypalClient.verifyWebhook({ headers: req.headers, event: req.body });\n"
                "}\n"
            ),
            "apps/web/pages/api/integrations/paypal/webhook.ts": 'export { default } from "@acme/app-store/paypal/api/webhook";\n',
        },
    )
    v = _verification(tmp_path, "/api/integrations/paypal/webhook", "apps/web/pages/api/integrations/paypal/webhook.ts", 1, "ANY")
    assert (v.state, v.provider) == ("verified", "paypal")


def test_instance_method_in_a_long_class_is_followed(tmp_path: Path) -> None:
    # The hop resolver caps a definition's lines, so a long class body is cut
    # before `verifyWebhook`; `x = new Paypal(); x.verifyWebhook()` reaches it.
    filler = "".join(f"  helper{i}() {{\n    return {i};\n  }}\n" for i in range(120))
    long_class = PAYPAL.replace("class Paypal {\n", "class Paypal {\n" + filler).replace(
        "{CHECK}", 'if (data.verification_status !== "SUCCESS") throw data;'
    )
    _write(
        tmp_path,
        {
            "lib/Paypal.ts": long_class,
            "api/webhook.ts": (
                'import Paypal from "../lib/Paypal";\n'
                "export default async function handler(req, res) {\n"
                "  const paypalClient = new Paypal(credentials);\n"
                "  await paypalClient.verifyWebhook({ headers: req.headers, event: req.body });\n"
                "}\n"
            ),
        },
    )
    v = _verification(tmp_path, "/api/paypal/webhook", "api/webhook.ts", 2, "ANY")
    assert (v.state, v.provider) == ("verified", "paypal")
