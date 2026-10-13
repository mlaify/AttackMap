"""Webhook management routes are not inbound receivers (#365).

CRUD for an app's own outgoing-webhook configuration (`/settings/webhooks`,
`/v2/webhooks/:webhookId`, a DRF `WebhookViewSet`) used to land in the
`webhook` category, get `webhook_verification: absent` and raise
`public-webhook`. Real receivers must keep their category.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from attackmap.analyzer import identify_attack_surfaces
from attackmap.models import Route, ScanResult
from attackmap.threat_model import generate_findings
from attackmap.webhook_verification import webhook_management_routes


def _scan(
    tmp_path: Path,
    routes: list[tuple[str, str]],
    file: str = "routes.js",
    body: str = "",
    authenticated: bool = False,
) -> ScanResult:
    (tmp_path / file).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / file).write_text(body or "\n".join(f"// {m} {p}" for m, p in routes) + "\n")
    auth = "required" if authenticated else "unknown"
    guards = ["SessionAuthGuard"] if authenticated else []
    return ScanResult(
        root=str(tmp_path),
        routes=[
            Route(path=p, method=m, file=file, line=i + 1, auth=auth, guards=guards) for i, (m, p) in enumerate(routes)
        ],
    )


def _management(tmp_path: Path, routes: list[tuple[str, str]], **kwargs) -> set[tuple[str, str]]:  # noqa: ANN003
    return {(m, p) for m, p, _ in webhook_management_routes(_scan(tmp_path, routes, **kwargs))}


@pytest.mark.parametrize(
    "routes",
    [
        # BookStack
        [("GET", "/settings/webhooks"), ("POST", "/settings/webhooks/create"), ("PUT", "/settings/webhooks/{id}")],
        # cal.com v2 REST (reads and changes; the POST create is below)
        [("GET", "/v2/webhooks"), ("PATCH", "/v2/webhooks/:webhookId"), ("DELETE", "/v2/webhooks/:webhookId")],
        [("GET", "/v2/event-types/:eventTypeId/webhooks/:webhookId")],
        # dub app router: `[webhookId]` and sub-resources
        [("GET", "/api/webhooks/[webhookId]"), ("GET", "/api/webhooks/[webhookId]/events"), ("PATCH", "/api/webhooks/[webhookId]/links")],
        # healthchecks / taiga: a management word fused with `webhook`
        [("ANY", "/projects/<uuid:code>/add_webhook/")],
        [("ANY", "/api/v1/webhooklogs")],
        # cal.com tRPC router for webhook CRUD
        [("ANY", "/api/trpc/webhook/:trpc")],
        # an action on a stored webhook
        [("POST", "/hooks/webhooks/:id/test")],
        # settings CRUD: a create action, an id, a read
        [("POST", "/settings/webhooks/create"), ("GET", "/settings/webhooks")],
        # fused words that can't be event names, on a non-POST route
        [("GET", "/admin/webhooklogs"), ("ANY", "/webhook_settings"), ("GET", "/edit-webhook/:id")],
        # Laravel route model binding
        [("DELETE", "/teams/{team}/webhooks/{webhook}")],
    ],
)
def test_management_routes(tmp_path: Path, routes: list[tuple[str, str]]) -> None:
    assert _management(tmp_path, routes) == set(routes)


@pytest.mark.parametrize(
    "routes",
    [
        [("POST", "/api/webhooks")],  # nextjs-subscription-payments
        [("POST", "/stripe/webhook")],
        [("ANY", "/stripe/webhook/")],
        [("POST", "/api/github/webhooks")],
        [("POST", "/age-assurance/webhooks/kws-age-verified")],
        [("POST", "/age-assurance-webhook")],
        [("ANY", "/api/integrations/btcpayserver/webhook")],
        # A provider name after `webhooks` routes inbound events.
        [("POST", "/api/webhooks/:provider"), ("POST", "/webhooks/[source]")],
        # GET handshake of a receiver (Meta/WhatsApp `hub.challenge`) on a provider param.
        [("GET", "/webhooks/:provider"), ("GET", "/webhooks/<str:source>/")],
        [("POST", "/v2/webhooks/vercel/deployment-promoted")],
        # Discord/Slack-style incoming webhook: POST to the id (and token) is the receiver.
        [("POST", "/api/webhooks/:webhookId/:token"), ("POST", "/api/webhooks/:id")],
        # An id-addressed callback stays a receiver.
        [("POST", "/webhooks/:webhookId/callback")],
        # Event names fused with `webhook`, and any POST with a fused word.
        [
            ("POST", "/subscription-webhook"),
            ("POST", "/new-order-webhook"),
            ("ANY", "/delivery_webhook"),
            ("POST", "/update-webhook"),
            ("POST", "/order_create_webhook"),
            ("POST", "/webhook_settings"),
        ],
        # A receiver under a settings path, POSTed by the provider.
        [("POST", "/settings/integrations/slack/webhook")],
        # A Django collection beside its int-pk member: no evidence it isn't a receiver.
        [("ANY", "/extras/webhooks/")],
    ],
)
def test_receivers_are_not_management(tmp_path: Path, routes: list[tuple[str, str]]) -> None:
    assert _management(tmp_path, routes) == set()


def test_receiver_beside_a_management_collection_is_kept(tmp_path: Path) -> None:
    routes = [
        ("GET", "/v2/webhooks"),
        ("DELETE", "/v2/webhooks/:webhookId"),
        ("POST", "/v2/webhooks/vercel/deployment-promoted"),
        ("POST", "/api/webhooks/callback"),
    ]
    assert _management(tmp_path, routes) == {("GET", "/v2/webhooks"), ("DELETE", "/v2/webhooks/:webhookId")}


def test_post_to_collection_beside_an_event_log_stays_a_receiver(tmp_path: Path) -> None:
    # `GET /webhooks/:id` may be a log of received events: the POST that
    # receives them needs positive management evidence.
    routes = [("POST", "/webhooks"), ("GET", "/webhooks/:id")]
    assert _management(tmp_path, routes) == {("GET", "/webhooks/:id")}


def test_authenticated_post_to_collection_is_management(tmp_path: Path) -> None:
    routes = [("POST", "/v2/webhooks"), ("GET", "/v2/webhooks/:webhookId")]
    assert _management(tmp_path, routes, authenticated=True) == set(routes)


def test_post_to_collection_that_persists_webhook_config_is_management(tmp_path: Path) -> None:
    body = (
        "router.post('/api/webhooks', async (req, res) => {\n"
        "  const hook = await prisma.webhook.create({ data: { url: req.body.url, secret: req.body.secret, events: req.body.events } })\n"
        "  res.json(hook)\n"
        "})\n"
        "router.get('/api/webhooks/:webhookId', getHook)\n"
    )
    routes = [("POST", "/api/webhooks"), ("GET", "/api/webhooks/:webhookId")]
    scan = _scan(tmp_path, routes, file="server.js", body=body)
    scan.routes[1].line = 5
    assert {(m, p) for m, p, _ in webhook_management_routes(scan)} == set(routes)


def test_drf_model_viewset_is_management_and_provider_viewsets_are_not(tmp_path: Path) -> None:
    (tmp_path / "webhooks").mkdir()
    (tmp_path / "webhooks" / "api.py").write_text(
        "class WebhookViewSet(ArchivedMixin, ModelCrudViewSet):\n    model = Webhook\n\n"
        "class StripeWebhookViewSet(viewsets.ModelViewSet):\n    pass\n\n"
        "class InboundViewSet(viewsets.ViewSet):\n    pass\n"
    )
    (tmp_path / "webhooks" / "__init__.py").write_text("")
    body = (
        "from webhooks.api import WebhookViewSet, StripeWebhookViewSet, InboundViewSet\n"
        'router.register(r"webhooks", WebhookViewSet, base_name="webhooks")\n'
        'router.register(r"webhooks/stripe", StripeWebhookViewSet)\n'
        'router.register(r"webhook", InboundViewSet)\n'
    )
    routes = [("ANY", "/api/v1/webhooks"), ("ANY", "/api/v1/webhooks/stripe"), ("ANY", "/api/v1/webhook")]
    scan = ScanResult(
        root=str(tmp_path),
        routes=[Route(path=p, method=m, file="routers.py", line=i + 2) for i, (m, p) in enumerate(routes)],
    )
    (tmp_path / "routers.py").write_text(body)
    assert {p for _, p, _ in webhook_management_routes(scan)} == {"/api/v1/webhooks"}


def test_management_routes_leave_the_webhook_category_and_findings(tmp_path: Path) -> None:
    scan = _scan(tmp_path, [("POST", "/settings/webhooks/create"), ("POST", "/stripe/webhook")])
    scan.databases = []
    surfaces = {s.route: s for s in identify_attack_surfaces(scan)}
    assert surfaces["/settings/webhooks/create"].category != "webhook"
    assert any("webhook configuration" in r for r in surfaces["/settings/webhooks/create"].rationale)
    assert surfaces["/stripe/webhook"].category == "webhook"


def test_candidate_whose_handler_verifies_a_signature_stays_a_receiver(tmp_path: Path) -> None:
    # Looks like management by shape (an id after `webhooks`, GET), but the
    # handler verifies a provider signature: precision first, keep it.
    body = (
        "router.get('/webhooks/:webhookId', (req, res) => {\n"
        "  const event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], secret)\n"
        "  res.send(event.id)\n"
        "})\n"
    )
    scan = _scan(tmp_path, [("GET", "/webhooks/:webhookId")], file="server.js", body=body)
    (surface,) = identify_attack_surfaces(scan)
    assert surface.category == "webhook"
    assert surface.webhook_verification is not None and surface.webhook_verification.state == "verified"


def test_public_webhook_no_longer_fires_on_management_crud(tmp_path: Path) -> None:
    scan = _scan(
        tmp_path,
        [("POST", "/settings/webhooks/create"), ("PUT", "/settings/webhooks/{id}"), ("DELETE", "/settings/webhooks/{id}")],
        file="routes/web.php",
    )
    scan.databases = []
    findings = generate_findings(scan, identify_attack_surfaces(scan))
    assert not [f for f in findings if f.rule_id == "public-webhook"]


def test_django_member_of_a_collection_is_management_but_the_collection_is_not(tmp_path: Path) -> None:
    # netbox: method-less Django routes. The int-pk member addresses a stored
    # webhook; the bare collection could be a receiver, so it stays one.
    routes = [("ANY", "/extras/webhooks/"), ("ANY", "/extras/webhooks/<int:pk>/")]
    assert _management(tmp_path, routes) == {("ANY", "/extras/webhooks/<int:pk>/")}



# ---------------------------------------------------------------------------
# Review round 2: PUT alone, tenant params, secret guards, handshakes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "routes",
    [
        [("PUT", "/webhooks/{id}")],  # a PUT alone isn't management
        [("PATCH", "/api/webhooks/:webhookId")],
        [("PUT", "/webhooks/:accountId"), ("GET", "/webhooks/:accountId")],  # tenant-scoped receiver
        [("DELETE", "/webhooks/:tenantId"), ("GET", "/hooks/webhook/:orgId")],
    ],
)
def test_put_alone_and_tenant_params_stay_receivers(tmp_path: Path, routes: list[tuple[str, str]]) -> None:
    assert _management(tmp_path, routes) == set()


def test_put_with_read_sibling_or_user_auth_is_management(tmp_path: Path) -> None:
    routes = [("PUT", "/webhooks/{id}"), ("GET", "/webhooks/{id}")]
    assert _management(tmp_path, routes) == set(routes)
    assert _management(tmp_path, [("PUT", "/hooks/webhooks/{id}")], authenticated=True) == {("PUT", "/hooks/webhooks/{id}")}


def _guarded(tmp_path: Path, guards: list[str], auth: str = "required") -> set[tuple[str, str]]:
    (tmp_path / "r.js").write_text("// POST /v2/webhooks\n// GET /v2/webhooks/:webhookId\n")
    scan = ScanResult(
        root=str(tmp_path),
        routes=[
            Route(path="/v2/webhooks", method="POST", file="r.js", line=1, auth=auth, guards=guards),
            Route(path="/v2/webhooks/:webhookId", method="GET", file="r.js", line=2),
        ],
    )
    return {(m, p) for m, p, _ in webhook_management_routes(scan)}


def test_only_user_guards_count_as_management_auth(tmp_path: Path) -> None:
    assert ("POST", "/v2/webhooks") in _guarded(tmp_path, ["ApiAuthGuard"])
    # A plugin-declared shared-secret / signature check is how receivers authenticate.
    assert ("POST", "/v2/webhooks") not in _guarded(tmp_path, ["WebhookSecretGuard"])
    assert ("POST", "/v2/webhooks") not in _guarded(tmp_path, ["verifySignature"])
    # Required with no named guard: doubt → receiver.
    assert ("POST", "/v2/webhooks") not in _guarded(tmp_path, [])


def test_get_with_subscription_handshake_stays_a_receiver(tmp_path: Path) -> None:
    body = (
        "router.get('/webhooks', (req, res) => {\n"
        "  if (req.query['hub.mode'] === 'subscribe') return res.send(req.query['hub.challenge'])\n"
        "  res.sendStatus(403)\n"
        "})\n"
        "router.get('/webhooks/:webhookId', show)\n"
    )
    scan = _scan(tmp_path, [("GET", "/webhooks"), ("GET", "/webhooks/:webhookId")], file="s.js", body=body)
    scan.routes[1].line = 5
    assert {(m, p) for m, p, _ in webhook_management_routes(scan)} == {("GET", "/webhooks/:webhookId")}
