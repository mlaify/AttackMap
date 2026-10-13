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


def _scan(tmp_path: Path, routes: list[tuple[str, str]], file: str = "routes.js", body: str = "") -> ScanResult:
    (tmp_path / file).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / file).write_text(body or "\n".join(f"// {m} {p}" for m, p in routes) + "\n")
    return ScanResult(
        root=str(tmp_path),
        routes=[Route(path=p, method=m, file=file, line=i + 1) for i, (m, p) in enumerate(routes)],
    )


def _management(tmp_path: Path, routes: list[tuple[str, str]], **kwargs) -> set[tuple[str, str]]:  # noqa: ANN003
    return {(m, p) for m, p, _ in webhook_management_routes(_scan(tmp_path, routes, **kwargs))}


@pytest.mark.parametrize(
    "routes",
    [
        # BookStack
        [("GET", "/settings/webhooks"), ("POST", "/settings/webhooks/create"), ("PUT", "/settings/webhooks/{id}")],
        # cal.com v2 REST
        [("POST", "/v2/webhooks"), ("GET", "/v2/webhooks"), ("PATCH", "/v2/webhooks/:webhookId"), ("DELETE", "/v2/webhooks/:webhookId")],
        [("POST", "/v2/event-types/:eventTypeId/webhooks"), ("GET", "/v2/event-types/:eventTypeId/webhooks/:webhookId")],
        # dub app router: `[webhookId]` and sub-resources
        [("GET", "/api/webhooks/[webhookId]"), ("GET", "/api/webhooks/[webhookId]/events"), ("PATCH", "/api/webhooks/[webhookId]/links")],
        # netbox (Django: method-less) — member with an int converter plus its collection
        [("ANY", "/extras/webhooks/"), ("ANY", "/extras/webhooks/<int:pk>/")],
        # healthchecks / taiga: a management word fused with `webhook`
        [("ANY", "/projects/<uuid:code>/add_webhook/")],
        [("ANY", "/api/v1/webhooklogs")],
        # cal.com tRPC router for webhook CRUD
        [("ANY", "/api/trpc/webhook/:trpc")],
        # an action on a stored webhook
        [("POST", "/hooks/webhooks/:id/test")],
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


def test_drf_viewset_registration_is_management(tmp_path: Path) -> None:
    body = 'router.register(r"webhooks", WebhookViewSet, base_name="webhooks")\nrouter.register(r"hooks/stripe", StripeHookView)\n'
    routes = [("ANY", "/api/v1/webhooks"), ("ANY", "/api/v1/hooks/stripe")]
    assert _management(tmp_path, routes, file="routers.py", body=body) == {("ANY", "/api/v1/webhooks")}


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
