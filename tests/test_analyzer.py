from attackmap.analyzer import identify_attack_surfaces, summarize_architecture, summarize_attack_surface
from attackmap.graph import build_graph
from attackmap.models import AuthHint, DatabaseHint, ExternalCall, Route, ScanResult


def test_identify_attack_surfaces_classifies_routes_for_attacker_review() -> None:
    scan = ScanResult(
        root=".",
        routes=[
            Route(path="/webhook/stripe", method="POST", file="api.py"),
            Route(path="/admin/users", method="GET", file="api.py"),
            Route(path="/login", method="POST", file="auth.py"),
        ],
        databases=[DatabaseHint(kind="postgresql", file="db.py")],
        external_calls=[ExternalCall(target="https://api.example.com/process", file="api.py")],
        auth_hints=[AuthHint(hint="jwt", file="auth.py")],
    )

    surfaces = identify_attack_surfaces(scan)

    assert any(surface.route == "/webhook/stripe" and surface.category == "webhook" and surface.risk == "high" for surface in surfaces)
    assert any(surface.route == "/admin/users" and surface.category == "admin" and surface.risk == "high" for surface in surfaces)
    assert any(
        surface.route == "/login" and surface.category == "auth" and "jwt" in surface.auth_signals
        for surface in surfaces
    )


def test_summarize_attack_surface_includes_classified_section() -> None:
    scan = ScanResult(
        root=".",
        routes=[Route(path="/webhook/stripe", method="POST", file="api.py")],
    )

    summary = summarize_attack_surface(scan)

    assert "## Priority View" in summary
    assert "## Highest-Risk Entry Points" in summary
    assert "## Public Application Routes" in summary
    assert "[HIGH] POST /webhook/stripe (api.py) -> webhook" in summary


def test_summarize_architecture_highlights_boundaries_and_overview() -> None:
    scan = ScanResult(
        root=".",
        languages=["python"],
        routes=[Route(path="/admin/users", method="GET", file="api.py")],
        databases=[DatabaseHint(kind="postgresql", file="db.py")],
        external_calls=[ExternalCall(target="https://api.example.com/process", file="api.py")],
        auth_hints=[AuthHint(hint="jwt", file="api.py")],
    )

    summary = summarize_architecture(scan, build_graph(scan))

    assert "## Overview" in summary
    assert "web-facing repository" in summary
    assert "- Inferred entry points: 1" in summary
    assert "## Likely Review Starting Point" in summary
    assert "## Inferred Trust Boundaries" in summary
    assert "web -> postgresql (uses)" in summary
    assert "## Analyst Notes" in summary


def test_identify_attack_surfaces_respects_node_service_internal_handler_hints() -> None:
    scan = ScanResult(
        root=".",
        routes=[
            Route(path="/sync/internal", method="POST", file="services/relay/src/consumer.ts"),
            Route(path="/xrpc/com.atproto.server.createSession", method="POST", file="services/api/src/server.ts"),
        ],
        auth_hints=[
            AuthHint(hint="service_name:relay", file="services/relay/src/consumer.ts"),
            AuthHint(hint="service_role:event_consumer", file="services/relay/src/consumer.ts"),
            AuthHint(hint="handler_type:internal_handler", file="services/relay/src/consumer.ts"),
            AuthHint(hint="service_name:api", file="services/api/src/server.ts"),
            AuthHint(hint="service_role:api", file="services/api/src/server.ts"),
            AuthHint(hint="handler_type:public_api", file="services/api/src/server.ts"),
        ],
    )

    surfaces = identify_attack_surfaces(scan)
    by_route = {surface.route: surface for surface in surfaces}

    assert by_route["/sync/internal"].exposure == "internal"
    assert by_route["/sync/internal"].category == "internal"
    assert by_route["/xrpc/com.atproto.server.createSession"].exposure == "public"


def test_identify_attack_surfaces_prefers_explicit_public_visibility_over_worker_role() -> None:
    scan = ScanResult(
        root=".",
        routes=[Route(path="/xrpc/com.atproto.server.createSession", method="POST", file="services/pds/src/server.ts")],
        auth_hints=[
            AuthHint(hint="service_name:pds", file="services/pds/src/server.ts"),
            AuthHint(hint="service_role:worker", file="services/pds/src/server.ts"),
            AuthHint(hint="handler_type:public_api", file="services/pds/src/server.ts"),
            AuthHint(hint="handler_visibility:public", file="services/pds/src/server.ts"),
        ],
    )

    surfaces = identify_attack_surfaces(scan)

    assert len(surfaces) == 1
    assert surfaces[0].route == "/xrpc/com.atproto.server.createSession"
    assert surfaces[0].exposure == "public"
    assert surfaces[0].category == "public_api"


# ---------------------------------------------------------------------------
# #41: route-scoped auth attribution.
# ---------------------------------------------------------------------------


def test_auth_hints_attach_only_to_routes_near_them_by_line_number() -> None:
    """Two routes in the same file, one near a jwt hint line, the other
    far below it. Only the near route should carry `jwt` in
    auth_signals — the old file-scoped attribution gave both routes
    every hint and produced the noise FINDINGS §55 called out."""
    scan = ScanResult(
        root=".",
        routes=[
            Route(path="/login", method="POST", file="app.py", line=10),
            Route(path="/orders", method="GET", file="app.py", line=200),
        ],
        auth_hints=[
            AuthHint(hint="jwt", file="app.py", line=12),
        ],
    )

    surfaces = identify_attack_surfaces(scan)
    by_route = {s.route: s for s in surfaces}
    assert "jwt" in by_route["/login"].auth_signals
    assert "jwt" not in by_route["/orders"].auth_signals


def test_auth_hint_within_window_below_the_route_still_attaches() -> None:
    """Auth checks often live at the top of the handler body, but
    sometimes they're deeper — a check 20 lines below a route should
    still count as evidence for that route."""
    scan = ScanResult(
        root=".",
        routes=[Route(path="/x", method="GET", file="app.py", line=10)],
        auth_hints=[AuthHint(hint="jwt", file="app.py", line=30)],
    )
    surfaces = identify_attack_surfaces(scan)
    assert "jwt" in surfaces[0].auth_signals


def test_auth_hint_outside_window_does_not_attach() -> None:
    """A hint 100 lines above the route in the same file isn't part
    of the route's handler — don't claim it as this route's evidence."""
    scan = ScanResult(
        root=".",
        routes=[Route(path="/x", method="GET", file="app.py", line=200)],
        auth_hints=[AuthHint(hint="jwt", file="app.py", line=50)],
    )
    surfaces = identify_attack_surfaces(scan)
    assert "jwt" not in surfaces[0].auth_signals
    assert surfaces[0].auth_signals == []


def test_routes_without_line_info_fall_back_to_file_scoped_attribution() -> None:
    """Framework config-driven routes (Laminas, Django URLconf) legitimately
    lack inline handler line numbers. Preserve the file-scoped fallback
    for those so we don't lose evidence entirely."""
    scan = ScanResult(
        root=".",
        routes=[Route(path="/admin", method="ANY", file="module/config.php")],  # no line
        auth_hints=[AuthHint(hint="controller:AdminController", file="module/config.php", line=42)],
    )
    surfaces = identify_attack_surfaces(scan)
    assert "controller:AdminController" in surfaces[0].auth_signals


def test_global_fallback_dropped_route_does_not_inherit_hints_from_unrelated_files() -> None:
    """FINDINGS §55: the old logic inherited every auth hint in the repo
    when a route's own file had none. That's the noise this ticket
    kills — a route in `orders.py` should not carry hints emitted only
    in `auth.py`."""
    scan = ScanResult(
        root=".",
        routes=[
            Route(path="/login", method="POST", file="auth.py", line=5),
            Route(path="/orders", method="GET", file="orders.py", line=5),
        ],
        auth_hints=[
            AuthHint(hint="jwt", file="auth.py", line=6),
            AuthHint(hint="passport", file="auth.py", line=8),
        ],
    )
    surfaces = identify_attack_surfaces(scan)
    by_route = {s.route: s for s in surfaces}
    assert "jwt" in by_route["/login"].auth_signals
    assert by_route["/orders"].auth_signals == []


def test_auth_hint_without_line_still_attaches_to_same_file_routes() -> None:
    """Older analyzers (or non-scanner-emitted hints) may lack `line`.
    When line is unknown, don't gate on it — count it toward same-file
    routes. Keeps existing plugin outputs working."""
    scan = ScanResult(
        root=".",
        routes=[Route(path="/x", method="GET", file="app.py", line=10)],
        auth_hints=[AuthHint(hint="jwt", file="app.py")],  # no line
    )
    surfaces = identify_attack_surfaces(scan)
    assert "jwt" in surfaces[0].auth_signals
