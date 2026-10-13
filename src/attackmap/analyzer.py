from __future__ import annotations

import re
from collections import Counter

import networkx as nx

from .models import AttackSurface, AuthHint, Route, ScanResult
from .webhook_verification import assess_webhook_surfaces, reclaim_receivers, webhook_management_routes


# Bounded line window used to attribute auth hints to a specific route
# handler. Chosen so a hint at the top of the handler body still lands
# on the route even if the handler is 40 lines long. Bigger than a typical
# handler; smaller than the distance between two adjacent routes. See #41
# / Bluesky FINDINGS §55 for the noise problem this fixes.
_ROUTE_AUTH_LINE_WINDOW = 40

# An authentication path segment (#340): the term starts the segment and is
# followed by the end of the segment, a non-letter (`login-form`, `oauth2`,
# `auth_callback`, `authCallback`) or one of its own word forms
# (`authenticate`, `authorize`, `sessions`, `tokens`). A substring match made
# `/api/authorities` and `/authors` auth routes.
_AUTH_SEGMENT = re.compile(
    r"\A(?i:login|signin|signup|auth|session|token|oauth)"
    r"(?i:s|enticate|entication|orize|orization)?"
    r"(?![a-z])"
)


def is_auth_path(path: str) -> bool:
    """Whether a route path has an authentication segment (see `_AUTH_SEGMENT`)."""
    return any(_AUTH_SEGMENT.match(segment) for segment in path.split("/")[1:] if segment)


# Authentication entry points (#328). The route that authenticates the caller
# has to be reachable without authentication, so `POST /admin/login` is an
# `auth` surface (brute force, lockout), not an unguarded admin action. Matched
# on whole path segments, and only when every segment before the action is
# admin/auth vocabulary: `/admin/users/:id/logout` (forcing another user out)
# and `/admin/login-as/:id` (impersonation) stay admin actions.
_LOGIN_SEGMENTS = frozenset({
    "login", "log-in", "log_in", "logon", "signin", "sign-in", "sign_in", "authenticate",
    "logout", "log-out", "log_out", "logoff", "signout", "sign-out", "sign_out",
    "forgot-password", "forgot_password", "forgotpassword", "reset-password", "reset_password",
    "resetpassword", "password-reset", "password_reset", "passwordreset",
})
# `/admin/password/reset`, `/admin/password/email` (Laravel).
_PASSWORD_ACTIONS = frozenset({"reset", "forgot", "email"})
# Token and callback actions count only under an auth segment
# (`/admin/auth/token`, `/admin/oauth/callback`): `/admin/api/token` may mint
# API tokens for others.
_TOKEN_SEGMENTS = frozenset({"token", "refresh", "refresh-token", "refresh_token", "callback"})
_AUTH_SEGMENTS = frozenset({
    "auth", "authentication", "oauth", "oauth2", "oidc", "openid", "sso", "saml", "jwt", "token",
})
# Exact words only: `administrators`, `admin-users`, `accounts`, `staff` or
# `sessions` name a resource an admin acts on (`/admin/accounts/reset-password`
# resets someone else's password).
_ADMIN_PREFIX_SEGMENTS = frozenset({
    "admin", "manage", "root", "api", "dashboard", "backend", "backoffice", "panel", "console", "password",
})
_VERSION_SEGMENT_RE = re.compile(r"v\d{1,3}")
_PLAIN_SEGMENT_RE = re.compile(r"[a-z0-9_-]{1,40}")
_ENTRY_SUFFIXES = (".php", ".aspx", ".asp", ".jsp", ".html", ".htm", ".do")


def _prefix_segment(segment: str) -> bool:
    return (
        segment in _ADMIN_PREFIX_SEGMENTS
        or segment in _AUTH_SEGMENTS
        or _VERSION_SEGMENT_RE.fullmatch(segment) is not None
    )


def is_auth_entry_point(path: str) -> bool:
    """Whether `path` is a login/logout/password-reset/token/OAuth-callback
    endpoint rather than an action behind authentication (#328)."""
    segments = [seg for seg in path.lower().split("?", 1)[0].split("/") if seg]
    if not segments or len(segments) > 8:
        return False
    action = segments[-1]
    for suffix in _ENTRY_SUFFIXES:
        if action.endswith(suffix):
            action = action[: -len(suffix)]
            break
    before = segments[:-1]
    if action in _LOGIN_SEGMENTS:
        pass
    elif action in _PASSWORD_ACTIONS:
        if not before or before[-1] != "password":
            return False
    elif action in _TOKEN_SEGMENTS:
        # One provider segment may sit before a callback: /admin/auth/google/callback.
        if action == "callback" and len(before) >= 2 and before[-2] in _AUTH_SEGMENTS:
            if _PLAIN_SEGMENT_RE.fullmatch(before[-1]) is None:
                return False
            before = before[:-1]
        if not any(seg in _AUTH_SEGMENTS for seg in before):
            return False
    else:
        return False
    return all(_prefix_segment(seg) for seg in before)


def _auth_hints_for_route(
    route: Route,
    scan_auth_hints: list[AuthHint],
    hints_by_file: dict[str, list[AuthHint]],
) -> list[str]:
    """Return the auth-hint strings that plausibly attach to `route`.

    If the route has a known `line`, only hints in the same file whose
    line falls within `_ROUTE_AUTH_LINE_WINDOW` above OR below the
    route are counted. If the route lacks line info (framework
    config-driven routes commonly do), fall back to file-scoped
    attribution — same as the old behavior.

    Deliberately no global fallback: the "if no hints in this file,
    inherit every auth hint in the repo" behavior was the biggest
    noise source per FINDINGS §55. Downstream code handles empty
    auth_signals correctly.
    """
    file_hints = hints_by_file.get(route.file, [])
    if not file_hints:
        return []
    if route.line is None:
        return sorted({hint.hint for hint in file_hints})
    lo = route.line - _ROUTE_AUTH_LINE_WINDOW
    hi = route.line + _ROUTE_AUTH_LINE_WINDOW
    windowed = {
        hint.hint
        for hint in file_hints
        if hint.line is None or lo <= hint.line <= hi
    }
    if windowed:
        return sorted(windowed)
    # Hints exist in the file but none are within the window. That's the
    # signal-to-noise fix: the previous route in this file had auth code,
    # this one doesn't. Return empty — the surface's rationale below will
    # say "no auth indicators near this route".
    return []


def identify_attack_surfaces(scan: ScanResult) -> list[AttackSurface]:
    surfaces: list[AttackSurface] = []
    auth_hints_by_file: dict[str, list[AuthHint]] = {}
    for hint in scan.auth_hints:
        auth_hints_by_file.setdefault(hint.file, []).append(hint)

    supporting_hints_by_file: dict[str, set[str]] = {}
    all_supporting_hints = [
        *scan.auth_hints,
        *scan.service_hints,
        *scan.edge_hints,
        *scan.entrypoint_hints,
        *scan.protocol_hints,
        *scan.framework_hints,
    ]

    for hint in all_supporting_hints:
        supporting_hints_by_file.setdefault(hint.file, set()).add(hint.hint)

    management = webhook_management_routes(scan)
    management_surfaces: list[tuple[AttackSurface, str]] = []

    for route in scan.routes:
        path_lower = route.path.lower()
        management_reason = management.get((route.method, route.path, route.file))
        # A plugin-declared route auth state (#256) beats the ±40-line file
        # window, which lets a route inherit its neighbour's guard.
        if route.auth == "required":
            auth_signals = sorted(set(route.guards)) or ["plugin_declared_auth"]
        elif route.auth == "anonymous":
            auth_signals = []
        else:
            auth_signals = _auth_hints_for_route(route, scan.auth_hints, auth_hints_by_file)
        supporting_signals = sorted(supporting_hints_by_file.get(route.file, set())) or sorted(
            {hint.hint for hint in all_supporting_hints}
        )
        rationale: list[str] = []
        exposure: AttackSurface["exposure"] = "public"
        internal_handler_markers = {
            "handler_visibility:internal",
            "handler_type:internal_handler",
            "service_role:worker",
            "service_role:event_consumer",
            "service_role:internal_handler",
        }
        has_explicit_public_visibility = "handler_visibility:public" in supporting_signals
        has_internal_handler_hint = any(marker in supporting_signals for marker in internal_handler_markers) and not has_explicit_public_visibility

        admin_path = any(segment in path_lower for segment in ("/admin", "/manage", "/root"))
        if management_reason is not None:
            # CRUD for the app's own outgoing webhooks is an ordinary route (#365).
            rationale.append(
                f"Manages the application's own webhook configuration ({management_reason}); "
                "not an inbound event receiver."
            )
        if "webhook" in path_lower and management_reason is None:
            category = "webhook"
            risk = "high"
            rationale.append("Webhook endpoints commonly accept attacker-controlled input from the internet.")
        elif admin_path and not is_auth_entry_point(path_lower):
            category = "admin"
            risk = "high"
            rationale.append("Administrative routes are high-value targets because they expose privileged actions.")
        elif admin_path or is_auth_path(route.path):  # an admin path here is its login/logout/token endpoint (#328)
            category = "auth"
            risk = "high" if not auth_signals else "medium"
            rationale.append("Authentication endpoints are common targets for brute force, token abuse, and session attacks.")
        elif any(segment in path_lower for segment in ("/upload", "/import", "/file")):
            category = "upload"
            risk = "high"
            rationale.append("Upload and import flows often lead to parser abuse or untrusted file handling.")
        elif any(segment in path_lower for segment in ("/internal", "/debug")):
            category = "internal"
            exposure = "internal"
            risk = "medium"
            rationale.append("Internal or debug routes are risky if they become reachable from untrusted networks.")
        elif any(segment in path_lower for segment in ("/health", "/ready", "/live", "/metrics")):
            category = "health"
            risk = "low"
            rationale.append("Operational endpoints reveal limited attack surface but may disclose useful reconnaissance details.")
        else:
            category = "public_api"
            risk = "medium" if scan.databases or scan.external_calls else "low"
            rationale.append("Public application routes are initial footholds for probing input handling and authorization gaps.")

        if has_internal_handler_hint and category not in {"admin", "auth", "webhook"}:
            exposure = "internal"
            if category == "public_api":
                category = "internal"
            risk = "medium" if category != "health" else "low"
            rationale.append("Service-level handler metadata suggests this route is internal-facing (worker/event/internal handler path).")

        if auth_signals:
            rationale.append(f"Auth indicators observed: {', '.join(auth_signals)}.")
        else:
            rationale.append("No auth indicators were observed near this route.")

        if scan.databases:
            rationale.append("Datastore usage was detected elsewhere in the repository, so route-to-data flows are plausible.")
        if scan.external_calls:
            rationale.append("Outbound HTTP calls were detected, creating trust boundaries to third-party systems.")

        surface = AttackSurface(
            route=route.path,
            method=route.method,
            file=route.file,
            line=route.line,
            category=category,
            exposure=exposure,
            risk=risk,
            auth_signals=auth_signals,
            data_store_interaction=bool(scan.databases),
            outbound_integration=bool(scan.external_calls),
            rationale=rationale,
            )
        surfaces.append(surface)
        if management_reason is not None:
            management_surfaces.append((surface, category))

    # Precision first: a management candidate whose handler reaches signature
    # verification is a receiver after all.
    for surface in reclaim_receivers(scan, [s for s, _ in management_surfaces]):
        surface.category = "webhook"
        surface.risk = "high"
        surface.exposure = "public"
        surface.rationale = [
            r for r in surface.rationale if not r.startswith("Manages the application's own webhook")
        ]
        surface.rationale.insert(0, "Webhook endpoints commonly accept attacker-controlled input from the internet.")

    assess_webhook_surfaces(scan, surfaces)
    return surfaces


def summarize_architecture(scan: ScanResult, graph: nx.DiGraph) -> str:
    route_count = len(scan.routes)
    dbs = sorted({db.kind for db in scan.databases})
    external_targets = sorted({call.target for call in scan.external_calls})
    auth_summary = sorted({hint.hint for hint in scan.auth_hints})
    secret_count = len(scan.secret_hints)
    graph_edges = sorted(
        f"{source} -> {target} ({data['relation']})"
        for source, target, data in graph.edges(data=True)
        if "relation" in data
    )

    lines = [
        "# Architecture Summary",
        "",
        "## Overview",
        f"- AttackMap inferred a {'web-facing' if route_count else 'non-web'} repository with {route_count} entry point{'s' if route_count != 1 else ''}.",
        f"- Files scanned: {scan.files_scanned}",
        f"- Languages detected: {', '.join(scan.languages) if scan.languages else 'none'}",
        f"- Inferred entry points: {route_count}",
        f"- Datastores detected: {', '.join(dbs) if dbs else 'none'}",
        f"- External targets detected: {', '.join(external_targets) if external_targets else 'none'}",
        f"- Auth hints observed: {', '.join(auth_summary) if auth_summary else 'none'}",
        f"- Secret-like env references: {secret_count}",
    ]

    if scan.routes:
        common = Counter(route.file for route in scan.routes).most_common(3)
        lines.extend(
            [
                "",
                "## Entry Point Concentration",
                *[f"- {file}: {count} routes" for file, count in common],
            ]
        )
        busiest_file, busiest_count = common[0]
        lines.extend(
            [
                "",
                "## Likely Review Starting Point",
                f"- Start with `{busiest_file}`. It contains {busiest_count} of the detected routes and is the fastest place to validate exposure and trust boundaries.",
            ]
        )

    if graph_edges:
        lines.extend(
            [
                "",
                "## Inferred Trust Boundaries",
                *[f"- {edge}" for edge in graph_edges[:10]],
            ]
        )

    lines.extend(
        [
            "",
            "## Analyst Notes",
            "- AttackMap inferred this system shape heuristically from framework patterns, dependencies, and code hints.",
            "- Treat this as an initial map for security review, then validate the highest-risk routes and boundaries manually.",
        ]
    )

    return "\n".join(lines)


def _risk_rank(value: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(value, 3)


def _surface_summary(surface: AttackSurface) -> str:
    traits: list[str] = []
    if surface.auth_signals:
        traits.append(f"auth signals: {', '.join(surface.auth_signals)}")
    else:
        traits.append("no auth signals observed")

    if surface.data_store_interaction:
        traits.append("data store reachable")
    if surface.outbound_integration:
        traits.append("external trust boundary")
    if surface.webhook_verification is not None:
        traits.append(f"webhook signature: {surface.webhook_verification.state.replace('_', ' ')}")

    return "; ".join(traits)


def summarize_attack_surface(scan: ScanResult, attack_surfaces: list[AttackSurface] | None = None) -> str:
    surfaces = attack_surfaces if attack_surfaces is not None else identify_attack_surfaces(scan)
    ordered_surfaces = sorted(surfaces, key=lambda surface: (_risk_rank(surface.risk), surface.route, surface.method))
    external_targets = sorted({call.target for call in scan.external_calls})
    auth_summary = sorted({a.hint for a in scan.auth_hints})
    high_risk = [surface for surface in ordered_surfaces if surface.risk == "high"]
    auth_and_admin = [surface for surface in ordered_surfaces if surface.category in {"auth", "admin"}]
    public_entry_points = [surface for surface in ordered_surfaces if surface.exposure == "public" and surface.category not in {"auth", "admin", "health"}]
    operational_routes = [surface for surface in ordered_surfaces if surface.category in {"health", "internal"}]

    lines = [
        "# Attack Surface",
        "",
        "## Priority View",
        f"- High-risk entry points: {len(high_risk)}",
        f"- Public routes detected: {sum(1 for surface in ordered_surfaces if surface.exposure == 'public')}",
        f"- Internal-only routes detected: {sum(1 for surface in ordered_surfaces if surface.exposure == 'internal')}",
        f"- Routes with likely data access: {sum(1 for surface in ordered_surfaces if surface.data_store_interaction)}",
        f"- Routes with outbound trust boundaries: {sum(1 for surface in ordered_surfaces if surface.outbound_integration)}",
    ]

    lines.extend(["", "## Highest-Risk Entry Points"])
    if high_risk:
        for surface in high_risk[:10]:
            lines.append(
                f"- {surface.method} {surface.route} ({surface.file}) -> {surface.category}; {_surface_summary(surface)}"
            )
    else:
        lines.append("- No high-risk entry points were classified")

    lines.extend(["", "## Auth And Privileged Routes"])
    if auth_and_admin:
        for surface in auth_and_admin[:10]:
            lines.append(
                f"- [{surface.risk.upper()}] {surface.method} {surface.route} "
                f"({surface.file}) -> {surface.category}, {surface.exposure}; {_surface_summary(surface)}"
            )
    else:
        lines.append("- No dedicated auth or admin routes were classified")

    lines.extend(["", "## Public Application Routes"])
    if public_entry_points:
        for surface in public_entry_points[:10]:
            lines.append(
                f"- [{surface.risk.upper()}] {surface.method} {surface.route} "
                f"({surface.file}) -> {surface.category}, {surface.exposure}; {_surface_summary(surface)}"
            )
    else:
        lines.append("- No additional public application routes were classified")

    lines.extend(["", "## Operational And Internal Routes"])
    if operational_routes:
        for surface in operational_routes[:10]:
            lines.append(
                f"- [{surface.risk.upper()}] {surface.method} {surface.route} "
                f"({surface.file}) -> {surface.category}, {surface.exposure}; {_surface_summary(surface)}"
            )
    else:
        lines.append("- No health, metrics, debug, or internal routes were classified")

    lines.extend(["", "## External Dependencies"])
    if external_targets:
        for target in external_targets[:25]:
            lines.append(f"- {target}")
    else:
        lines.append("- No explicit outbound HTTP calls detected")

    lines.extend(["", "## Secrets And Auth Hints"])
    if scan.secret_hints:
        for hint in scan.secret_hints[:25]:
            lines.append(f"- Secret-related env usage: {hint.name} ({hint.file})")
    else:
        lines.append("- No secret-like environment variable usage detected")

    if auth_summary:
        lines.append(f"- Auth-related keywords observed: {', '.join(auth_summary)}")
    else:
        lines.append("- No auth-related keywords observed")

    return "\n".join(lines)
