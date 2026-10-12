"""Auth-route classification and `weak-auth-route` per surface (#340)."""

from __future__ import annotations

import pytest

from attackmap.analyzer import identify_attack_surfaces, is_auth_path
from attackmap.models import Route, ScanResult
from attackmap.threat_model import generate_findings


@pytest.mark.parametrize(
    "path",
    [
        "/auth", "/api/auth/login", "/login", "/login-form", "/api/authenticate", "/api/authorize",
        "/oauth2/callback", "/api/sessions", "/tokens/refresh", "/authCallback", "/auth_callback",
        "/signin", "/signup", "/x/auth.json",
    ],
)
def test_auth_paths(path: str) -> None:
    assert is_auth_path(path)


@pytest.mark.parametrize(
    "path",
    [
        "/api/authorities", "/api/authorities/{id}", "/authors", "/api/authors/:id", "/v1/tokenizer",
        "/sessionstorage", "/reset/:token", "/reset/{token}", "/oauthors", "/", "",
    ],
)
def test_not_auth_paths(path: str) -> None:
    assert not is_auth_path(path)


def _weak_auth(routes: list[Route]):
    scan = ScanResult(root=".", routes=routes)
    findings = generate_findings(scan, identify_attack_surfaces(scan))
    return [f for f in findings if f.rule_id == "weak-auth-route"]


def test_authorities_crud_is_not_an_auth_route() -> None:
    scan = ScanResult(root=".", routes=[Route(path="/api/authorities", method="GET", file="AuthorityResource.java")])
    [surface] = identify_attack_surfaces(scan)
    assert surface.category != "auth"
    assert _weak_auth(scan.routes) == []


def test_a_guarded_auth_route_does_not_hide_the_others() -> None:
    # jhipster shape: the plugin marks one auth-category route as guarded;
    # the login endpoint must still be reported.
    routes = [
        Route(path="/api/auth/me", method="GET", file="a.java", auth="required", guards=["@PreAuthorize"]),
        Route(path="/api/authenticate", method="POST", file="b.java", auth="anonymous"),
    ]
    [finding] = _weak_auth(routes)
    assert [loc.file for loc in finding.locations] == ["b.java"]
    assert all("/api/authenticate" in line for line in finding.evidence)


def test_all_guarded_auth_routes_produce_no_finding() -> None:
    routes = [Route(path="/api/auth/me", method="GET", file="a.java", auth="required", guards=["@PreAuthorize"])]
    assert _weak_auth(routes) == []
