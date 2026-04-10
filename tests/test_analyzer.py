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
    assert "- Inferred entry points: 1" in summary
    assert "## Inferred Trust Boundaries" in summary
    assert "web -> postgresql (uses)" in summary
    assert "## Analyst Notes" in summary
