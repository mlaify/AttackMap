"""Plugin-declared route auth (#256): Route.auth / guards / guard_evidence."""

from __future__ import annotations

from pathlib import Path

from attackmap.analyzer import identify_attack_surfaces
from attackmap.analyzers import merge_analyzer_results
from attackmap.models import AuthHint, Route, ScanResult
from attackmap.route_auth_fusion import synthesize_unauthenticated_routes
from attackmap.sdk import Route as SdkRoute

CS = """using Microsoft.AspNetCore.Authorization;
[ApiController]
[Route("api/admin")]
[Authorize]
public class AdminController : ControllerBase {
    [HttpPost("reset")]
    [AllowAnonymous]
    public IActionResult Reset() => Ok();

    [HttpPost("users")]
    public IActionResult Create() => Ok();
}
"""


def _scan(tmp_path: Path, routes: list[Route], auth_hints: list[AuthHint] | None = None) -> ScanResult:
    (tmp_path / "AdminController.cs").write_text(CS, encoding="utf-8")
    return ScanResult(root=str(tmp_path), routes=routes, auth_hints=auth_hints or [])


def _flagged(scan: ScanResult) -> list[str]:
    findings = synthesize_unauthenticated_routes(scan, identify_attack_surfaces(scan))
    return [f"{loc.file}:{loc.line}" for f in findings for loc in f.locations]


def test_sdk_route_exposes_optional_auth_fields() -> None:
    route = SdkRoute(path="/x", file="a.py")
    assert (route.auth, route.guards, route.guard_evidence) == ("unknown", [], None)


def test_declared_anonymous_cs_route_is_flagged_despite_file_level_authorize(tmp_path: Path) -> None:
    routes = [
        Route(path="/api/public/reset", method="POST", file="AdminController.cs", line=6,
              auth="anonymous", guard_evidence="[AllowAnonymous]"),
        Route(path="/api/public/users", method="POST", file="AdminController.cs", line=9,
              auth="required", guards=["[Authorize]"], guard_evidence="[Authorize] on AdminController"),
    ]
    scan = _scan(tmp_path, routes, [AuthHint(hint="authorize_attribute", file="AdminController.cs", line=4)])
    assert _flagged(scan) == ["AdminController.cs:6"]
    surfaces = {s.route: s for s in identify_attack_surfaces(scan)}
    assert surfaces["/api/public/reset"].auth_signals == []
    assert surfaces["/api/public/users"].auth_signals == ["[Authorize]"]


def test_unknown_cs_route_keeps_old_behavior_and_required_fixes_it(tmp_path: Path) -> None:
    # Core can't resolve C# guards, so an undeclared C# route is flagged even
    # when the class has [Authorize] — the pre-#256 behavior. Declaring
    # auth="required" is what clears it.
    route = Route(path="/api/public/users", method="POST", file="AdminController.cs", line=9)
    assert _flagged(_scan(tmp_path, [route])) == ["AdminController.cs:9"]
    declared = route.model_copy(update={"auth": "required", "guards": ["[Authorize]"]})
    assert _flagged(_scan(tmp_path, [declared])) == []


def test_merge_prefers_known_auth_over_unknown_duplicate() -> None:
    unknown = ScanResult(root="/r", routes=[Route(path="/a", method="POST", file="x.cs", line=3)])
    known = ScanResult(root="/r", routes=[Route(path="/a", method="POST", file="x.cs", line=3, auth="required",
                                                guards=["[Authorize]"], guard_evidence="[Authorize]")])
    merged = merge_analyzer_results([unknown, known], root="/r")
    assert len(merged.routes) == 1
    assert (merged.routes[0].auth, merged.routes[0].guards) == ("required", ["[Authorize]"])
    # A later unknown never downgrades a known state.
    merged = merge_analyzer_results([known, unknown], root="/r")
    assert merged.routes[0].auth == "required"


def test_guard_evidence_is_redacted() -> None:
    secret = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    route = Route(path="/a", file="a.cs", auth="required", guard_evidence=f'[ApiKey("{secret}")]')
    assert secret not in (route.guard_evidence or "")
