"""Built-in / plugin route twins (#337).

Core's built-in extractors read one registration call at a time. A plugin
that joins group prefixes (`api := r.Group("/api")`) or parses a route
pattern emits the same registration under another path, and the
`(path, method, file)` merge key kept both: every prefixed route had an
unprefixed twin, which lost the plugin's auth and showed up as a separate,
wrong surface. A plugin route on the same (file, line) now supersedes a
built-in route that is plausibly the same registration.
"""

from __future__ import annotations

import time
from pathlib import Path

from attackmap.analyzer import identify_attack_surfaces
from attackmap.analyzers import (
    BUILTIN_ANALYZER_NAMES,
    DefaultAnalyzer,
    analyze_repository,
    merge_analyzer_results,
)
from attackmap.merge import superseded_builtin_routes
from attackmap.route_auth_fusion import unauthenticated_routes
from attackmap.sdk import AnalyzerMetadata, AnalyzerResult, Route


def _route(path: str, method: str, source: str, *, line: int | None = 10, file: str = "routes.go", **kw) -> Route:
    route = Route(path=path, method=method, file=file, line=line, **kw)
    route.source_analyzer = source
    return route


def _merge(*groups: list[Route]) -> list[tuple[str, str, int | None, str | None, str]]:
    merged = merge_analyzer_results([AnalyzerResult(root=".", routes=list(g)) for g in groups], root=".")
    return [(r.method, r.path, r.line, r.source_analyzer, r.auth) for r in merged.routes]


def test_builtin_names_are_the_core_analyzers() -> None:
    assert BUILTIN_ANALYZER_NAMES == {"python-web", "javascript-web", "config", "default"}


def test_plugin_route_with_joined_prefix_replaces_builtin_twin() -> None:
    builtin = [_route("/reset", "POST", "default")]
    plugin = [_route("/admin/reset", "POST", "go", auth="required", guards=["AuthRequired"])]
    expected = [("POST", "/admin/reset", 10, "go", "required")]
    # Whichever runs first (built-ins and plugins share priorities).
    assert _merge(builtin, plugin) == expected
    assert _merge(plugin, builtin) == expected


def test_identical_route_keeps_plugin_provenance_and_auth() -> None:
    builtin = [_route("/users", "POST", "default")]
    plugin = [_route("/users", "POST", "go", auth="required", guards=["AuthRequired"], guard_evidence="r.Use(AuthRequired())")]
    merged = merge_analyzer_results(
        [AnalyzerResult(root=".", routes=builtin), AnalyzerResult(root=".", routes=plugin)], root="."
    )
    assert len(merged.routes) == 1
    route = merged.routes[0]
    assert route.source_analyzer == "go"
    assert (route.auth, route.guards, route.guard_evidence) == ("required", ["AuthRequired"], "r.Use(AuthRequired())")


def test_raw_pattern_and_any_method_builtins_are_twins() -> None:
    builtin = [
        _route("GET /items/{id}", "ANY", "default", line=3),
        _route("example.com/x", "ANY", "default", line=4),
        _route("/static/", "ANY", "default", line=5),
        _route("/", "GET", "default", line=6),
    ]
    plugin = [
        _route("/items/{id}", "GET", "go", line=3),
        _route("/x", "POST", "go", line=4),
        _route("/assets/static/", "GET", "go", line=5),
        _route("/api/ping/", "GET", "go", line=6),
    ]
    assert _merge(builtin, plugin) == [(r.method, r.path, r.line, "go", "unknown") for r in plugin]


def test_resource_line_keeps_every_plugin_route_and_drops_the_single_twin() -> None:
    """A Laravel `Route::resource` line legitimately yields several routes."""
    builtin = [_route("/photos", "GET", "default", file="routes/web.php")]
    plugin = [
        _route("/admin/photos", "GET", "php-web", file="routes/web.php"),
        _route("/admin/photos", "POST", "php-web", file="routes/web.php"),
        _route("/admin/photos/{photo}", "GET", "php-web", file="routes/web.php"),
        _route("/admin/photos/{photo}", "DELETE", "php-web", file="routes/web.php"),
    ]
    assert [(m, p) for m, p, *_ in _merge(builtin, plugin)] == [(r.method, r.path) for r in plugin]


def test_different_registrations_on_one_line_survive() -> None:
    builtin = [
        _route("/a", "GET", "default"),  # the plugin's /v1/a
        _route("/b", "GET", "default"),  # a second call the plugin didn't read
        _route("/reset", "POST", "default"),  # same path, other method
        _route("/reset", "GET", "default", line=11),  # segment boundary: /xreset isn't /reset
    ]
    plugin = [
        _route("/v1/a", "GET", "go"),
        _route("/v1/reset", "PUT", "go"),
        _route("/v1/xreset", "GET", "go", line=11),
    ]
    merged = _merge(builtin, plugin)
    assert ("GET", "/a", 10, "default", "unknown") not in merged
    assert ("GET", "/b", 10, "default", "unknown") in merged
    assert ("POST", "/reset", 10, "default", "unknown") in merged
    assert ("GET", "/reset", 11, "default", "unknown") in merged
    assert len(merged) == 6


def test_plugin_and_builtin_routes_never_collapse_among_themselves() -> None:
    plugins = [_route("/a", "GET", "go"), _route("/x/a", "GET", "go"), _route("/a", "GET", "node-service")]
    builtins = [_route("/a", "GET", "default"), _route("/x/a", "GET", "javascript-web")]
    # Two plugin routes ending in the same path both stay; the built-ins go.
    assert [(p, s) for _, p, _, s, _ in _merge(plugins, builtins)] == [("/a", "go"), ("/x/a", "go")]
    # With no plugin route there, built-ins are untouched.
    assert len(_merge(builtins)) == 2


def test_only_same_file_and_line_with_known_provenance_match() -> None:
    builtin = [
        _route("/reset", "POST", "default", line=None),
        _route("/reset", "POST", "default", file="other.go"),
        _route("/reset", "POST", "default", file="third.go", line=11),
    ]
    plugin = [_route("/admin/reset", "POST", "go")]
    assert len(_merge(builtin, plugin)) == 4
    # Results that were never stamped (public merge API) are passthrough.
    unstamped = [Route(path="/reset", method="POST", file="routes.go", line=10)]
    unstamped_plugin = [Route(path="/admin/reset", method="POST", file="routes.go", line=10)]
    assert len(_merge(unstamped, unstamped_plugin)) == 2


def test_twin_matching_is_linear_on_crowded_lines() -> None:
    builtin = [_route(f"/r{i}", "GET", "default", line=i % 50) for i in range(20000)]
    plugin = [_route(f"/api/r{i}", "GET", "go", line=i % 50) for i in range(0, 20000, 400)]
    start = time.monotonic()
    superseded = superseded_builtin_routes([*builtin, *plugin], BUILTIN_ANALYZER_NAMES)
    assert time.monotonic() - start < 10
    assert len(superseded) == 50
    long_raw = _route("GET " + "a" * 100000 + "/x", "ANY", "default", line=1)
    start = time.monotonic()
    superseded_builtin_routes([long_raw, _route("/x", "GET", "go", line=1)], BUILTIN_ANALYZER_NAMES)
    assert time.monotonic() - start < 1


class _GroupPrefixPlugin:
    """Stands in for a plugin that joins `r.Group("/api", AuthRequired())`."""

    metadata = AnalyzerMetadata(name="go-like")

    @property
    def name(self) -> str:
        return self.metadata.name

    def detect(self, root: str | Path) -> bool:
        return True

    def analyze(self, root: str | Path) -> AnalyzerResult:
        return AnalyzerResult(
            root=str(root),
            routes=[
                Route(
                    path="/api/users", method="POST", file="main.go", line=8,
                    auth="required", guards=["AuthRequired"], guard_evidence='r.Group("/api", AuthRequired())',
                )
            ],
        )


def test_guarded_group_route_is_not_flagged_through_its_twin(tmp_path: Path) -> None:
    """End to end: core's built-in Go extractor sees `api.POST("/users", h)` as
    `POST /users` with no auth; before #337 that twin was flagged
    unauth-state-change while the plugin's guarded route wasn't."""
    (tmp_path / "main.go").write_text(
        'package main\n\nimport "github.com/gin-gonic/gin"\n\n'
        "func main() {\n"
        "\tr := gin.Default()\n"
        '\tapi := r.Group("/api", AuthRequired())\n'
        '\tapi.POST("/users", createUser)\n'
        "}\n",
        encoding="utf-8",
    )
    scan = analyze_repository(tmp_path, analyzers=[DefaultAnalyzer(), _GroupPrefixPlugin()])
    assert [(r.method, r.path, r.source_analyzer, r.auth) for r in scan.routes] == [
        ("POST", "/api/users", "go-like", "required")
    ]
    assert unauthenticated_routes(scan, identify_attack_surfaces(scan)) == []
