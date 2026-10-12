"""Built-in / plugin route twins (#337).

Core's built-in extractors read one registration call at a time. A plugin
that joins group prefixes (`api := r.Group("/api")`) emits the same
registration under a longer path, and the `(path, method, file)` merge key
kept both: every prefixed route had an unprefixed twin, which lost the
plugin's auth and showed up as a separate, wrong surface. A plugin route on
the same (file, line) now supersedes a built-in route that is plausibly the
same registration.
"""

from __future__ import annotations

import time
from pathlib import Path

from attackmap.analyzer import identify_attack_surfaces
from attackmap.analyzers import (
    BuiltinJavaScriptWebAnalyzer,
    BuiltinPythonWebAnalyzer,
    DefaultAnalyzer,
    analyze_repository,
    is_builtin_analyzer,
    merge_analyzer_results,
)
from attackmap.merge import superseded_builtin_routes
from attackmap.route_auth_fusion import unauthenticated_routes
from attackmap.sdk import AnalyzerMetadata, AnalyzerResult, Route


def _route(path: str, method: str, source: str, *, line: int | None = 10, file: str = "routes.go", **kw) -> Route:
    route = Route(path=path, method=method, file=file, line=line, **kw)
    route.source_analyzer = source
    return route


def _merge(builtin: list[Route], plugin: list[Route], *, plugin_first: bool = False) -> list[tuple]:
    groups = [(plugin, False), (builtin, True)] if plugin_first else [(builtin, True), (plugin, False)]
    merged = merge_analyzer_results(
        [AnalyzerResult(root=".", routes=list(routes)) for routes, _ in groups],
        root=".",
        builtin=[flag for _, flag in groups],
    )
    return [(r.method, r.path, r.line, r.source_analyzer, r.auth) for r in merged.routes]


def test_builtin_is_decided_by_analyzer_type() -> None:
    assert all(is_builtin_analyzer(a) for a in (DefaultAnalyzer(), BuiltinPythonWebAnalyzer(), BuiltinJavaScriptWebAnalyzer()))
    assert not is_builtin_analyzer(_PrefixPlugin([]))


def test_plugin_route_with_joined_prefix_replaces_builtin_twin() -> None:
    builtin = [_route("/reset", "POST", "default")]
    plugin = [_route("/admin/reset", "POST", "go", auth="required", guards=["AuthRequired"])]
    expected = [("POST", "/admin/reset", 10, "go", "required")]
    # Whichever runs first (built-ins and plugins share priorities).
    assert _merge(builtin, plugin) == expected
    assert _merge(builtin, plugin, plugin_first=True) == expected


def test_identical_route_keeps_plugin_provenance_and_auth() -> None:
    builtin = [_route("/users", "POST", "default")]
    plugin = [_route("/users", "POST", "go", auth="required", guards=["AuthRequired"], guard_evidence="r.Use(AuthRequired())")]
    merged = merge_analyzer_results(
        [AnalyzerResult(root=".", routes=builtin), AnalyzerResult(root=".", routes=plugin)], root=".", builtin=[True, False]
    )
    assert len(merged.routes) == 1
    route = merged.routes[0]
    assert route.source_analyzer == "go"
    assert (route.auth, route.guards, route.guard_evidence) == ("required", ["AuthRequired"], "r.Use(AuthRequired())")


def test_plugin_cannot_claim_to_be_builtin() -> None:
    """Provenance a plugin pre-stamps doesn't make its routes droppable."""
    spoofed = [_route("/reset", "POST", "default")]  # really from a plugin
    plugin = [_route("/admin/reset", "POST", "go")]
    merged = merge_analyzer_results(
        [AnalyzerResult(root=".", routes=spoofed), AnalyzerResult(root=".", routes=plugin)], root=".", builtin=[False, False]
    )
    assert len(merged.routes) == 2
    # Without flags (the public merge API), routes merge on their key alone.
    assert len(merge_analyzer_results(
        [AnalyzerResult(root=".", routes=[_route("/reset", "POST", "default")]), AnalyzerResult(root=".", routes=plugin)]
    ).routes) == 2


def test_any_builtin_and_parameter_syntax() -> None:
    builtin = [
        _route("/static/", "ANY", "default", line=5),
        _route("/users/:id", "PUT", "javascript-web", line=6),
        _route("/items/<int:item_id>", "GET", "python-web", line=7),
    ]
    plugin = [
        _route("/assets/static/", "GET", "go", line=5),
        _route("/api/users/{id}", "PUT", "node-service", line=6),
        _route("/v1/items/{item_id}", "GET", "python", line=7),
    ]
    assert _merge(builtin, plugin) == [(r.method, r.path, r.line, r.source_analyzer, "unknown") for r in plugin]


def test_plugin_any_does_not_replace_a_specific_builtin_method() -> None:
    """The built-in's method would be lost, so both stay."""
    builtin = [_route("/reset", "POST", "default")]
    plugin = [_route("/admin/reset", "ANY", "go")]
    assert len(_merge(builtin, plugin)) == 2


def test_plugin_route_on_a_different_line_is_not_a_twin() -> None:
    """Multi-line registrations can be reported on different lines; without
    the same (file, line) a twin can't be told from a second registration."""
    builtin = [_route("/reset", "POST", "default", line=10)]
    plugin = [_route("/admin/reset", "POST", "go", line=11)]
    assert len(_merge(builtin, plugin)) == 2


def test_root_only_matches_a_root_or_a_lone_pair() -> None:
    # `app.get('/', a); app.get('/health', b)` on one line: the root survives.
    builtin = [_route("/", "GET", "javascript-web"), _route("/health", "GET", "javascript-web")]
    plugin = [_route("/health", "GET", "node-service"), _route("/v2/health", "GET", "node-service")]
    merged = _merge(builtin, plugin)
    assert ("GET", "/", 10, "javascript-web", "unknown") in merged
    assert ("GET", "/health", 10, "node-service", "unknown") in merged
    # One route of each kind on the line: the root is the plugin's route.
    assert _merge([_route("/", "GET", "default", line=6)], [_route("/api/ping/", "GET", "go", line=6)]) == [
        ("GET", "/api/ping/", 6, "go", "unknown")
    ]
    # A plugin root matches a built-in root among several routes.
    builtin = [_route("/", "GET", "default"), _route("/b", "GET", "default")]
    plugin = [_route("//", "GET", "go"), _route("/x/c", "GET", "go")]
    assert [p for _, p, *_ in _merge(builtin, plugin)] == ["/b", "//", "/x/c"]


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
        _route("/reset", "GET", "default", file="x.go", line=11),  # segment boundary: /xreset isn't /reset
        _route("users/:id", "GET", "javascript-web", file="y.js"),  # relative paths aren't host + path
    ]
    plugin = [
        _route("/v1/a", "GET", "go"),
        _route("/v1/reset", "PUT", "go"),
        _route("/v1/xreset", "GET", "go", file="x.go", line=11),
        _route("/other/:id", "GET", "node-service", file="y.js"),
    ]
    merged = _merge(builtin, plugin)
    assert ("GET", "/a", 10, "default", "unknown") not in merged
    for kept in (("GET", "/b", 10), ("POST", "/reset", 10), ("GET", "/reset", 11), ("GET", "users/:id", 10)):
        assert any(m[:3] == kept for m in merged), kept
    assert len(merged) == 8


def test_plugin_and_builtin_routes_never_collapse_among_themselves() -> None:
    plugins = [_route("/a", "GET", "go"), _route("/x/a", "GET", "go"), _route("/a", "GET", "node-service")]
    builtins = [_route("/a", "GET", "default"), _route("/x/a", "GET", "javascript-web")]
    merged = _merge(builtins, plugins, plugin_first=True)
    # Two plugin routes ending in the same path both stay; the built-ins go.
    assert [(p, s) for _, p, _, s, _ in merged] == [("/a", "go"), ("/x/a", "go")]
    # With no plugin route there, built-ins are untouched.
    assert len(_merge(builtins, [])) == 2


def test_only_same_file_and_line_match() -> None:
    builtin = [
        _route("/reset", "POST", "default", line=None),
        _route("/reset", "POST", "default", file="other.go"),
        _route("/reset", "POST", "default", file="third.go", line=11),
    ]
    plugin = [_route("/admin/reset", "POST", "go")]
    assert len(_merge(builtin, plugin)) == 4


def _crowded(n: int) -> tuple[list[Route], list[Route]]:
    """n routes of each kind on one line: flat paths, deep paths, roots."""
    builtin = [_route(f"/r{i}/x", "GET", "default", line=1) for i in range(n)]
    builtin += [_route("/" + "/".join(f"s{j}" for j in range(i % 40)), "ANY", "default", line=1) for i in range(n)]
    plugin = [_route(f"/api/r{i}/x", "GET", "go", line=1) for i in range(n)]
    plugin += [_route("/p/" + "/".join(f"s{j}" for j in range(40)) + f"/{i}", "GET", "go", line=1) for i in range(n)]
    return builtin, plugin


def _best_time(builtin: list[Route], plugin: list[Route]) -> float:
    best = float("inf")
    for _ in range(3):
        start = time.perf_counter()
        superseded_builtin_routes(builtin, plugin)
        best = min(best, time.perf_counter() - start)
    return best


def test_twin_matching_is_linear_on_crowded_lines() -> None:
    """Thousands of routes of both kinds on one line. Measured as a ratio
    (4x the input must cost well under 16x, which quadratic would), so a
    slow runner doesn't matter."""
    small, large = _crowded(500), _crowded(2000)
    assert len(superseded_builtin_routes(*large)) == 2000  # the flat twins; deep paths and roots aren't
    ratio = _best_time(*large) / max(_best_time(*small), 1e-6)
    assert ratio < 8, ratio


class _PrefixPlugin:
    """Stands in for a plugin that joins a prefix core's built-in can't see."""

    metadata = AnalyzerMetadata(name="prefix-plugin")

    def __init__(self, routes: list[Route]) -> None:
        self._routes = routes

    @property
    def name(self) -> str:
        return self.metadata.name

    def detect(self, root: str | Path) -> bool:
        return True

    def analyze(self, root: str | Path) -> AnalyzerResult:
        return AnalyzerResult(root=str(root), routes=[r.model_copy() for r in self._routes])


def _scan(tmp_path: Path, files: dict[str, str], builtin, routes: list[Route]):
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    scan = analyze_repository(tmp_path, analyzers=[builtin, _PrefixPlugin(routes)])
    return scan, sorted((r.method, r.path, r.file, r.source_analyzer, r.auth) for r in scan.routes)


def test_go_group_route_is_not_flagged_through_its_twin(tmp_path: Path) -> None:
    """Core's built-in Go extractor sees `api.POST("/users", h)` as an
    unguarded `POST /users`; before #337 that twin was flagged
    unauth-state-change while the plugin's guarded route wasn't."""
    scan, routes = _scan(
        tmp_path,
        {
            "main.go": 'package main\n\nimport "github.com/gin-gonic/gin"\n\n'
            "func main() {\n"
            "\tr := gin.Default()\n"
            '\tapi := r.Group("/api", AuthRequired())\n'
            '\tapi.POST("/users", createUser)\n'
            "}\n"
        },
        DefaultAnalyzer(),
        [Route(path="/api/users", method="POST", file="main.go", line=8, auth="required", guards=["AuthRequired"])],
    )
    assert routes == [("POST", "/api/users", "main.go", "prefix-plugin", "required")]
    assert unauthenticated_routes(scan, identify_attack_surfaces(scan)) == []


def test_express_router_mounted_with_use_prefix(tmp_path: Path) -> None:
    """javascript-web reads `router.post('/users/:id')`; the mount
    `app.use('/api', require('./routes'))` is in another file."""
    _, routes = _scan(
        tmp_path,
        {
            "routes.js": "const express = require('express')\n"
            "const router = express.Router()\n"
            "router.post('/users/:id', updateUser)\n"
            "router.get('/', listUsers)\n"
            "module.exports = router\n",
            "app.js": "const express = require('express')\nconst app = express()\napp.use('/api', require('./routes'))\n",
        },
        BuiltinJavaScriptWebAnalyzer(),
        [
            Route(path="/api/users/{id}", method="POST", file="routes.js", line=3, auth="required", guards=["requireAuth"]),
            Route(path="/api", method="GET", file="routes.js", line=4),
        ],
    )
    assert routes == [
        ("GET", "/api", "routes.js", "prefix-plugin", "unknown"),
        ("POST", "/api/users/{id}", "routes.js", "prefix-plugin", "required"),
    ]


def test_flask_blueprint_and_fastapi_router_prefixes(tmp_path: Path) -> None:
    """python-web reads the Blueprint / APIRouter routes; their prefixes are
    set where they're registered, in another file."""
    _, routes = _scan(
        tmp_path,
        {
            "views.py": 'from flask import Blueprint\nbp = Blueprint("admin", __name__)\n\n'
            '@bp.route("/reset", methods=["POST"])\ndef reset():\n    return ""\n',
            "app.py": 'from flask import Flask\nfrom views import bp\napp = Flask(__name__)\n'
            'app.register_blueprint(bp, url_prefix="/admin")\n',
            "api.py": "from fastapi import APIRouter\nrouter = APIRouter()\n\n"
            '@router.delete("/items/{item_id}")\ndef delete_item(item_id: int):\n    return {}\n',
        },
        BuiltinPythonWebAnalyzer(),
        [
            Route(path="/admin/reset", method="POST", file="views.py", line=4, auth="required", guards=["login_required"]),
            Route(path="/v1/items/{item_id}", method="DELETE", file="api.py", line=4),
        ],
    )
    assert routes == [
        ("DELETE", "/v1/items/{item_id}", "api.py", "prefix-plugin", "unknown"),
        ("POST", "/admin/reset", "views.py", "prefix-plugin", "required"),
    ]
