from pathlib import Path

import pytest

from attackmap.analyzer_contracts import normalize_analyzer_metadata
from attackmap.analyzers import (
    ANALYZER_ENTRYPOINT_GROUP,
    AnalyzerMetadata,
    AnalyzerResult,
    BuiltinJavaScriptWebAnalyzer,
    BuiltinPythonWebAnalyzer,
    DefaultAnalyzer,
    analyze_repository,
    discover_installed_analyzers,
    get_analyzer_metadata,
    get_available_modules,
    get_available_repository_modules,
    get_builtin_repository_analyzers,
    get_registered_analyzers,
    merge_analyzer_results,
    select_requested_analyzers,
)
from attackmap.models import (
    AuthHint,
    EdgeHint,
    ExternalCall,
    FrameworkHint,
    ProtocolHint,
    Route,
    ScanResult,
    SecretHint,
    ServiceHint,
)


def test_analyzer_result_reuses_scan_result_shape() -> None:
    result = AnalyzerResult(root=".")

    assert isinstance(result, ScanResult)


def test_get_registered_analyzers_exposes_builtin_web_analyzers(monkeypatch) -> None:
    monkeypatch.setattr("attackmap.analyzers.discover_installed_analyzers", lambda: [])
    analyzers = get_registered_analyzers()

    assert len(analyzers) == 3
    assert isinstance(analyzers[0], BuiltinPythonWebAnalyzer)
    assert isinstance(analyzers[1], BuiltinJavaScriptWebAnalyzer)
    assert isinstance(analyzers[2], DefaultAnalyzer)
    assert [analyzer.name for analyzer in analyzers] == ["python-web", "javascript-web", "default"]


def test_get_builtin_repository_analyzers_contains_builtin_defaults() -> None:
    analyzers = get_builtin_repository_analyzers()

    assert len(analyzers) == 3
    assert [analyzer.name for analyzer in analyzers] == ["python-web", "javascript-web", "default"]


def test_discover_installed_analyzers_loads_valid_entrypoints_in_name_order(monkeypatch) -> None:
    class ExternalAnalyzerB:
        metadata = AnalyzerMetadata(
            name="external-b",
            description="external b",
            scope="external analyzer test",
            ecosystems=("php",),
        )

        @property
        def name(self) -> str:
            return "external-b"

        def analyze(self, root: str | Path) -> AnalyzerResult:
            return AnalyzerResult(root=str(root))

    class ExternalAnalyzerA:
        metadata = AnalyzerMetadata(
            name="external-a",
            description="external a",
            scope="external analyzer test",
            ecosystems=("php",),
        )

        @property
        def name(self) -> str:
            return "external-a"

        def analyze(self, root: str | Path) -> AnalyzerResult:
            return AnalyzerResult(root=str(root))

    class FakeEntryPoint:
        def __init__(self, name: str, value) -> None:
            self.name = name
            self._value = value

        def load(self):
            return self._value

    class FakeEntryPoints:
        def __init__(self, candidates) -> None:
            self._candidates = candidates

        def select(self, *, group: str):
            if group != ANALYZER_ENTRYPOINT_GROUP:
                return []
            return self._candidates

    fake_points = FakeEntryPoints(
        [
            FakeEntryPoint("php-web", ExternalAnalyzerB),
            FakeEntryPoint("aaa-web", ExternalAnalyzerA),
            FakeEntryPoint("broken", object()),
        ]
    )
    monkeypatch.setattr("attackmap.analyzers.entry_points", lambda: fake_points)

    analyzers = discover_installed_analyzers()

    assert [analyzer.name for analyzer in analyzers] == ["external-a", "external-b"]


def test_discover_installed_analyzers_includes_php_web_when_installed() -> None:
    pytest.importorskip("attackmap_analyzer_php_web")

    analyzers = discover_installed_analyzers()

    assert any(analyzer.name == "php-web" for analyzer in analyzers)


def test_select_requested_analyzers_matches_builtin_and_external_names(monkeypatch) -> None:
    class ExternalPhpAnalyzer:
        metadata = AnalyzerMetadata(
            name="php-web",
            description="php analyzer",
            scope="external test analyzer",
            ecosystems=("php",),
        )

        @property
        def name(self) -> str:
            return "php-web"

        def analyze(self, root: str | Path) -> AnalyzerResult:
            return AnalyzerResult(root=str(root))

    monkeypatch.setattr("attackmap.analyzers.get_registered_analyzers", lambda: [ExternalPhpAnalyzer()])

    selected = select_requested_analyzers(
        [
            "php-web",
            "attackmap-analyzer-php-web",
            "mlaify/attackmap-analyzer-php-web",
        ]
    )

    assert [analyzer.name for analyzer in selected] == ["php-web"]


def test_select_requested_analyzers_installs_missing_modules_when_enabled(monkeypatch) -> None:
    class ExternalPhpAnalyzer:
        metadata = AnalyzerMetadata(
            name="php-web",
            description="php analyzer",
            scope="external test analyzer",
            ecosystems=("php",),
        )

        @property
        def name(self) -> str:
            return "php-web"

        def analyze(self, root: str | Path) -> AnalyzerResult:
            return AnalyzerResult(root=str(root))

    calls: list[str] = []
    registry_state = {"ready": False}

    def fake_registry() -> list[object]:
        if registry_state["ready"]:
            return [ExternalPhpAnalyzer()]
        return []

    def fake_installer(repo_name: str) -> None:
        calls.append(repo_name)
        registry_state["ready"] = True

    monkeypatch.setattr("attackmap.analyzers.get_registered_analyzers", fake_registry)

    selected = select_requested_analyzers(["php-web"], auto_install=True, installer=fake_installer)

    assert calls == ["attackmap-analyzer-php-web"]
    assert [analyzer.name for analyzer in selected] == ["php-web"]


def test_select_requested_analyzers_errors_when_missing_without_install(monkeypatch) -> None:
    monkeypatch.setattr("attackmap.analyzers.get_registered_analyzers", lambda: [])

    with pytest.raises(ValueError, match="not available"):
        select_requested_analyzers(["php-web"], auto_install=False)


def test_get_registered_analyzers_skips_duplicate_names(monkeypatch) -> None:
    class DuplicatePythonAnalyzer:
        metadata = get_analyzer_metadata(BuiltinPythonWebAnalyzer())

        @property
        def name(self) -> str:
            return "python-web"

        def analyze(self, root: str | Path) -> AnalyzerResult:
            return AnalyzerResult(root=str(root))

    monkeypatch.setattr("attackmap.analyzers.discover_installed_analyzers", lambda: [DuplicatePythonAnalyzer()])

    analyzers = get_registered_analyzers()

    assert [analyzer.name for analyzer in analyzers] == ["python-web", "javascript-web", "default"]


def test_builtin_analyzers_expose_metadata() -> None:
    python_metadata = get_analyzer_metadata(BuiltinPythonWebAnalyzer())
    javascript_metadata = get_analyzer_metadata(BuiltinJavaScriptWebAnalyzer())
    default_metadata = get_analyzer_metadata(DefaultAnalyzer())

    assert python_metadata.name == "python-web"
    assert python_metadata.display_name == "Python Web Analyzer"
    assert python_metadata.version == "0.1.0"
    assert "Python web frameworks" in python_metadata.description
    assert python_metadata.scope.startswith("Python source files")
    assert python_metadata.ecosystems == ("python", "fastapi", "flask")
    assert python_metadata.enabled_by_default is True

    assert javascript_metadata.name == "javascript-web"
    assert javascript_metadata.display_name == "JavaScript Web Analyzer"
    assert "JavaScript web frameworks" in javascript_metadata.description
    assert javascript_metadata.ecosystems == ("javascript", "express", "node")
    assert javascript_metadata.enabled_by_default is True

    assert default_metadata.name == "default"
    assert default_metadata.display_name == "Default Analyzer"
    assert "Fallback" in default_metadata.description
    assert default_metadata.ecosystems == ("typescript",)
    assert default_metadata.enabled_by_default is True


def test_analyzer_metadata_remains_backward_compatible_with_legacy_ecosystems_input() -> None:
    metadata = AnalyzerMetadata(
        name="php-web",
        description="php analyzer",
        scope="legacy compatibility test",
        ecosystems=("php", "laminas"),
    )

    assert metadata.name == "php-web"
    assert metadata.display_name == "php-web"
    assert metadata.languages == ["php", "laminas"]
    assert metadata.ecosystems == ("php", "laminas")


def test_normalize_analyzer_metadata_preserves_rich_plugin_fields() -> None:
    metadata = normalize_analyzer_metadata(
        {
            "name": "node-service",
            "display_name": "Node Service Analyzer",
            "version": "1.2.3",
            "description": "Plugin metadata shape",
            "scope": "node service repos",
            "targets": ["node-service", "node"],
            "languages": ["typescript", "javascript"],
            "priority": 25,
            "experimental": False,
            "enabled_by_default": True,
        }
    )

    assert metadata.name == "node-service"
    assert metadata.display_name == "Node Service Analyzer"
    assert metadata.version == "1.2.3"
    assert metadata.description == "Plugin metadata shape"
    assert metadata.scope == "node service repos"
    assert metadata.targets == ["node-service", "node"]
    assert metadata.languages == ["typescript", "javascript"]
    assert metadata.priority == 25
    assert metadata.experimental is False
    assert metadata.enabled_by_default is True
    assert metadata.ecosystems == ("typescript", "javascript", "node-service", "node")


def test_get_available_modules_returns_registered_metadata(monkeypatch) -> None:
    class ExternalAnalyzer:
        metadata = AnalyzerMetadata(
            name="php-web",
            description="php analyzer",
            scope="external test analyzer",
            ecosystems=("php",),
        )

        @property
        def name(self) -> str:
            return "php-web"

        def analyze(self, root: str | Path) -> AnalyzerResult:
            return AnalyzerResult(root=str(root))

    monkeypatch.setattr("attackmap.analyzers.get_registered_analyzers", lambda: [ExternalAnalyzer()])

    modules = get_available_modules()

    assert len(modules) == 1
    assert modules[0].name == "php-web"
    assert modules[0].ecosystems == ("php",)


def test_get_analyzer_metadata_normalizes_external_rich_metadata_shape() -> None:
    class ExternalAnalyzer:
        metadata = {
            "name": "atproto",
            "display_name": "AT Protocol Analyzer",
            "version": "0.9.0",
            "description": "Protocol-aware overlay",
            "scope": "ATProto repos",
            "targets": ["atproto", "bluesky"],
            "languages": ["typescript", "json"],
            "priority": 35,
            "experimental": True,
            "enabled_by_default": False,
        }

        @property
        def name(self) -> str:
            return "atproto"

        def analyze(self, root: str | Path) -> AnalyzerResult:
            return AnalyzerResult(root=str(root))

    metadata = get_analyzer_metadata(ExternalAnalyzer())

    assert metadata.name == "atproto"
    assert metadata.display_name == "AT Protocol Analyzer"
    assert metadata.version == "0.9.0"
    assert metadata.scope == "ATProto repos"
    assert metadata.priority == 35
    assert metadata.experimental is True
    assert metadata.enabled_by_default is False
    assert metadata.ecosystems == ("typescript", "json", "atproto", "bluesky")


def test_get_available_repository_modules_filters_and_normalizes() -> None:
    modules = get_available_repository_modules(
        fetcher=lambda _url: [
            {
                "name": "attackmap-analyzer-php-web",
                "html_url": "https://github.com/mlaify/attackmap-analyzer-php-web",
            },
            {"name": "random-repo", "html_url": "https://github.com/mlaify/random-repo"},
            {
                "name": "attackmap-analyzer-node-express",
                "html_url": "https://github.com/mlaify/attackmap-analyzer-node-express",
            },
        ]
    )

    assert [module.analyzer_name for module in modules] == ["node-express", "php-web"]
    assert [module.repo_name for module in modules] == ["attackmap-analyzer-node-express", "attackmap-analyzer-php-web"]


def test_get_available_repository_modules_passes_through_fetch_errors() -> None:
    with pytest.raises(ValueError, match="registry is unavailable"):
        get_available_repository_modules(fetcher=lambda _url: (_ for _ in ()).throw(ValueError("registry is unavailable")))


def test_merge_analyzer_results_combines_languages_and_deduplicates_signals() -> None:
    first = AnalyzerResult(
        root=".",
        languages=["python"],
        routes=[Route(path="/health", method="GET", file="app.py")],
        external_calls=[ExternalCall(target="https://api.example.com", file="app.py")],
        auth_hints=[AuthHint(hint="oauth", file="app.py")],
        service_hints=[ServiceHint(hint="service_name:api", file="app.py")],
        edge_hints=[EdgeHint(hint="edge:api->worker", file="app.py")],
        protocol_hints=[ProtocolHint(hint="atproto_protocol:xrpc", file="app.py")],
        framework_hints=[FrameworkHint(hint="controller:App\\Controller\\Health", file="app.py")],
        secret_hints=[SecretHint(name="API_KEY", file="app.py")],
        files_scanned=2,
    )
    second = AnalyzerResult(
        root=".",
        languages=["python", "javascript"],
        routes=[
            Route(path="/health", method="GET", file="app.py"),
            Route(path="/login", method="POST", file="auth.py"),
        ],
        external_calls=[ExternalCall(target="https://api.example.com", file="app.py")],
        auth_hints=[AuthHint(hint="oauth", file="app.py")],
        service_hints=[ServiceHint(hint="service_name:api", file="app.py")],
        edge_hints=[EdgeHint(hint="edge:api->worker", file="app.py")],
        protocol_hints=[ProtocolHint(hint="atproto_protocol:xrpc", file="app.py")],
        framework_hints=[FrameworkHint(hint="controller:App\\Controller\\Health", file="app.py")],
        secret_hints=[SecretHint(name="API_KEY", file="app.py")],
        files_scanned=3,
    )

    merged = merge_analyzer_results([first, second], root=".")

    assert merged.files_scanned == 5
    assert merged.languages == ["javascript", "python"]
    assert {(route.path, route.method, route.file) for route in merged.routes} == {
        ("/health", "GET", "app.py"),
        ("/login", "POST", "auth.py"),
    }
    assert len(merged.external_calls) == 1
    assert len(merged.auth_hints) == 1
    assert len(merged.service_hints) == 1
    assert len(merged.edge_hints) == 1
    assert len(merged.protocol_hints) == 1
    assert len(merged.framework_hints) == 1
    assert len(merged.secret_hints) == 1


def test_analyze_repository_merges_and_deduplicates_multiple_analyzer_results() -> None:
    class FirstAnalyzer:
        metadata = get_analyzer_metadata(BuiltinPythonWebAnalyzer())

        @property
        def name(self) -> str:
            return self.metadata.name

        def analyze(self, root: str | Path) -> AnalyzerResult:
            return AnalyzerResult(
                root=str(root),
                languages=["python"],
                routes=[Route(path="/login", method="POST", file="app.py")],
                external_calls=[ExternalCall(target="https://api.example.com", file="app.py")],
                auth_hints=[AuthHint(hint="oauth", file="app.py")],
                secret_hints=[SecretHint(name="API_KEY", file="app.py")],
                files_scanned=2,
            )

    class SecondAnalyzer:
        metadata = get_analyzer_metadata(DefaultAnalyzer())

        @property
        def name(self) -> str:
            return self.metadata.name

        def analyze(self, root: str | Path) -> AnalyzerResult:
            return AnalyzerResult(
                root=str(root),
                languages=["javascript", "python"],
                routes=[
                    Route(path="/login", method="POST", file="app.py"),
                    Route(path="/healthz", method="GET", file="server.js"),
                ],
                external_calls=[ExternalCall(target="https://api.example.com", file="app.py")],
                auth_hints=[AuthHint(hint="oauth", file="app.py")],
                secret_hints=[SecretHint(name="API_KEY", file="app.py")],
                files_scanned=3,
            )

    result = analyze_repository(".", analyzers=[FirstAnalyzer(), SecondAnalyzer()])

    assert result.files_scanned == 5
    assert result.languages == ["javascript", "python"]
    assert {(route.path, route.method, route.file) for route in result.routes} == {
        ("/login", "POST", "app.py"),
        ("/healthz", "GET", "server.js"),
    }
    assert len(result.external_calls) == 1
    assert len(result.auth_hints) == 1
    assert len(result.secret_hints) == 1


def test_analyze_repository_keeps_specialized_overlay_signals_analyzer_driven(tmp_path: Path) -> None:
    server_file = tmp_path / "services" / "api" / "src" / "server.js"
    server_file.parent.mkdir(parents=True, exist_ok=True)
    server_file.write_text(
        """
const express = require("express");
const app = express();
app.post("/xrpc/com.atproto.server.createSession", (_req, res) => res.json({ ok: true }));
""",
        encoding="utf-8",
    )

    class SyntheticOverlayAnalyzer:
        metadata = AnalyzerMetadata(
            name="synthetic-overlay",
            description="synthetic test overlay",
            scope="tests analyzer-driven specialization",
            ecosystems=("typescript",),
        )

        @property
        def name(self) -> str:
            return "synthetic-overlay"

        def detect(self, root: str | Path) -> bool:
            return True

        def analyze(self, root: str | Path) -> AnalyzerResult:
            return AnalyzerResult(
                    root=str(root),
                    auth_hints=[
                        AuthHint(hint="service_name:api", file="services/api/src/server.js"),
                        AuthHint(hint="edge:api->relay", file="services/api/src/server.js"),
                        AuthHint(hint="atproto_protocol:xrpc", file="services/api/src/server.js"),
                    ],
                )

    result = analyze_repository(tmp_path, analyzers=[BuiltinJavaScriptWebAnalyzer(), SyntheticOverlayAnalyzer()])
    hint_values = {hint.hint for hint in result.auth_hints}
    route_values = {(route.path, route.method) for route in result.routes}

    assert ("/xrpc/com.atproto.server.createSession", "POST") in route_values
    assert "service_name:api" in hint_values
    assert "edge:api->relay" in hint_values
    assert "atproto_protocol:xrpc" in hint_values


def test_analyze_repository_respects_optional_detect() -> None:
    class DetectFalseAnalyzer:
        metadata = get_analyzer_metadata(DefaultAnalyzer())

        @property
        def name(self) -> str:
            return "detect-false"

        def detect(self, root: str | Path) -> bool:
            return False

        def analyze(self, root: str | Path) -> AnalyzerResult:
            raise AssertionError("analyze() should not run when detect() is False")

    class DetectTrueAnalyzer:
        metadata = get_analyzer_metadata(DefaultAnalyzer())

        @property
        def name(self) -> str:
            return "detect-true"

        def detect(self, root: str | Path) -> bool:
            return True

        def analyze(self, root: str | Path) -> AnalyzerResult:
            return AnalyzerResult(
                root=str(root),
                languages=["php"],
                routes=[Route(path="/health", method="GET", file="index.php")],
                files_scanned=1,
            )

    result = analyze_repository(".", analyzers=[DetectFalseAnalyzer(), DetectTrueAnalyzer()])

    assert result.files_scanned == 1
    assert result.languages == ["php"]
    assert any(route.path == "/health" and route.file == "index.php" for route in result.routes)


def test_registered_analyzers_merge_specialized_and_fallback_results(tmp_path: Path) -> None:
    js_file = tmp_path / "server.js"
    js_file.write_text(
        """
const express = require("express");
const app = express();
app.get("/healthz", (_req, res) => res.send("ok"));
""",
        encoding="utf-8",
    )
    ts_file = tmp_path / "client.ts"
    ts_file.write_text(
        """
const token = process.env.API_KEY;
fetch("https://api.example.com/ping");
""",
        encoding="utf-8",
    )

    result = analyze_repository(tmp_path)

    assert result.files_scanned == 2
    assert result.languages == ["javascript", "typescript"]
    assert any(route.path == "/healthz" and route.method == "GET" for route in result.routes)
    assert any(call.target == "https://api.example.com/ping" and call.file == "client.ts" for call in result.external_calls)
    assert any(secret.name == "API_KEY" and secret.file == "client.ts" for secret in result.secret_hints)


def test_analyze_repository_uses_installed_php_web_analyzer_for_php_routes(tmp_path: Path) -> None:
    pytest.importorskip("attackmap_analyzer_php_web")

    composer = tmp_path / "composer.json"
    composer.write_text(
        """
{"name": "example/php-app", "require": {"php": "^8.2"}}
""",
        encoding="utf-8",
    )
    routes_file = tmp_path / "routes.php"
    routes_file.write_text(
        """
<?php
Route::post('/webhook/stripe', fn () => null);
""",
        encoding="utf-8",
    )

    result = analyze_repository(tmp_path)

    assert "php" in result.languages
    assert any(route.path == "/webhook/stripe" and route.method == "POST" for route in result.routes)


def test_analyze_repository_runs_registered_builtin_analyzers(tmp_path: Path) -> None:
    python_file = tmp_path / "app.py"
    python_file.write_text(
        """
from fastapi import FastAPI

app = FastAPI()

@app.get("/health")
def health():
    return {"ok": True}
""",
        encoding="utf-8",
    )
    js_file = tmp_path / "server.js"
    js_file.write_text(
        """
const express = require("express");
const app = express();
app.get("/healthz", (_req, res) => res.send("ok"));
""",
        encoding="utf-8",
    )

    # Explicitly pass the built-in analyzers so this test is robust to entry-point
    # plugins (e.g. attackmap-analyzer-python) being installed in the same env.
    result = analyze_repository(tmp_path, analyzers=get_builtin_repository_analyzers())

    assert result.files_scanned == 2
    assert result.languages == ["javascript", "python"]
    assert any(route.path == "/health" and route.method == "GET" for route in result.routes)
    assert any(route.path == "/healthz" and route.method == "GET" for route in result.routes)
