from pathlib import Path

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
    get_builtin_repository_analyzers,
    get_registered_analyzers,
    merge_analyzer_results,
)
from attackmap.models import AuthHint, ExternalCall, Route, ScanResult, SecretHint


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
    assert "Python web frameworks" in python_metadata.description
    assert python_metadata.scope.startswith("Python source files")
    assert python_metadata.ecosystems == ("python", "fastapi", "flask")

    assert javascript_metadata.name == "javascript-web"
    assert "JavaScript web frameworks" in javascript_metadata.description
    assert javascript_metadata.ecosystems == ("javascript", "express", "node")

    assert default_metadata.name == "default"
    assert "Fallback" in default_metadata.description
    assert default_metadata.ecosystems == ("typescript",)


def test_merge_analyzer_results_combines_languages_and_deduplicates_signals() -> None:
    first = AnalyzerResult(
        root=".",
        languages=["python"],
        routes=[Route(path="/health", method="GET", file="app.py")],
        external_calls=[ExternalCall(target="https://api.example.com", file="app.py")],
        auth_hints=[AuthHint(hint="oauth", file="app.py")],
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

    result = analyze_repository(tmp_path)

    assert result.files_scanned == 2
    assert result.languages == ["javascript", "python"]
    assert any(route.path == "/health" and route.method == "GET" for route in result.routes)
    assert any(route.path == "/healthz" and route.method == "GET" for route in result.routes)
