from pathlib import Path

from attackmap.analyzers import (
    AnalyzerResult,
    BuiltinJavaScriptWebAnalyzer,
    BuiltinPythonWebAnalyzer,
    analyze_repository,
    get_registered_analyzers,
    merge_analyzer_results,
)
from attackmap.models import AuthHint, ExternalCall, Route, ScanResult, SecretHint


def test_analyzer_result_reuses_scan_result_shape() -> None:
    result = AnalyzerResult(root=".")

    assert isinstance(result, ScanResult)


def test_get_registered_analyzers_exposes_builtin_web_analyzers() -> None:
    analyzers = get_registered_analyzers()

    assert len(analyzers) == 2
    assert isinstance(analyzers[0], BuiltinPythonWebAnalyzer)
    assert isinstance(analyzers[1], BuiltinJavaScriptWebAnalyzer)
    assert [analyzer.name for analyzer in analyzers] == ["python-web", "javascript-web"]


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
    assert merged.languages == ["python", "javascript"]
    assert {(route.path, route.method, route.file) for route in merged.routes} == {
        ("/health", "GET", "app.py"),
        ("/login", "POST", "auth.py"),
    }
    assert len(merged.external_calls) == 1
    assert len(merged.auth_hints) == 1
    assert len(merged.secret_hints) == 1


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
    assert result.languages == ["python", "javascript"]
    assert any(route.path == "/health" and route.method == "GET" for route in result.routes)
    assert any(route.path == "/healthz" and route.method == "GET" for route in result.routes)
