"""SDK 1.0 contract (#201, #254): requires_core, assert_conforms, the template."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from attackmap import analyzers
from attackmap.analyzer_contracts import core_version_matches
from attackmap.sdk import AnalyzerMetadata, ScanResult
from attackmap.sdk import testing as sdk_testing
from attackmap.sdk.testing import assert_conforms

TEMPLATE = Path(__file__).resolve().parents[1] / "templates" / "analyzer-plugin"


@pytest.mark.parametrize(
    ("version", "spec", "ok"),
    [("0.8.0", ">=0.8,<2", True), ("0.7.9", ">=0.8", False), ("1.0.0", "<1", False),
     ("1.2", "==1.2.0", True), ("0.8.0rc1", ">=0.8", True), ("2.0", "!=2", False)],
)
def test_core_version_matches(version: str, spec: str, ok: bool) -> None:
    assert core_version_matches(version, spec) is ok


def test_malformed_requires_core_is_rejected() -> None:
    with pytest.raises(ValueError):
        AnalyzerMetadata(name="x", requires_core="~=1.0")


def test_core_skips_an_analyzer_built_for_another_core(caplog) -> None:
    class Future:
        metadata = AnalyzerMetadata(name="future", requires_core=">=99")
        name = "future"

        def detect(self, root):
            return True

        def analyze(self, root):
            return ScanResult(root=str(root))

    entry = SimpleNamespace(name="future", load=lambda: Future)
    assert analyzers._load_discovered_analyzer(entry) is None
    assert "requires attackmap >=99" in caplog.text and "pip install -U" in caplog.text


def test_template_plugin_conforms(monkeypatch) -> None:
    # The template targets the next release (sdk.testing ships in 0.8).
    monkeypatch.setattr(sdk_testing, "__version__", "0.8.0")
    monkeypatch.syspath_prepend(str(TEMPLATE / "src"))
    sys.modules.pop("attackmap_analyzer_example", None)
    module = importlib.import_module("attackmap_analyzer_example")
    result = assert_conforms(module.ExampleAnalyzer(), TEMPLATE / "tests" / "fixtures" / "sample")
    assert [(r.method, r.path) for r in result.routes] == [("GET", "/users/:id"), ("POST", "/users")]


def test_assert_conforms_rejects_absolute_paths(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("x")

    class Bad:
        metadata = AnalyzerMetadata(name="bad")
        name = "bad"

        def detect(self, root):
            return True

        def analyze(self, root):
            from attackmap.sdk import Route
            return ScanResult(root=str(root), routes=[Route(path="/x", method="GET", file=str(Path(root) / "a.txt"), line=1)])

    with pytest.raises(AssertionError, match="relative"):
        assert_conforms(Bad(), tmp_path)
