from pathlib import Path

from attackmap.sdk.testing import assert_conforms

from attackmap_analyzer_example import ExampleAnalyzer


def test_conforms_and_finds_routes() -> None:
    result = assert_conforms(ExampleAnalyzer(), Path(__file__).parent / "fixtures" / "sample")
    assert [(r.method, r.path, r.line) for r in result.routes] == [("GET", "/users/:id", 1), ("POST", "/users", 4)]
