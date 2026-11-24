"""Conformance checks for analyzer plugins (#201, #254).

Call from a plugin's tests with a small fixture repo the analyzer should
detect::

    from attackmap.sdk.testing import assert_conforms

    def test_conforms():
        result = assert_conforms(MyAnalyzer(), Path(__file__).parent / "fixtures" / "sample")
        assert result.routes  # then the plugin's own expectations

It checks what core relies on: metadata validates (and ``requires_core``
matches the running core), ``detect()`` is a bool and doesn't raise on an
empty directory, ``analyze()`` returns a scan result whose paths are
repo-relative with 1-based lines, and nothing raises on empty, binary or
non-UTF-8 files.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from .. import __version__
from ..analyzer_contracts import core_version_matches, normalize_analyzer_metadata
from .contracts import AnalyzerResult


def _check_records(result: AnalyzerResult) -> None:
    for field_name in type(result).model_fields:
        value = getattr(result, field_name)
        if not isinstance(value, list):
            continue
        for item in value:
            file = getattr(item, "file", None)
            if isinstance(file, str):
                path = PurePosixPath(file.replace("\\", "/"))
                assert not path.is_absolute() and ".." not in path.parts, (
                    f"{field_name}: {file!r} must be relative to the scanned repo"
                )
            line = getattr(item, "line", None)
            assert line is None or (isinstance(line, int) and line >= 1), (
                f"{field_name}: line {line!r} in {file!r} must be 1-based or None"
            )


def assert_conforms(analyzer: Any, fixture_dir: str | Path) -> AnalyzerResult:
    """Assert ``analyzer`` meets the SDK contract on ``fixture_dir`` (a repo
    it should detect); return its result there."""
    fixture_dir = Path(fixture_dir)
    metadata = normalize_analyzer_metadata(getattr(analyzer, "metadata", None))
    if hasattr(analyzer, "name"):
        assert analyzer.name == metadata.name, f"name {analyzer.name!r} != metadata.name {metadata.name!r}"
    if metadata.requires_core:
        assert core_version_matches(__version__, metadata.requires_core), (
            f"requires_core {metadata.requires_core!r} doesn't match the running attackmap {__version__}"
        )

    with tempfile.TemporaryDirectory() as tmp:
        empty = Path(tmp) / "empty"
        empty.mkdir()
        assert isinstance(analyzer.detect(empty), bool), "detect() must return a bool"
        assert analyzer.detect(fixture_dir) is True, f"detect() is False on the fixture {fixture_dir}"

        result = analyzer.analyze(fixture_dir)
        assert isinstance(result, AnalyzerResult), f"analyze() returned {type(result).__name__}, not AnalyzerResult"
        _check_records(result)

        # Hostile but ordinary inputs: empty, binary and non-UTF-8 files.
        noisy = Path(tmp) / "noisy"
        shutil.copytree(fixture_dir, noisy)
        for suffix in {p.suffix for p in fixture_dir.rglob("*") if p.is_file() and p.suffix} or {".txt"}:
            (noisy / f"empty{suffix}").write_bytes(b"")
            (noisy / f"binary{suffix}").write_bytes(bytes(range(256)) * 4)
            (noisy / f"latin1{suffix}").write_bytes("caf\xe9 = '\xff'\n".encode("latin-1"))
        _check_records(analyzer.analyze(noisy))
    return result


__all__ = ["assert_conforms"]
