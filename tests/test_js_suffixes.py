"""Routes are extracted from every JS/TS suffix the core scans (#227)."""

from __future__ import annotations

from pathlib import Path

from attackmap.analyzers import analyze_repository
from attackmap.scanner import CODE_EXTENSIONS
from attackmap.srcpaths import JS_TS_SUFFIXES


def test_routes_from_mjs_cjs_jsx(tmp_path: Path) -> None:
    for ext in ("js", "mjs", "cjs", "jsx"):
        (tmp_path / f"server_{ext}.{ext}").write_text(
            "const app = require('express')();\n"
            f"app.post('/charge-{ext}', (req, res) => res.send('ok'));\n"
        )
    result = analyze_repository(tmp_path)
    found = {(r.method, r.path, r.file) for r in result.routes}
    for ext in ("js", "mjs", "cjs", "jsx"):
        assert ("POST", f"/charge-{ext}", f"server_{ext}.{ext}") in found


def test_js_ts_suffixes_match_scanned_languages() -> None:
    scanned = {s for s, lang in CODE_EXTENSIONS.items() if lang in {"javascript", "typescript"}}
    assert scanned == set(JS_TS_SUFFIXES)
