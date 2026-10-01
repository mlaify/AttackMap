"""Per-instance fingerprints for finding locations (#222).

A ``Finding`` aggregates every site of one issue type, and its id hashes only
the title, so a PR that adds a *second* command-injection route used to diff as
"persisted" and pass ``--fail-on-new-high``. Each ``FindingLocation`` now gets
a fingerprint that identifies that instance across runs:

    sha256(rule_id | file | normalized source line | occurrence)[:16]

The line *number* is deliberately excluded so unrelated edits above a site
(line drift) don't make it look new. The source line is normalized —
whitespace removed, string and number literals masked — so reformatting or
changing a literal value doesn't either, while a different call or a
different file does. Identical normalized lines in one file are told apart by
their occurrence index.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from .models import Finding, finding_rule_id
from .safe_fs import contained_file, is_oversized

_STRING = re.compile(r"""(?:[rbuf]{0,2})("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)""", re.IGNORECASE)
_NUMBER = re.compile(r"\b\d+(?:\.\d+)?\b")
_SPACE = re.compile(r"\s+")


def normalize_line(line: str) -> str:
    """Whitespace-insensitive, literal-insensitive form of a source line."""
    text = _STRING.sub('"S"', line)
    text = _NUMBER.sub("0", text)
    # All whitespace goes, not just runs of it: `a + b` and `a+b` are the
    # same code, and token boundaries don't matter for a hash.
    return _SPACE.sub("", text)


def _digest(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:16]


def assign_fingerprints(findings: list[Finding], root: str | Path) -> None:
    """Set ``fingerprint`` on every location of every finding (in place)."""
    root_path = Path(root)
    line_cache: dict[str, list[str] | None] = {}

    def source_line(rel: str, line: int | None) -> str:
        if line is None:
            return ""
        if rel not in line_cache:
            path = contained_file(root_path, rel)
            try:
                line_cache[rel] = (
                    path.read_text(encoding="utf-8", errors="replace").splitlines()
                    if path is not None and not is_oversized(path)
                    else None
                )
            except OSError:
                line_cache[rel] = None
        lines = line_cache[rel]
        if not lines or not 1 <= line <= len(lines):
            return f"#line-unavailable:{line}"
        return normalize_line(lines[line - 1])

    for finding in findings:
        rule = finding_rule_id(finding)
        seen: dict[tuple[str, str], int] = {}
        for loc in finding.locations:
            file = loc.file.replace("\\", "/")
            content = source_line(file, loc.line)
            occurrence = seen.get((file, content), 0)
            seen[(file, content)] = occurrence + 1
            loc.fingerprint = _digest(rule, file, content, str(occurrence))
