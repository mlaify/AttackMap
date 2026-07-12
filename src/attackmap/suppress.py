"""Finding suppression: inline comments + a repo-level baseline file (#144).

Teams adopting AttackMap in CI need a way to silence a residual false
positive *without* going blind to new signal. This module provides two
mechanisms, both applied as a post-pass over the assembled ``Finding``
list:

## 1. Repo-level baseline — ``.attackmap-suppress.yaml``

Placed at the repo root. Each entry carries a mandatory ``reason`` and one
or more selectors:

```yaml
version: 1
suppress:
  # by stable finding id (the 16-hex id in attackmap-report.json)
  - id: 1a2b3c4d5e6f7a8b
    reason: accepted risk, tracked in JIRA-1234

  # by rule (a slug of the finding title — matches the SARIF ruleId)
  - rule: hardcoded-secret-literals
    reason: test fixtures only, never shipped
    paths: ["tests/fixtures/**"]     # optional: scope the rule to paths

  # by path only (any finding whose evidence is *entirely* within paths)
  - path: "vendor/**"
    reason: third-party code, out of scope
```

``paths``/``path`` are globs. A path selector matches a finding only when
**every** file its evidence cites falls under the glob — so a finding that
also touches live code is never silently hidden. ``*`` matches across path
separators (``vendor/*`` covers the whole subtree); ``**`` is accepted as a
synonym for ``*``.

## 2. Inline directives

```python
API_KEY = "…"  # attackmap:ignore[hardcoded-secret-literals] rotated, staging only
```

A directive in file ``X`` contributes a path selector for ``X`` (optionally
scoped to the bracketed rule; a bare ``attackmap:ignore`` matches any rule).
Because findings aggregate every site of an issue-type, an inline directive
suppresses a finding only when *all* of the finding's cited files carry a
matching directive (or are covered by a baseline path glob). For a
single-file finding one directive is enough; a multi-file finding needs the
directive in each cited file, or a baseline ``path`` entry.

## Semantics

Suppressed findings are **not dropped** — they are partitioned out of the
active set (so they don't trip ``--fail-on-new-high`` and don't clutter the
console), but they are still emitted to SARIF marked ``suppressions`` and to
``attackmap-report.json`` under ``suppressed_findings``, each carrying the
reason. Suppression counts are printed in the run summary.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path

from .diff import finding_id
from .models import Finding

__all__ = [
    "Suppression",
    "SuppressionSet",
    "SuppressedFinding",
    "SuppressionOutcome",
    "collect_suppressions",
    "apply_suppressions",
    "rule_slug",
    "SUPPRESS_FILENAMES",
    "INLINE_DIRECTIVE",
]

# Candidate baseline filenames at the repo root, in preference order.
SUPPRESS_FILENAMES = (".attackmap-suppress.yaml", ".attackmap-suppress.yml")

# `# attackmap:ignore[rule-a, rule-b] free-text reason`. The comment leader
# (`#`, `//`, `--`, `;`, `/* … */`) is irrelevant — we only match the
# directive token, so it works across languages. Rule list is optional; a
# bare `attackmap:ignore` matches any rule.
INLINE_DIRECTIVE = re.compile(
    r"attackmap:ignore(?:\[\s*([a-z0-9_.,\s-]*?)\s*\])?[ \t:-]*(.*?)\s*(?:\*/)?$",
    re.IGNORECASE,
)

# Lift file paths out of evidence strings — mirrors sarif._LOCATION_FROM_EVIDENCE
# but captures the path only (line numbers are irrelevant to suppression).
_EVIDENCE_PATH = re.compile(
    r"(?:in|at)\s+`?([\w./_\\-]+\.(?:py|js|jsx|ts|tsx|mjs|cjs|go|rs|php|java|kt|"
    r"cs|cpp|c|h|hpp|yml|yaml|json|toml|env|sh|dockerfile))`?(?::\d+)?",
    re.IGNORECASE,
)

# Directories we never read when scanning for inline directives — matches the
# scanner's own output dirs so we never chase our own reports (see #85 / the
# 0.4.5 feedback-loop fix).
_SKIP_INLINE_PARTS = {".git", ".attackmap", ".attackmap-gui", "node_modules"}


def rule_slug(title: str) -> str:
    """Human-readable, stable rule id for a finding title.

    Identical to ``sarif._slugify`` so the ``rule:`` key in a suppress file
    matches the ``ruleId`` a user sees in SARIF / GitHub Code Scanning. The
    equality is locked by a test.
    """
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    return slug or "finding"


def _evidence_paths(finding: Finding) -> list[str]:
    """Best-effort set of source files a finding's evidence cites."""
    paths: list[str] = []
    seen: set[str] = set()
    for line in finding.evidence:
        for match in _EVIDENCE_PATH.finditer(line):
            path = match.group(1).replace("\\", "/")
            if path not in seen:
                seen.add(path)
                paths.append(path)
    return paths


def _glob_match(path: str, glob: str) -> bool:
    """Glob match where ``*`` spans path separators. ``**`` is treated as a
    synonym for ``*`` so both ``vendor/*`` and ``vendor/**`` cover a subtree."""
    normalized = glob.replace("**", "*")
    return fnmatch.fnmatch(path, normalized)


@dataclass(frozen=True)
class Suppression:
    """One suppression selector plus its justification.

    Exactly one *primary* selector kind is used per instance: ``id`` (exact
    finding), ``rule`` without ``path`` (whole rule), or ``path`` (with an
    optional ``rule`` scope). ``origin`` and ``source`` are for logging.
    """

    reason: str
    id: str | None = None
    rule: str | None = None
    path: str | None = None
    origin: str = "file"  # "file" | "inline"
    source: str = ""  # human-readable declaration site

    def label(self) -> str:
        if self.id:
            sel = f"id={self.id}"
        elif self.path and self.rule:
            sel = f"rule={self.rule} path={self.path}"
        elif self.path:
            sel = f"path={self.path}"
        else:
            sel = f"rule={self.rule}"
        return f"{sel} ({self.origin})"


@dataclass
class SuppressedFinding:
    """A finding that matched at least one suppression."""

    finding: Finding
    id: str
    rule: str
    reason: str
    matched: list[Suppression] = field(default_factory=list)


@dataclass
class SuppressionOutcome:
    active: list[Finding]
    suppressed: list[SuppressedFinding]
    warnings: list[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.suppressed)

    def summary_lines(self) -> list[str]:
        """One line per suppressed finding, for the run summary."""
        lines: list[str] = []
        for s in self.suppressed:
            reasons = "; ".join(dict.fromkeys(m.reason for m in s.matched if m.reason))
            lines.append(f"  - [{s.rule}] {s.finding.title} — {reasons or 'no reason given'}")
        return lines


class SuppressionSet:
    """Resolves whether a finding is suppressed and by which selector(s)."""

    def __init__(self, suppressions: list[Suppression]) -> None:
        self._by_id: dict[str, list[Suppression]] = {}
        self._rule_only: list[Suppression] = []  # rule set, no path → whole-rule
        self._path: list[Suppression] = []  # path set (optional rule scope)
        for sup in suppressions:
            if sup.id:
                self._by_id.setdefault(sup.id, []).append(sup)
            elif sup.path:
                self._path.append(sup)
            elif sup.rule:
                self._rule_only.append(sup)

    def match(self, finding: Finding) -> list[Suppression]:
        """Return the suppressions that cover ``finding`` (empty = active)."""
        fid = finding_id(finding.title)
        rule = rule_slug(finding.title)

        exact = self._by_id.get(fid, [])
        if exact:
            return list(exact)

        rule_hits = [s for s in self._rule_only if _rule_matches(s.rule, rule)]
        if rule_hits:
            return rule_hits

        # Path coverage: the finding is suppressed only if EVERY file it cites
        # is covered by a rule-compatible path selector. A finding with no
        # citable path can never be path-suppressed (only by id/rule).
        candidates = [s for s in self._path if _rule_matches(s.rule, rule)]
        if not candidates:
            return []
        paths = _evidence_paths(finding)
        if not paths:
            return []
        contributing: list[Suppression] = []
        for path in paths:
            covering = next((s for s in candidates if _glob_match(path, s.path or "")), None)
            if covering is None:
                return []  # a cited file is outside every glob → keep finding
            if covering not in contributing:
                contributing.append(covering)
        return contributing


def _rule_matches(selector_rule: str | None, finding_rule: str) -> bool:
    """A ``None`` selector rule is a wildcard; otherwise slug-equal."""
    return selector_rule is None or rule_slug(selector_rule) == finding_rule


def apply_suppressions(
    findings: list[Finding], suppset: SuppressionSet, *, warnings: list[str] | None = None
) -> SuppressionOutcome:
    active: list[Finding] = []
    suppressed: list[SuppressedFinding] = []
    for finding in findings:
        matched = suppset.match(finding)
        if matched:
            suppressed.append(
                SuppressedFinding(
                    finding=finding,
                    id=finding_id(finding.title),
                    rule=rule_slug(finding.title),
                    reason="; ".join(dict.fromkeys(m.reason for m in matched if m.reason)),
                    matched=matched,
                )
            )
        else:
            active.append(finding)
    return SuppressionOutcome(active=active, suppressed=suppressed, warnings=warnings or [])


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def _load_yaml_entries(path: Path, warnings: list[str]) -> list[Suppression]:
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        warnings.append(
            f"{path.name} found but PyYAML is not installed; suppressions ignored. "
            "Install attackmap with its dependencies to enable suppression."
        )
        return []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:  # type: ignore[attr-defined]
        warnings.append(f"Failed to parse {path.name}: {exc}")
        return []

    if isinstance(data, dict):
        entries = data.get("suppress") or data.get("suppressions") or []
    elif isinstance(data, list):
        entries = data
    elif data is None:
        entries = []
    else:
        warnings.append(f"{path.name}: expected a list or a mapping with 'suppress:'")
        return []

    suppressions: list[Suppression] = []
    for raw in entries:
        if not isinstance(raw, dict):
            warnings.append(f"{path.name}: skipping non-mapping entry {raw!r}")
            continue
        reason = str(raw.get("reason", "")).strip()
        sup_id = raw.get("id")
        rule = raw.get("rule")
        globs = raw.get("paths")
        if globs is None and raw.get("path") is not None:
            globs = raw.get("path")
        glob_list = [globs] if isinstance(globs, str) else list(globs or [])

        if not reason:
            warnings.append(f"{path.name}: skipping entry without a 'reason' ({raw!r})")
            continue
        if not (sup_id or rule or glob_list):
            warnings.append(f"{path.name}: skipping entry with no selector (id/rule/path)")
            continue

        source = f"{path.name}"
        if sup_id:
            suppressions.append(
                Suppression(reason=reason, id=str(sup_id), origin="file", source=source)
            )
        if glob_list:
            for glob in glob_list:
                suppressions.append(
                    Suppression(
                        reason=reason,
                        rule=str(rule) if rule else None,
                        path=str(glob),
                        origin="file",
                        source=source,
                    )
                )
        elif rule:
            suppressions.append(
                Suppression(reason=reason, rule=str(rule), origin="file", source=source)
            )
    return suppressions


def load_suppress_file(
    root: Path, warnings: list[str], *, explicit: Path | None = None
) -> list[Suppression]:
    """Load the repo-level baseline. ``explicit`` overrides auto-discovery."""
    if explicit is not None:
        if not explicit.exists():
            warnings.append(f"Suppress file not found: {explicit}")
            return []
        return _load_yaml_entries(explicit, warnings)
    for name in SUPPRESS_FILENAMES:
        candidate = root / name
        if candidate.exists():
            return _load_yaml_entries(candidate, warnings)
    return []


def scan_inline_suppressions(root: Path, findings: list[Finding]) -> list[Suppression]:
    """Scan the files cited by ``findings`` for inline ``attackmap:ignore``
    directives. Only cited files are read — this is both efficient and
    inherently scoped to what could actually be suppressed.
    """
    cited: set[str] = set()
    for finding in findings:
        cited.update(_evidence_paths(finding))

    suppressions: list[Suppression] = []
    for rel in sorted(cited):
        if any(part in _SKIP_INLINE_PARTS for part in Path(rel).parts):
            continue
        file_path = (root / rel)
        try:
            if not file_path.is_file():
                continue
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if "attackmap:ignore" not in line.lower():
                continue
            match = INLINE_DIRECTIVE.search(line)
            if not match:
                continue
            rules_raw, reason = match.group(1), (match.group(2) or "").strip()
            source = f"{rel}:{lineno}"
            rule_tokens = [r.strip() for r in (rules_raw or "").split(",") if r.strip()]
            if rule_tokens:
                for token in rule_tokens:
                    suppressions.append(
                        Suppression(
                            reason=reason,
                            rule=token,
                            path=rel,
                            origin="inline",
                            source=source,
                        )
                    )
            else:
                suppressions.append(
                    Suppression(reason=reason, path=rel, origin="inline", source=source)
                )
    return suppressions


def collect_suppressions(
    root: Path,
    findings: list[Finding],
    *,
    enable_inline: bool = True,
    explicit_file: Path | None = None,
) -> tuple[SuppressionSet, list[str]]:
    """Gather baseline-file + inline suppressions into a ready-to-apply set."""
    warnings: list[str] = []
    suppressions = load_suppress_file(root, warnings, explicit=explicit_file)
    if enable_inline:
        suppressions.extend(scan_inline_suppressions(root, findings))
    return SuppressionSet(suppressions), warnings
