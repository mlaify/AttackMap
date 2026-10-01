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

  # by rule id (the stable detector id — `attackmap rules` lists them; it is
  # also the SARIF ruleId)
  - rule: hardcoded-secret
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
API_KEY = "…"  # attackmap:ignore[hardcoded-secret] rotated, staging only
```

A directive covers only the finding **instance on its own line or the line
below it** (#224) — put it at the end of the flagged line, or on its own line
just above. Other findings in the same file, and instances added later, stay
active. A finding with several instances is suppressed when every instance is
covered; partly covered findings stay active with the covered instances
removed. Name the rule (``attackmap rules`` lists ids); a bare
``attackmap:ignore`` matches any rule on that line and is warned about.

For file-wide scope use the explicit form:

```python
# attackmap:ignore-file[hardcoded-secret] fixture keys, never deployed
```

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

from .srcpaths import evidence_locations
from .safe_fs import contained_file, read_repo_text
from .diff import finding_id
from .models import Finding, finding_rule_id, title_slug

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
    r"attackmap:ignore(?:-file)?(?:\[\s*([a-z0-9_.,\s-]*?)\s*\])?[ \t:-]*(.*?)\s*(?:\*/)?$",
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


def _instances(finding: Finding) -> list[tuple[str, int | None]]:
    """``(file, line)`` per instance: structured locations (#214), else the
    locations cited in evidence."""
    if finding.locations:
        return [(loc.file.replace("\\", "/"), loc.line) for loc in finding.locations]
    return [(f.replace("\\", "/"), l) for f, l in evidence_locations(finding.evidence)]


def _evidence_paths(finding: Finding) -> list[str]:
    """Source files a finding covers: structured `Finding.locations` (#214),
    else the files cited in its evidence (shared parser, #213)."""
    pairs = (
        [(loc.file, loc.line) for loc in finding.locations]
        if finding.locations
        else evidence_locations(finding.evidence)
    )
    paths: list[str] = []
    for file, _line in pairs:
        path = file.replace("\\", "/")
        if path not in paths:
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
    # Inline directives (#224) cover only the instance on their own line or
    # the line below; `attackmap:ignore-file` (and suppress-file `path:`
    # entries) leave this None and cover the whole file.
    line: int | None = None
    origin: str = "file"  # "file" | "inline"
    source: str = ""  # human-readable declaration site

    def label(self) -> str:
        where = f"{self.path}:{self.line}" if self.line is not None else self.path
        if self.id:
            sel = f"id={self.id}"
        elif self.path and self.rule:
            sel = f"rule={self.rule} path={where}"
        elif self.path:
            sel = f"path={where}"
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
    # Post-match notices (#223): legacy selectors and entries matching nothing.
    notices: list[str] = field(default_factory=list)

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
        self._all = list(suppressions)
        self._used: set[int] = set()
        # Legacy title-slug selectors that matched, keyed by selector →
        # the stable rule id to use instead (#223).
        self.legacy_selectors: dict[str, str] = {}
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
        hits = self._match(finding)
        self._used.update(id(s) for s in hits)
        return hits

    def mark_used(self, sups) -> None:  # type: ignore[no-untyped-def]
        self._used.update(id(s) for s in sups)

    def unused(self) -> list[Suppression]:
        """Entries that matched no finding in this run (#223)."""
        return [s for s in self._all if id(s) not in self._used]

    def _rule_ok(self, selector_rule: str | None, finding: Finding) -> bool:
        """A ``None`` selector is a wildcard. Otherwise it must equal the stable
        rule id, or — deprecated — the finding's title slug."""
        if selector_rule is None:
            return True
        selector = rule_slug(selector_rule)
        stable = finding_rule_id(finding)
        if selector == stable:
            return True
        legacy = title_slug(finding.title)
        if finding.rule_id and selector == legacy:
            self.legacy_selectors[selector] = stable
            return True
        return False

    def _match(self, finding: Finding) -> list[Suppression]:
        fid = finding_id(finding.title)

        exact = self._by_id.get(fid, [])
        if exact:
            return list(exact)

        rule_hits = [s for s in self._rule_only if self._rule_ok(s.rule, finding)]
        if rule_hits:
            return rule_hits

        # Path coverage: the finding is suppressed only if EVERY instance it
        # covers is covered — by a path glob / `ignore-file` directive for its
        # file, or by a line-scoped inline directive on its line (or the line
        # above it, #224). A finding with no citable location can never be
        # path-suppressed (only by id/rule).
        coverage = self.instance_coverage(finding)
        if not coverage or any(c is None for c in coverage):
            return []
        return list(dict.fromkeys(coverage))  # type: ignore[arg-type]

    def instance_coverage(self, finding: Finding) -> list[Suppression | None]:
        """Per instance of ``finding``, the path/inline suppression covering
        it (or None). Empty when the finding has no citable location."""
        candidates = [s for s in self._path if self._rule_ok(s.rule, finding)]
        instances = _instances(finding)
        if not candidates or not instances:
            return [None] * len(instances)
        out: list[Suppression | None] = []
        for file, line in instances:
            covering = None
            for sup in candidates:
                if sup.line is not None:
                    if file == sup.path and line is not None and line in (sup.line, sup.line + 1):
                        covering = sup
                        break
                elif _glob_match(file, sup.path or ""):
                    covering = sup
                    break
            out.append(covering)
        return out


def apply_suppressions(
    findings: list[Finding], suppset: SuppressionSet, *, warnings: list[str] | None = None
) -> SuppressionOutcome:
    active: list[Finding] = []
    suppressed: list[SuppressedFinding] = []
    for finding in findings:
        matched = suppset.match(finding)
        if not matched:
            # Instance-level inline directives (#224): drop just the covered
            # locations and keep the finding active for the rest.
            coverage = suppset.instance_coverage(finding)
            if finding.locations and len(coverage) == len(finding.locations) and any(coverage):
                suppset.mark_used(c for c in coverage if c is not None)
                finding = finding.model_copy(
                    update={"locations": [loc for loc, c in zip(finding.locations, coverage) if c is None]}
                )
        if matched:
            suppressed.append(
                SuppressedFinding(
                    finding=finding,
                    id=finding_id(finding.title),
                    rule=finding_rule_id(finding),
                    reason="; ".join(dict.fromkeys(m.reason for m in matched if m.reason)),
                    matched=matched,
                )
            )
        else:
            active.append(finding)
    notices: list[str] = []
    for selector, stable in sorted(suppset.legacy_selectors.items()):
        notices.append(
            f"rule '{selector}' is a legacy title-based selector; use the stable rule id "
            f"'{stable}' (title selectors will stop working in a future release)"
        )
    for sup in suppset.unused():
        where = f" at {sup.source}" if sup.source else ""
        notices.append(f"suppression {sup.label()}{where} matched no findings")
    return SuppressionOutcome(
        active=active, suppressed=suppressed, warnings=warnings or [], notices=notices
    )


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


_FINDING_ID_RE = re.compile(r"^[0-9a-f]{16}$")
_SUPPORTED_VERSIONS = {1}


def _str_list(value: object) -> list[str] | None:
    """A ``paths`` value as a list of strings, or None when malformed."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return list(value)
    return None


def _load_yaml_entries(path: Path, warnings: list[str], *, root: Path | None = None) -> list[Suppression]:
    """Parse a suppress file. Never raises (#225): every problem becomes a
    ``Suppression warning`` and the offending entry (or file) is skipped."""
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        warnings.append(
            f"{path.name} found but PyYAML is not installed; suppressions ignored. "
            "Install attackmap with its dependencies to enable suppression."
        )
        return []
    try:
        # A repo-provided suppress file is read like any repo file: never
        # through a symlink out of the repo (#234).
        text = read_repo_text(root, path) if root is not None else path.read_text(encoding="utf-8")
        data = yaml.safe_load(text)
    except UnicodeDecodeError:
        warnings.append(f"{path.name} is not valid UTF-8; suppressions ignored")
        return []
    except (OSError, yaml.YAMLError) as exc:  # type: ignore[attr-defined]
        warnings.append(f"Failed to parse {path.name}: {exc}")
        return []

    if isinstance(data, dict):
        version = data.get("version", 1)
        if version not in _SUPPORTED_VERSIONS:
            warnings.append(f"{path.name}: unknown version {version!r} (supported: 1); reading it as version 1")
        entries = data.get("suppress", data.get("suppressions", []))
        if entries is None:
            entries = []
    elif isinstance(data, list):
        entries = data
    elif data is None:
        entries = []
    else:
        warnings.append(f"{path.name}: expected a list or a mapping with 'suppress:'")
        return []
    if not isinstance(entries, list):
        warnings.append(f"{path.name}: 'suppress' must be a list of entries, got {type(entries).__name__}")
        return []

    suppressions: list[Suppression] = []
    for index, raw in enumerate(entries, start=1):
        where = f"{path.name} entry {index}"
        if not isinstance(raw, dict):
            warnings.append(f"{where}: skipping non-mapping entry {raw!r}")
            continue
        reason = raw.get("reason", "")
        if not isinstance(reason, str) or not reason.strip():
            warnings.append(f"{where}: skipping entry without a text 'reason'")
            continue
        reason = reason.strip()

        sup_id = raw.get("id")
        if sup_id is not None:
            if not isinstance(sup_id, str):
                warnings.append(
                    f"{where}: id {sup_id!r} was read as {type(sup_id).__name__}, not text — quote it "
                    "(e.g. id: \"0123456789abcdef\"); YAML turns digit-only or 0-prefixed ids into numbers"
                )
                continue
            if not _FINDING_ID_RE.match(sup_id.strip()):
                warnings.append(f"{where}: id {sup_id!r} is not a 16-hex finding id; skipping")
                continue
            sup_id = sup_id.strip()

        rule = raw.get("rule")
        if rule is not None and (not isinstance(rule, str) or not rule.strip()):
            warnings.append(f"{where}: 'rule' must be a rule id string (see `attackmap rules`); skipping")
            continue

        globs = raw.get("paths", raw.get("path"))
        glob_list: list[str] = []
        if globs is not None:
            parsed = _str_list(globs)
            if parsed is None:
                warnings.append(f"{where}: 'paths' must be a string or a list of strings, got {globs!r}; skipping")
                continue
            glob_list = [g for g in parsed if g.strip()]

        if not (sup_id or rule or glob_list):
            warnings.append(f"{where}: skipping entry with no selector (id/rule/path)")
            continue

        source = where
        if sup_id:
            suppressions.append(Suppression(reason=reason, id=sup_id, origin="file", source=source))
        if glob_list:
            for glob in glob_list:
                suppressions.append(
                    Suppression(reason=reason, rule=rule, path=glob, origin="file", source=source)
                )
        elif rule:
            suppressions.append(Suppression(reason=reason, rule=rule, origin="file", source=source))
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
        if candidate.exists() or candidate.is_symlink():
            return _load_yaml_entries(candidate, warnings, root=root)
    return []


def scan_inline_suppressions(
    root: Path, findings: list[Finding], warnings: list[str] | None = None
) -> list[Suppression]:
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
        file_path = contained_file(root, rel)
        try:
            if file_path is None:
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
            file_wide = "attackmap:ignore-file" in line.lower()
            scope_line = None if file_wide else lineno
            rule_tokens = [r.strip() for r in (rules_raw or "").split(",") if r.strip()]
            if not rule_tokens and warnings is not None:
                warnings.append(
                    f"bare attackmap:ignore{'-file' if file_wide else ''} at {source} matches every rule; "
                    "name the rule (attackmap:ignore[rule-id]) — see `attackmap rules`"
                )
            for token in rule_tokens or [None]:
                suppressions.append(
                    Suppression(
                        reason=reason,
                        rule=token,
                        path=rel,
                        line=scope_line,
                        origin="inline",
                        source=source,
                    )
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
        suppressions.extend(scan_inline_suppressions(root, findings, warnings))
    return SuppressionSet(suppressions), warnings
