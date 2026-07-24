"""Precision/recall benchmark harness (#197).

The 1.0 precision gate. Where ``review_eval`` grades LLM *review text*, this
scores AttackMap's *findings* against a hand-labeled corpus of ground-truth
vulnerabilities, and reports precision/recall/F1 **per detector class**.

## How it works

- A **benchmark manifest** (`evals/benchmark/benchmark.json`) lists cases. Each
  case points at a repo path and declares `expected` — the genuine, exploitable
  weaknesses in that repo, labeled *independently of what the tool emits* (so the
  score isn't circular). Each label carries a canonical `category`, the
  `file`/`line`/`route`/`method`, and a note.
- Only **scored categories** (precise detector classes — injection, BOLA,
  unauth-state-change, webhook-exposure, crypto, CVE) are held to
  precision/recall. Architectural / advisory findings (e.g. "public routes sit
  near sensitive data") make no precise claim and are *out of scope* — they never
  count as false positives.
- Each finding is mapped to a canonical category from its tags/title, and matched
  to an expected label when the category agrees and the finding's evidence cites
  the same file (refined by route substring or a line within a small window).

Recall counts *expected labels matched by ≥1 finding*; precision counts *scored
findings that matched ≥1 label* — so a single grouped finding that legitimately
cites several true routes helps recall without being penalized.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

# --- canonical detector classes ---------------------------------------------

# Precise detector classes we hold to precision/recall. Everything else a
# finding might carry (admin-exposure grouping, secret-env references, generic
# "public route near data" insight) is advisory and deliberately unscored.
SCORED_CATEGORIES: tuple[str, ...] = (
    "injection",
    "bola",
    "unauth_state_change",
    "webhook_exposure",
    "crypto",
    "cve",
)

_INJECTION_MARKERS = (
    "injection",
    "sql",
    "ssrf",
    "ssti",
    "nosql",
    "deserial",
    "command exec",
    "code execution",
    "open redirect",
    "path traversal",
)


def canonical_category(finding: dict[str, Any]) -> str:
    """Map a report-shaped finding to a canonical detector class.

    Returns a scored class from :data:`SCORED_CATEGORIES` or one of the advisory
    buckets (``secret_env`` / ``admin_exposure`` / ``advisory``) that the scorer
    ignores. The order is a priority: most specific first.
    """
    tags = {t.lower() for t in finding.get("tags", [])}
    title = (finding.get("title") or "").lower()
    text = title + " " + " ".join(finding.get("evidence", [])).lower()

    if "dependency" in tags or "cve" in tags:
        return "cve"
    if any(m in tags for m in ("crypto", "weak-crypto", "insecure-crypto")) or "weak random" in title:
        return "crypto"
    if any(m in title or m in tags for m in _INJECTION_MARKERS):
        return "injection"
    if "broken-authorization" in tags or "bola" in title or "idor" in title:
        return "bola"
    if "auth-missing" in tags and "webhook" in title:
        return "webhook_exposure"
    if "auth-missing" in tags and "state-changing" in tags:
        return "unauth_state_change"
    if "secret-exposure" in tags:
        return "secret_env"
    if "privileged" in tags or "administrative" in title:
        return "admin_exposure"
    return "advisory"


# --- data model --------------------------------------------------------------


@dataclass
class Expected:
    category: str
    file: str
    line: int | None = None
    route: str | None = None
    method: str | None = None
    severity: str | None = None
    note: str = ""


@dataclass
class Case:
    id: str
    path: str
    expected: list[Expected]
    modules: list[str] = field(default_factory=list)


@dataclass
class Benchmark:
    scored_categories: tuple[str, ...]
    line_window: int
    cases: list[Case]


def load_benchmark(path: str | Path) -> Benchmark:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    cases = [
        Case(
            id=c["id"],
            path=c["path"],
            modules=list(c.get("modules", [])),
            expected=[Expected(**e) for e in c.get("expected", [])],
        )
        for c in data.get("cases", [])
    ]
    scored = tuple(data.get("scored_categories", SCORED_CATEGORIES))
    return Benchmark(scored_categories=scored, line_window=int(data.get("line_window", 8)), cases=cases)


# --- matching ----------------------------------------------------------------

_LOC_RE = re.compile(r"([\w./-]+\.[A-Za-z0-9_]+):(\d+)")


def _finding_locations(finding: dict[str, Any]) -> list[tuple[str, int]]:
    """Every ``file:line`` cited in a finding's title + evidence."""
    text = (finding.get("title") or "") + "\n" + "\n".join(finding.get("evidence", []))
    return [(m.group(1), int(m.group(2))) for m in _LOC_RE.finditer(text)]


def _finding_text(finding: dict[str, Any]) -> str:
    return ((finding.get("title") or "") + " " + " ".join(finding.get("evidence", []))).lower()


def _matches(finding: dict[str, Any], exp: Expected, window: int) -> bool:
    """True if ``finding`` corroborates the expected label.

    Requires the finding to cite ``exp.file`` (basename match), then refines by
    route substring or a cited line within ``window`` of ``exp.line``. When the
    finding carries neither a matching line nor route but does cite the file, a
    file-level match is accepted (single-signal cases).
    """
    locs = _finding_locations(finding)
    exp_base = Path(exp.file).name
    file_locs = [ln for (f, ln) in locs if Path(f).name == exp_base]
    text = _finding_text(finding)
    file_hit = bool(file_locs) or exp_base.lower() in text
    if not file_hit:
        return False
    if exp.route and exp.route.lower() in text:
        return True
    if exp.line is not None and any(abs(ln - exp.line) <= window for ln in file_locs):
        return True
    # File cited but no finer signal to disambiguate on either side → accept.
    if exp.route is None and exp.line is None:
        return True
    # File matched but the finding offered a line and none was near, or a route
    # that didn't appear: only accept if the finding gave no line at all.
    return not file_locs and exp.route is None


@dataclass
class CategoryScore:
    category: str
    tp: int = 0        # scored findings that matched ≥1 expected
    fp: int = 0        # scored findings that matched no expected
    fn: int = 0        # expected labels matched by no finding
    matched_expected: list[str] = field(default_factory=list)
    missed_expected: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)

    @property
    def precision(self) -> float | None:
        denom = self.tp + self.fp
        return None if denom == 0 else self.tp / denom

    @property
    def recall(self) -> float | None:
        denom = self.tp_expected_total
        return None if denom == 0 else len(self.matched_expected) / denom

    @property
    def tp_expected_total(self) -> int:
        return len(self.matched_expected) + len(self.missed_expected)

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if not p or not r:
            return None
        return 2 * p * r / (p + r)


def score_case(
    findings: list[dict[str, Any]],
    expected: list[Expected],
    scored_categories: Iterable[str],
    window: int,
) -> dict[str, CategoryScore]:
    scored = set(scored_categories)
    scores: dict[str, CategoryScore] = {}

    def cat(name: str) -> CategoryScore:
        return scores.setdefault(name, CategoryScore(category=name))

    # Categorize findings; only scored-category findings participate.
    finding_cats = [(f, canonical_category(f)) for f in findings]
    scored_findings = [(f, c) for f, c in finding_cats if c in scored]

    # Recall: which expected labels does any finding of the same category match?
    for exp in expected:
        if exp.category not in scored:
            continue
        cs = cat(exp.category)
        label = f"{exp.method or ''} {exp.route or exp.file}:{exp.line or ''}".strip()
        if any(c == exp.category and _matches(f, exp, window) for f, c in scored_findings):
            cs.matched_expected.append(label)
        else:
            cs.missed_expected.append(label)

    # Precision: each scored finding is a TP if it matched ≥1 expected, else FP.
    for f, c in scored_findings:
        cs = cat(c)
        exp_in_cat = [e for e in expected if e.category == c]
        if any(_matches(f, e, window) for e in exp_in_cat):
            cs.tp += 1
        else:
            cs.fp += 1
            cs.false_positives.append(f.get("title", "")[:80])

    return scores


# --- running -----------------------------------------------------------------


def findings_for_repo(root: str | Path) -> list[dict[str, Any]]:
    """Run the heuristic analysis in-process and return report-shaped findings."""
    from .analyzers import analyze_repository
    from .diff import finding_id
    from .threat_model import generate_findings

    scan = analyze_repository(str(root))
    out = []
    for f in generate_findings(scan):
        d = f.model_dump()
        d["id"] = finding_id(f.title)
        out.append(d)
    return out


@dataclass
class CaseResult:
    id: str
    scores: dict[str, CategoryScore]
    finding_count: int
    error: str | None = None


def run_benchmark(
    benchmark: Benchmark,
    root: str | Path,
    analyze: Callable[[str | Path], list[dict[str, Any]]] = findings_for_repo,
) -> list[CaseResult]:
    root = Path(root)
    results: list[CaseResult] = []
    for case in benchmark.cases:
        case_path = root / case.path
        try:
            findings = analyze(case_path)
        except Exception as exc:  # a scan failure is a benchmark result, not a crash
            results.append(CaseResult(id=case.id, scores={}, finding_count=0, error=str(exc)))
            continue
        scores = score_case(findings, case.expected, benchmark.scored_categories, benchmark.line_window)
        results.append(CaseResult(id=case.id, scores=scores, finding_count=len(findings)))
    return results


def aggregate(results: list[CaseResult]) -> dict[str, CategoryScore]:
    """Sum per-category scores across all cases into an overall table."""
    overall: dict[str, CategoryScore] = {}
    for r in results:
        for name, cs in r.scores.items():
            agg = overall.setdefault(name, CategoryScore(category=name))
            agg.tp += cs.tp
            agg.fp += cs.fp
            agg.matched_expected += cs.matched_expected
            agg.missed_expected += cs.missed_expected
            agg.false_positives += cs.false_positives
    return overall


# --- rendering ---------------------------------------------------------------


def _pct(x: float | None) -> str:
    return "—" if x is None else f"{x * 100:.0f}%"


def render_markdown(results: list[CaseResult]) -> str:
    overall = aggregate(results)
    lines = ["# AttackMap detection benchmark", ""]
    lines.append("Precision/recall per detector class, scored against a hand-labeled corpus.")
    lines.append("Only precise detector classes are scored; advisory/architectural findings are out of scope.")
    lines.append("")
    lines.append("## Overall")
    lines.append("")
    lines.append("| Detector class | Precision | Recall | F1 | TP | FP | Expected |")
    lines.append("|---|---|---|---|---|---|---|")
    for name in sorted(overall):
        cs = overall[name]
        lines.append(
            f"| `{name}` | {_pct(cs.precision)} | {_pct(cs.recall)} | {_pct(cs.f1)} "
            f"| {cs.tp} | {cs.fp} | {cs.tp_expected_total} |"
        )
    lines.append("")
    lines.append("## Per case")
    for r in results:
        lines.append("")
        if r.error:
            lines.append(f"### {r.id} — ERROR")
            lines.append(f"```\n{r.error}\n```")
            continue
        lines.append(f"### {r.id}  ({r.finding_count} findings)")
        lines.append("")
        lines.append("| Detector class | Precision | Recall | Missed (recall gaps) | False positives |")
        lines.append("|---|---|---|---|---|")
        for name in sorted(r.scores):
            cs = r.scores[name]
            missed = "; ".join(cs.missed_expected) or "—"
            fps = "; ".join(cs.false_positives) or "—"
            lines.append(f"| `{name}` | {_pct(cs.precision)} | {_pct(cs.recall)} | {missed} | {fps} |")
    lines.append("")
    return "\n".join(lines)


def bench_json(results: list[CaseResult]) -> dict[str, Any]:
    def cat_dict(cs: CategoryScore) -> dict[str, Any]:
        return {
            "precision": cs.precision,
            "recall": cs.recall,
            "f1": cs.f1,
            "tp": cs.tp,
            "fp": cs.fp,
            "expected_total": cs.tp_expected_total,
            "matched_expected": cs.matched_expected,
            "missed_expected": cs.missed_expected,
            "false_positives": cs.false_positives,
        }

    overall = aggregate(results)
    return {
        "overall": {name: cat_dict(cs) for name, cs in sorted(overall.items())},
        "cases": [
            {
                "id": r.id,
                "finding_count": r.finding_count,
                "error": r.error,
                "categories": {name: cat_dict(cs) for name, cs in sorted(r.scores.items())},
            }
            for r in results
        ],
    }


def min_scored_metric(results: list[CaseResult]) -> float:
    """The lowest defined precision/recall across all scored categories — used by
    the CI `--fail-under` gate. Returns 1.0 when nothing scorable ran."""
    vals: list[float] = []
    for cs in aggregate(results).values():
        for m in (cs.precision, cs.recall):
            if m is not None:
                vals.append(m)
    return min(vals) if vals else 1.0


__all__ = [
    "Benchmark",
    "Case",
    "CaseResult",
    "CategoryScore",
    "Expected",
    "SCORED_CATEGORIES",
    "aggregate",
    "bench_json",
    "canonical_category",
    "findings_for_repo",
    "load_benchmark",
    "min_scored_metric",
    "render_markdown",
    "run_benchmark",
    "score_case",
]
