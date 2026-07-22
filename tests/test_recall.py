"""Tests for recall mode (#148a) — verifier-gated aggressive taint discovery."""

from __future__ import annotations

from pathlib import Path

from attackmap.models import Route, ScanResult
from attackmap.taint import (
    DEFAULT_RECALL,
    RecallConfig,
    analyze_taint,
    recall_config,
)
from attackmap.threat_model import generate_findings


def _write(root: Path, name: str, body: str) -> None:
    (root / name).write_text(body, encoding="utf-8")


def _deep_chain_repo(root: Path) -> ScanResult:
    """route a.py → b → c → d(sink): the sink sits 3 hops out, past the
    default _MAX_HOPS of 2."""
    _write(root, "a.py", "from b import step_b\n\n\ndef handler(x):\n    return step_b(x)\n")
    _write(root, "b.py", "from c import step_c\n\n\ndef step_b(x):\n    return step_c(x)\n")
    _write(root, "c.py", "from d import sink\n\n\ndef step_c(x):\n    return sink(x)\n")
    _write(root, "d.py", "def sink(x):\n    return eval(x)\n")
    return ScanResult(
        root=str(root),
        routes=[Route(path="/x", method="GET", file="a.py", line=4)],
    )


def _static_arg_repo(root: Path) -> ScanResult:
    """A same-file eval() with a static-literal argument — the default pass
    suppresses it (#88), recall keeps it as a speculative lead."""
    _write(
        root,
        "app.py",
        'def handler(x):\n    return eval("1 + 1")\n',
    )
    return ScanResult(
        root=str(root),
        routes=[Route(path="/x", method="GET", file="app.py", line=1)],
    )


# ---------------------------------------------------------------------------
# knobs
# ---------------------------------------------------------------------------


def test_recall_config_aggressive_flag() -> None:
    assert not DEFAULT_RECALL.aggressive
    assert recall_config().aggressive
    assert RecallConfig(include_static_args=True).aggressive
    assert RecallConfig(max_hops=3).aggressive


# ---------------------------------------------------------------------------
# deeper hop depth
# ---------------------------------------------------------------------------


def test_default_misses_deep_chain(tmp_path: Path) -> None:
    scan = _deep_chain_repo(tmp_path)
    chains = analyze_taint(scan, tmp_path)  # DEFAULT_RECALL
    assert not [c for c in chains if c.sink_kind == "eval"]


def test_recall_surfaces_deep_chain_as_speculative(tmp_path: Path) -> None:
    scan = _deep_chain_repo(tmp_path)
    chains = analyze_taint(scan, tmp_path, recall=recall_config())
    reached = [c for c in chains if c.sink_kind == "eval"]
    assert len(reached) == 1
    assert reached[0].hops == 3
    assert reached[0].speculative is True
    # Speculative chains are docked below the HIGH threshold.
    assert reached[0].confidence < 0.5


# ---------------------------------------------------------------------------
# relaxed static-arg gate
# ---------------------------------------------------------------------------


def test_default_suppresses_static_arg(tmp_path: Path) -> None:
    scan = _static_arg_repo(tmp_path)
    chains = analyze_taint(scan, tmp_path)
    assert not [c for c in chains if c.sink_kind == "eval"]


def test_recall_surfaces_static_arg_as_speculative(tmp_path: Path) -> None:
    scan = _static_arg_repo(tmp_path)
    chains = analyze_taint(scan, tmp_path, recall=recall_config())
    evals = [c for c in chains if c.sink_kind == "eval"]
    assert len(evals) == 1
    assert evals[0].speculative is True


def test_recall_surfaces_more_than_default(tmp_path: Path) -> None:
    """Acceptance: recall surfaces strictly more candidate paths than default."""
    scan = _deep_chain_repo(tmp_path)
    default = analyze_taint(scan, tmp_path)
    aggressive = analyze_taint(scan, tmp_path, recall=recall_config())
    assert len(aggressive) > len(default)


# ---------------------------------------------------------------------------
# default behavior unchanged
# ---------------------------------------------------------------------------


def test_normal_chain_not_speculative_in_either_mode(tmp_path: Path) -> None:
    """A conservative-reachable, non-relaxed chain is identical (and never
    speculative) in default and recall runs."""
    _write(root := tmp_path, "app.py",
           'from svc import run\n\n\ndef handler(x):\n    return run(x)\n')
    _write(root, "svc.py",
           'def run(x):\n    return cursor.execute("SELECT * FROM t WHERE id=" + x)\n')
    scan = ScanResult(root=str(root), routes=[Route(path="/x", method="GET", file="app.py", line=4)])
    default = [c for c in analyze_taint(scan, tmp_path) if c.sink_kind == "sql_execute"]
    aggressive = [c for c in analyze_taint(scan, tmp_path, recall=recall_config()) if c.sink_kind == "sql_execute"]
    assert len(default) == 1 and default[0].speculative is False
    assert len(aggressive) == 1 and aggressive[0].speculative is False
    assert default[0].confidence == aggressive[0].confidence


# ---------------------------------------------------------------------------
# threat_model surfacing
# ---------------------------------------------------------------------------


def test_speculative_finding_is_low_severity_and_marked(tmp_path: Path) -> None:
    scan = _deep_chain_repo(tmp_path)
    scan.taint_chains = analyze_taint(scan, tmp_path, recall=recall_config())
    findings = generate_findings(scan, [])
    spec = [f for f in findings if "speculative" in f.tags]
    assert spec, "expected a speculative recall finding"
    f = spec[0]
    assert f.severity == "low"
    assert "recall" in f.tags
    assert any("SPECULATIVE" in e for e in f.evidence)
    # A low-severity finding never trips the new-HIGH gate.
    assert f.severity != "high"


def test_no_speculative_findings_without_recall(tmp_path: Path) -> None:
    scan = _deep_chain_repo(tmp_path)
    scan.taint_chains = analyze_taint(scan, tmp_path)  # default
    findings = generate_findings(scan, [])
    assert not [f for f in findings if "speculative" in f.tags]
