"""Tests for recall mode (#148a) — verifier-gated aggressive taint discovery."""

from __future__ import annotations

from pathlib import Path

from attackmap.models import Route, ScanResult, TaintChain
from attackmap.taint import (
    _MAX_HOPS,
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


# ---------------------------------------------------------------------------
# visit-cap-only discoveries are speculative too (#148a Codex P1 #2)
# ---------------------------------------------------------------------------


def test_visit_cap_only_discovery_is_speculative(tmp_path: Path) -> None:
    """A fan-out graph with 45 one-hop sink modules exceeds the default 40-file
    visit budget. The modules the default pass never processes are recall-only
    even though they sit within the default hop depth — they must be marked
    speculative (not just deep-hop chains)."""
    n = 45
    imports = "\n".join(f"from m{i} import f{i}" for i in range(n))
    calls = "\n".join(f"    f{i}(x)" for i in range(n))
    _write(tmp_path, "a.py", f"{imports}\n\n\ndef handler(x):\n{calls}\n")
    for i in range(n):
        _write(tmp_path, f"m{i}.py",
               f"import subprocess\n\n\ndef f{i}(x):\n    subprocess.run(x, shell=True)\n")
    scan = ScanResult(root=str(tmp_path), routes=[Route(path="/x", method="GET", file="a.py", line=n + 3)])

    default = [c for c in analyze_taint(scan, tmp_path) if c.sink_kind == "subprocess_shell"]
    aggressive = [c for c in analyze_taint(scan, tmp_path, recall=recall_config())
                  if c.sink_kind == "subprocess_shell"]

    assert len(aggressive) > len(default)  # widened cap reached more modules
    spec = [c for c in aggressive if c.speculative]
    assert spec, "expected visit-cap-only speculative chains"
    # These are speculative because of the visit cap, not hop depth (all 1 hop).
    assert all(c.hops <= _MAX_HOPS for c in spec)
    assert all(not c.speculative for c in default)


# ---------------------------------------------------------------------------
# speculative chains never feed asserted downstream findings (#148a Codex P1 #1)
# ---------------------------------------------------------------------------


def test_speculative_sql_chain_not_scored_exploitable(tmp_path: Path) -> None:
    from attackmap.exploitability import score_exploitability

    scan = ScanResult(
        root=str(tmp_path),
        routes=[Route(path="/orders/{id}", method="GET", file="r.py", line=1)],
        taint_chains=[
            TaintChain(
                route_path="/orders/{id}", route_method="GET", route_file="r.py",
                sink_kind="sql_execute", sink_file="db.py", sink_line=3, hops=1,
                files=["r.py", "db.py"], speculative=True,
            )
        ],
    )
    assert score_exploitability(scan, []) == []


def test_speculative_sql_chain_ignored_by_authz(tmp_path: Path) -> None:
    from attackmap.authz import analyze_authz

    # A path-param route whose ONLY datastore reachability is a speculative SQL
    # chain — with the fix it raises no BOLA candidate (would, without it).
    scan = ScanResult(
        root=str(tmp_path),
        routes=[Route(path="/orders/{id}", method="GET", file="r.py", line=1)],
        taint_chains=[
            TaintChain(
                route_path="/orders/{id}", route_method="GET", route_file="r.py",
                sink_kind="sql_execute", sink_file="db.py", sink_line=3, hops=1,
                files=["r.py", "db.py"], speculative=True,
            )
        ],
    )
    assert analyze_authz(scan, tmp_path) == []
