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


# ---------------------------------------------------------------------------
# capability-reach enumeration (#148b)
# ---------------------------------------------------------------------------


def _capability_repo(root: Path, body_line: str) -> ScanResult:
    _write(root, "app.py", f"import requests\n\n\ndef handler(request):\n    {body_line}\n")
    return ScanResult(root=str(root), routes=[Route(path="/x", method="GET", file="app.py", line=4)])


def test_default_ignores_constant_url_network_call(tmp_path: Path) -> None:
    """A constant-URL network call is not a signature hit — default stays quiet."""
    scan = _capability_repo(tmp_path, 'return requests.get("https://api.internal/health")')
    assert not [c for c in analyze_taint(scan, tmp_path) if c.sink_kind == "ssrf"]


def test_capability_reach_surfaces_constant_url_as_speculative(tmp_path: Path) -> None:
    """Recall surfaces the reach to the network capability even with no
    request-derived argument — speculative (#148b acceptance)."""
    scan = _capability_repo(tmp_path, 'return requests.get("https://api.internal/health")')
    ssrf = [c for c in analyze_taint(scan, tmp_path, recall=recall_config()) if c.sink_kind == "ssrf"]
    assert len(ssrf) == 1
    assert ssrf[0].speculative is True


def test_capability_reach_does_not_duplicate_request_derived_sink(tmp_path: Path) -> None:
    """When the argument IS request-derived, the gated pass already fires — the
    capability pass must not emit a duplicate speculative hit at the same line."""
    scan = _capability_repo(tmp_path, 'return requests.get(request.args["url"])')
    ssrf = [c for c in analyze_taint(scan, tmp_path, recall=recall_config()) if c.sink_kind == "ssrf"]
    assert len(ssrf) == 1
    # The genuine request-derived reach stays a confirmed (non-speculative) hit.
    assert ssrf[0].speculative is False


def test_capability_reach_covers_fs_template_redirect(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "app.py",
        "from flask import redirect, render_template_string\n\n\n"
        "def handler():\n"
        '    render_template_string("hello")\n'
        '    open("/etc/config")\n'
        '    return redirect("/home")\n',
    )
    scan = ScanResult(root=str(tmp_path), routes=[Route(path="/x", method="GET", file="app.py", line=4)])
    kinds = {
        c.sink_kind
        for c in analyze_taint(scan, tmp_path, recall=recall_config())
        if c.speculative
    }
    assert {"ssti", "dynamic_open", "open_redirect"} <= kinds


def test_capability_reach_off_without_recall(tmp_path: Path) -> None:
    scan = _capability_repo(tmp_path, 'return requests.get("https://api.internal/health")')
    # Even the widest non-capability knobs don't enumerate bare capabilities.
    cfg = RecallConfig(max_hops=4, include_static_args=True)  # capability_reach=False
    assert not [c for c in analyze_taint(scan, tmp_path, recall=cfg) if c.sink_kind == "ssrf"]


def test_capability_reach_not_suppressed_by_file_sanitizer(tmp_path: Path) -> None:
    """A sanitizer token in the reachable file must not mark a bare
    capability-reach hit sanitized — that would make generate_findings drop it
    and silently lose the capability inventory (#148b Codex P2)."""
    _write(
        tmp_path,
        "app.py",
        "import requests\n\n\n"
        "def handler():\n"
        "    if is_safe_url(target):\n"  # a recognized SSRF/redirect sanitizer token
        '        return requests.get("https://internal/")\n',
    )
    scan = ScanResult(root=str(tmp_path), routes=[Route(path="/x", method="GET", file="app.py", line=4)])
    chains = analyze_taint(scan, tmp_path, recall=recall_config())
    ssrf = [c for c in chains if c.sink_kind == "ssrf"]
    assert len(ssrf) == 1
    assert ssrf[0].speculative is True
    assert ssrf[0].sanitized is False  # capability reaches carry no sanitizer status

    scan.taint_chains = chains
    findings = generate_findings(scan, [])
    assert [f for f in findings if "speculative" in f.tags], "capability finding must survive"
