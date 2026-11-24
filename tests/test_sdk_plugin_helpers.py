"""SDK plugin helpers (#382, #384) and plugin-emitted deep-pass records (#257)."""

from __future__ import annotations

from pathlib import Path

import pytest

import attackmap
from attackmap.exploitability import score_exploitability
from attackmap.sdk import (
    AuthHint,
    Route,
    ScanResult,
    SignalCollector,
    TaintChain,
    line_of,
    line_snippet,
    plugin_version,
    snippet_at,
)
from attackmap.taint import analyze_taint
from attackmap.threat_model import generate_findings


def test_signal_collector_keeps_the_first_record_per_identity() -> None:
    result = ScanResult(root="/r", routes=[Route(path="/a", method="GET", file="x.py", line=1)])
    signals = SignalCollector(result)
    assert not signals.add(Route(path="/a", method="GET", file="x.py", line=9))  # seeded from result
    assert signals.add(Route(path="/a", method="POST", file="x.py", line=2))
    assert signals.add(AuthHint(hint="jwt", file="x.py", line=3))
    assert not signals.add(AuthHint(hint="jwt", file="x.py", line=4))
    assert [(r.method, r.line) for r in result.routes] == [("GET", 1), ("POST", 2)]
    assert [h.line for h in result.auth_hints] == [3]
    with pytest.raises(TypeError):
        signals.add(object())


def test_snippet_at_matches_line_snippet() -> None:
    content = "first\n  second line  \f still second\nx" + "y" * 300
    for offset in (0, 8, 25, len(content) - 1):
        assert snippet_at(content, offset) == line_snippet(content, line_of(content, offset))
    assert snippet_at(content, len(content) - 1).endswith("…")


def test_plugin_version_reads_the_installed_distribution() -> None:
    assert plugin_version("attackmap") == attackmap.__version__
    assert plugin_version("attackmap-no-such-plugin") == "0+unknown"


def test_plugin_route_in_java_reaches_a_ranked_sink(tmp_path: Path) -> None:
    # #257: a plugin reports the route; core's taint pass finds the sink.
    (tmp_path / "RunController.java").write_text(
        "@RestController\npublic class RunController {\n  @PostMapping(\"/run\")\n"
        "  public String run(@RequestParam String cmd) throws Exception {\n"
        "    Runtime.getRuntime().exec(cmd);\n    return \"ok\";\n  }\n}\n"
    )
    scan = ScanResult(root=str(tmp_path), routes=[Route(path="/run", method="POST", file="RunController.java", line=3)])
    scan.taint_chains = analyze_taint(scan, tmp_path)
    [top] = score_exploitability(scan)[:1]
    assert (top.route, top.location) == ("/run", "RunController.java:5")


def test_plugin_emitted_chain_becomes_a_scored_finding() -> None:
    # #257: a C plugin ties a CGI handler to system() itself.
    chain = TaintChain(
        route_path="/cgi-bin/run", route_method="GET", route_file="cgi/run.c",
        sink_kind="subprocess_shell", sink_file="cgi/run.c", sink_line=12, hops=0, source_kind="query",
    )
    scan = ScanResult(root="/r", routes=[Route(path="/cgi-bin/run", method="GET", file="cgi/run.c", line=3)], taint_chains=[chain])
    [finding] = [f for f in generate_findings(scan) if "taint-chain" in f.tags]
    assert finding.exploitability is not None and finding.locations[0].file == "cgi/run.c"
