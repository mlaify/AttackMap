"""Repo-derived text can't inject Markdown into AttackMap's outputs (#233, part B)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from attackmap.analyzer import summarize_attack_surface
from attackmap.cli import app
from attackmap.defensive_review import render_defensive_review
from attackmap.diagrams import (
    render_attack_paths_dot,
    render_attack_paths_mermaid,
    render_topology_dot,
    render_topology_mermaid,
)
from attackmap.contracts import ContractLink
from attackmap.crossrepo import CrossBoundaryFlow, CrossRepoAnomaly, TrustGap
from attackmap.diff import DiffReport, FindingSnapshot, render_diff_markdown
from attackmap.fleet import FleetRepoResult, FleetScan, render_fleet_graph_mermaid, render_fleet_summary
from attackmap.md import md_code, md_text, sanitize_llm_markdown
from attackmap.models import (
    AttackPath,
    AttackSurface,
    AuthHint,
    ExploitabilityFactor,
    ExploitabilityScore,
    ExternalCall,
    Finding,
    ScanResult,
    SecretHint,
)
from attackmap.report import render_exploitability_ranking, render_pr_comment
from attackmap.sarif import build_sarif
from attackmap.topology import ServiceEdge, ServiceGraph, ServiceNode

HOSTILE = "/x](https://evil.example/login) <img src=https://evil.example/p.png> @org/security-team ‮gnp.exe ` "
# A terminal hyperlink (OSC 8) and a colour code: raw ESC must never reach a file.
TERMINAL = "/t\x1b]8;;https://evil.example\x1b\\click\x1b]8;;\x1b\\ \x1b[2K\x1b[31mred"


_CODE_SPAN = re.compile(r"(`+)(.+?)\1")


def _assert_inert(markdown: str) -> None:
    """None of the hostile constructs would render: outside code spans every
    link/HTML/mention/autolink is escaped or broken; bidi is never raw."""
    assert "\u202e" not in markdown  # bidi override shown escaped, never applied
    prose = _CODE_SPAN.sub("", markdown)
    assert not re.search(r"(?<!\\)\]\(", prose), "live Markdown link"
    assert not re.search(r"(?<!\\)<(?!/?sub>)[A-Za-z!/]", prose), "raw HTML"
    assert not re.search(r"(?<![\w;])@[A-Za-z]", prose), "live @mention"
    assert "https://evil" not in prose, "live autolink"


def _hostile_finding() -> Finding:
    return Finding(
        title=f"Vulnerable dependency: {HOSTILE}@1.0 (pypi)",
        severity="high",
        mitigation="Upgrade.",
        evidence=[f"app.py:3 — @app.post('{HOSTILE}')"],
        exploitability=90,
        exploitability_tier="critical",
    )


def test_md_text_neutralizes_every_construct() -> None:
    out = md_text(HOSTILE)
    assert "\\]\\(" in out and "\\<img" in out
    assert "@&#8203;org" in out
    assert "https:&#8203;//evil" in out
    assert "\\u202e" in out
    assert "\n" not in md_text("a\nb")


@pytest.mark.parametrize("value", ["plain", "has `tick`", "``double``", "`edge", HOSTILE])
def test_md_code_fence_cannot_be_closed_early(value: str) -> None:
    span = md_code(value)
    fence = re.match(r"`+", span).group(0)
    inner = span[len(fence) : -len(fence)]
    assert fence not in inner
    assert span.endswith(fence)


def test_pr_comment_is_inert() -> None:
    finding = _hostile_finding()
    snapshot = FindingSnapshot.from_finding(finding)
    _assert_inert(render_pr_comment([finding], DiffReport(new=[snapshot])))
    _assert_inert(render_pr_comment([finding]))


def test_diff_markdown_is_inert() -> None:
    snapshot = FindingSnapshot.from_finding(_hostile_finding())
    md = render_diff_markdown(DiffReport(new=[snapshot]))
    _assert_inert(md)
    assert "`" in md  # evidence rendered as a code span


def test_sarif_markdown_is_inert() -> None:
    sarif = build_sarif([_hostile_finding()], [])
    for run in sarif["runs"]:
        for result in run["results"]:
            _assert_inert(result["message"]["markdown"])


def test_defensive_review_is_inert() -> None:
    scan = ScanResult(root=".", languages=["python"], files_scanned=1)
    surface = AttackSurface(
        route=HOSTILE, method="POST", file="app.py", category="admin", exposure="public", risk="high",
        auth_signals=[], data_store_interaction=True,
    )
    path = AttackPath(name=f"Path via {HOSTILE}", steps=[f"Entry: {HOSTILE}"], impact="x")
    _assert_inert(render_defensive_review(scan, [surface], [_hostile_finding()], [path]))


def test_attack_surface_markdown_is_inert() -> None:
    scan = ScanResult(
        root=".", languages=["python"], files_scanned=1,
        external_calls=[ExternalCall(target=HOSTILE, file=HOSTILE)],
        secret_hints=[SecretHint(name=HOSTILE, file=HOSTILE)],
        auth_hints=[AuthHint(hint=HOSTILE, file="app.py")],
    )
    surfaces = [
        AttackSurface(
            route=HOSTILE, method=HOSTILE, file=HOSTILE, category=category, exposure=exposure, risk="high",
            auth_signals=[HOSTILE],
        )
        # One per section: highest-risk, auth/admin, public, operational.
        for category, exposure in (("admin", "public"), ("public_api", "public"), ("health", "internal"))
    ]
    md = summarize_attack_surface(scan, surfaces)
    _assert_inert(md)
    assert md.count("evil.example") >= 7  # escaped, not dropped


def test_exploitability_markdown_is_inert() -> None:
    score = ExploitabilityScore(
        subject=f"POST {HOSTILE} → subprocess_shell", route=HOSTILE, method="POST", sink_kind="subprocess_shell",
        location=f"{HOSTILE}:12", score=90, raw_score=90, tier="critical",
        factors=[ExploitabilityFactor(name=f"dependency ({HOSTILE})", points=20, detail=f"entry route {HOSTILE}")],
    )
    md = render_exploitability_ranking([score])
    _assert_inert(md)
    assert "evil.example" in md
    # Escaped at render time only: the score itself keeps the raw value.
    assert score.route == HOSTILE


_MERMAID_BLOCK = re.compile(r"```mermaid\n(.*?)\n```", re.S)


def _assert_attack_paths_inert(markdown: str) -> None:
    """Outside the Mermaid blocks the document is inert Markdown; inside,
    labels carry no raw HTML or backticks and can't close the block."""
    blocks = _MERMAID_BLOCK.findall(markdown)
    assert blocks
    _assert_inert(_MERMAID_BLOCK.sub("", markdown))
    for block in blocks:
        labels = re.sub(r"[-.=]>", "", block)  # drop arrows (-->, .->, ==>)
        assert "<" not in labels and ">" not in labels, "raw HTML in a Mermaid label"
        assert "`" not in block


def test_attack_paths_markdown_is_inert() -> None:
    path = AttackPath(name=f"Path via {HOSTILE}", steps=[f"Entry: {HOSTILE}", f"`{HOSTILE}`"], impact=HOSTILE)
    md = render_attack_paths_mermaid([path])
    _assert_attack_paths_inert(md)
    assert "#lt;img" in md  # shown as text, not dropped


def _hostile_graph(text: str) -> ServiceGraph:
    return ServiceGraph(
        nodes=[ServiceNode(name=f"svc {text}", role=f"role {text}"), ServiceNode(name="db", role="datastore")],
        edges=[ServiceEdge(source=f"svc {text}", target="db", kind="http-call", file="app.py", evidence=text)],
    )


def test_topology_markdown_is_inert() -> None:
    md = render_topology_mermaid(_hostile_graph(HOSTILE))
    _assert_attack_paths_inert(md.replace("<br/><i>", "").replace("</i>", ""))
    assert "#lt;img" in md and "<br/><i>" in md  # role styling kept, repo text shown as text


def test_diagrams_never_carry_raw_control_characters() -> None:
    path = AttackPath(name=f"Path via {TERMINAL}", steps=[f"Entry: {TERMINAL}"], impact=TERMINAL)
    graph = _hostile_graph(TERMINAL)
    outputs = {
        "attackmap-paths.md": render_attack_paths_mermaid([path]),
        "attackmap-paths.dot": render_attack_paths_dot([path]),
        "attackmap-topology.md": render_topology_mermaid(graph),
        "attackmap-topology.dot": render_topology_dot(graph),
    }
    for name, text in outputs.items():
        assert "\x1b" not in text, f"raw ESC in {name}"
        assert "u001b" in text, f"ESC dropped instead of shown in {name}"


def test_llm_markdown_is_defanged() -> None:
    llm = (
        "## Review\n\nSee [the fix](https://evil.example/phish) and ![x](https://evil.example/p.png)\n"
        "<script>alert(1)</script><details><summary>hidden</summary>buried</details>\n"
        "cc @org/security-team — visit https://evil.example\n- keep **this** `code`\n"
    )
    out = sanitize_llm_markdown(llm)
    assert "<script>" not in out and "<details>" not in out
    assert "the fix (https:&#8203;//evil.example/phish)" in out
    assert "[image removed: x]" in out
    assert "@&#8203;org" in out
    assert "## Review" in out and "**this**" in out and "`code`" in out


def test_end_to_end_pr_comment_and_review(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "from flask import Flask, request\nimport subprocess\napp = Flask(__name__)\n\n"
        f"@app.route({json.dumps(HOSTILE)}, methods=['POST'])\n"
        "def admin():\n    subprocess.run(request.args['c'], shell=True)\n    return 'ok'\n",
        encoding="utf-8",
    )
    out = tmp_path / "out"
    result = CliRunner().invoke(
        app, ["analyze", str(repo), "-o", str(out), "--pr-comment", str(out / "pr-comment.md")]
    )
    assert result.exit_code == 0, result.output
    for name in ("pr-comment.md", "defensive-review.md", "attack-surface.md", "attackmap-exploitability.md"):
        _assert_inert((out / name).read_text(encoding="utf-8"))
    _assert_attack_paths_inert((out / "attackmap-paths.md").read_text(encoding="utf-8"))


def _hostile_fleet(text: str) -> FleetScan:
    def result(repo_id: str) -> FleetRepoResult:
        return FleetRepoResult(
            repo_id=repo_id, root=f"/repos/{text}", report_dir=f"/out/{repo_id}",
            scan=ScanResult(root=f"/repos/{repo_id}"), findings=[_hostile_finding()],
        )
    link = ContractLink(
        client_repo="client", server_repo="server", method="POST", path_template=f"a/{text}",
        client_target=f"http://a/{text}", client_file=f"c|{text}.py", client_line=3,
        server_route_path=f"/a/{text}", server_file="s.py", server_line=5,
    )
    return FleetScan(
        results=[result("client"), result("server")],
        links=[link],
        cross_boundary=[CrossBoundaryFlow(
            client_repo="client", server_repo="server", method="POST", route=f"/a/{text}", basis="taint",
            detail=text, client_target=f"http://a/{text}", client_file="c.py", client_line=3,
            server_file="s.py", server_line=5, severity="high",
        )],
        trust_gaps=[TrustGap(
            client_repo="client", server_repo="server", method="POST", route=f"/a/{text}",
            client_target=f"http://a/{text}", client_file="c.py", client_line=3, server_file="s.py", server_line=5,
        )],
        cross_repo_anomalies=[CrossRepoAnomaly(repo="client", method="POST", route=f"/a/{text}", template=f"a/{text}", peers=(f"peer{text}",))],
        failed=[{"repo_id": "broken", "root": "/repos/broken", "error": text}],
    )


@pytest.mark.parametrize("text", [HOSTILE, TERMINAL], ids=["markdown", "terminal"])
def test_fleet_summary_is_inert(text: str) -> None:
    md = render_fleet_summary(_hostile_fleet(text))
    # The per-repo report link `[<id>/](<id>/)` is built from the slug
    # `fleet_repo_ids` produces ([a-z0-9-]), never from repo text.
    _assert_inert(re.sub(r"\[[a-z0-9-]+/\]\([a-z0-9-]+/\)", "", md))
    assert "\x1b" not in md
    # A backtick in a route can't close the code span: every row still has 5 cells.
    for row in (line for line in md.splitlines() if line.startswith("| ")):
        assert row.count(" | ") >= 4, row


@pytest.mark.parametrize("text", [HOSTILE, TERMINAL], ids=["markdown", "terminal"])
def test_fleet_graph_is_inert(text: str) -> None:
    md = render_fleet_graph_mermaid(_hostile_fleet(text))
    _assert_attack_paths_inert(md)
    assert "\x1b" not in md
