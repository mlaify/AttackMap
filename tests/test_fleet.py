"""Tests for multi-repo fleet mode (#146a)."""

from __future__ import annotations

import json
import re
from pathlib import Path

from typer.testing import CliRunner

from attackmap.cli import app
from attackmap.contracts import ContractLink
from attackmap.fleet import (
    FleetRepoResult,
    FleetScan,
    fleet_repo_ids,
    fleet_summary_json,
    render_fleet_graph_mermaid,
    render_fleet_summary,
)
from attackmap.models import Finding, ScanResult

runner = CliRunner()

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _norm(output: str) -> str:
    """Typer renders BadParameter in a Rich error panel that wraps the message
    across bordered lines at narrow terminal widths — so a raw substring check
    is width-dependent. Strip ANSI + box-drawing and collapse whitespace so the
    message reassembles regardless of wrapping."""
    text = _ANSI.sub("", output)
    text = re.sub(r"[│╭╮╰╯─]", " ", text)
    return " ".join(text.split())


def _finding(title: str, severity: str) -> Finding:
    return Finding(title=title, severity=severity, mitigation="x")


def _result(repo_id: str, findings: list[Finding]) -> FleetRepoResult:
    return FleetRepoResult(
        repo_id=repo_id,
        root=f"/repos/{repo_id}",
        report_dir=f"/out/{repo_id}",
        scan=ScanResult(root=f"/repos/{repo_id}"),
        findings=findings,
    )


# ---------------------------------------------------------------------------
# repo id disambiguation
# ---------------------------------------------------------------------------


def test_fleet_repo_ids_slugifies_and_disambiguates() -> None:
    ids = fleet_repo_ids(
        [Path("/a/My Service"), Path("/b/my-service"), Path("/c/service")]
    )
    assert ids == ["my-service", "my-service-2", "service"]


def test_fleet_repo_ids_stable_and_unique() -> None:
    ids = fleet_repo_ids([Path("/x/api"), Path("/y/api"), Path("/z/api")])
    assert ids == ["api", "api-2", "api-3"]
    assert len(set(ids)) == 3


def test_fleet_repo_ids_unique_against_preexisting_suffix() -> None:
    # `api`, `api`, `api-2`: the disambiguated 2nd (`api-2`) must not collide
    # with the 3rd input's own name — else reports overwrite each other.
    ids = fleet_repo_ids([Path("/x/api"), Path("/y/api"), Path("/z/api-2")])
    assert len(set(ids)) == 3
    assert ids == ["api", "api-2", "api-2-2"]


# ---------------------------------------------------------------------------
# summary rendering
# ---------------------------------------------------------------------------


def test_render_fleet_summary_counts_by_severity() -> None:
    fleet = FleetScan(
        results=[
            _result("svc-a", [_finding("SQLi", "high"), _finding("weak-tls", "medium")]),
            _result("svc-b", [_finding("info", "low")]),
        ]
    )
    md = render_fleet_summary(fleet)
    assert "2 repositories analyzed · 3 finding(s) total." in md
    assert "| `svc-a` | 1 | 1 | 0 | 2 |" in md
    assert "| `svc-b` | 0 | 0 | 1 | 1 |" in md
    assert "[svc-a/](svc-a/)" in md
    assert "SQLi" in md  # top findings listed


def test_fleet_summary_json_shape() -> None:
    fleet = FleetScan(results=[_result("svc-a", [_finding("SQLi", "high")])])
    data = fleet_summary_json(fleet)
    assert data["repo_count"] == 1
    assert data["total_findings"] == 1
    repo = data["repos"][0]
    assert repo["repo_id"] == "svc-a"
    assert repo["severity_counts"] == {"high": 1, "medium": 0, "low": 0}
    assert data["cross_repo_links"] == []


# ---------------------------------------------------------------------------
# cross-repo links (#146b) rendering
# ---------------------------------------------------------------------------


def _link() -> ContractLink:
    return ContractLink(
        client_repo="client",
        server_repo="server",
        method="GET",
        path_template="api/orders/*",
        client_target="http://order-svc/api/orders/",
        client_file="c.py",
        client_line=3,
        server_route_path="/api/orders/<id>",
        server_file="s.py",
        server_line=5,
    )


def test_summary_lists_cross_repo_links() -> None:
    fleet = FleetScan(
        results=[_result("client", []), _result("server", [])], links=[_link()]
    )
    md = render_fleet_summary(fleet)
    assert "Cross-repo links" in md
    assert "1 client→server contract link(s)" in md
    assert "`client`" in md and "`server`" in md
    assert "/api/orders/<id>" in md and "c.py:3" in md


def test_fleet_graph_mermaid_has_edge_citing_both_sides() -> None:
    fleet = FleetScan(
        results=[_result("client", []), _result("server", [])], links=[_link()]
    )
    graph = render_fleet_graph_mermaid(fleet)
    assert "flowchart LR" in graph
    assert '"client"' in graph and '"server"' in graph
    assert "GET /api/orders/*" in graph
    assert "-->" in graph  # a directed cross-repo edge exists


def test_fleet_summary_json_includes_links() -> None:
    fleet = FleetScan(results=[_result("client", []), _result("server", [])], links=[_link()])
    data = fleet_summary_json(fleet)
    assert len(data["cross_repo_links"]) == 1
    link = data["cross_repo_links"][0]
    assert link["client_repo"] == "client" and link["server_repo"] == "server"
    assert link["client_location"] == "c.py:3"
    assert link["server_location"] == "s.py:5"


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------

_APP = """\
from flask import Flask, request
app = Flask(__name__)


@app.route("/x")
def x():
    return request.args["q"]
"""


def _repo(root: Path, name: str, body: str = _APP) -> Path:
    d = root / name
    d.mkdir(parents=True)
    (d / "app.py").write_text(body, encoding="utf-8")
    return d


def test_single_repo_writes_reports_flat_no_fleet_summary(tmp_path: Path) -> None:
    repo = _repo(tmp_path, "solo")
    out = tmp_path / "out"
    result = runner.invoke(app, ["analyze", str(repo), "-o", str(out)])
    assert result.exit_code == 0, result.output
    # Single-repo path is unchanged: reports land flat, no fleet artifacts.
    assert (out / "attackmap-report.json").exists()
    assert not (out / "fleet-summary.md").exists()


def test_multi_repo_writes_per_repo_dirs_and_fleet_summary(tmp_path: Path) -> None:
    a = _repo(tmp_path, "svcA")
    b = _repo(tmp_path, "svcB")
    out = tmp_path / "out"
    result = runner.invoke(app, ["analyze", str(a), str(b), "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert (out / "fleet-summary.md").exists()
    assert (out / "fleet-summary.json").exists()
    assert (out / "svca" / "attackmap-report.json").exists()
    assert (out / "svcb" / "attackmap-report.json").exists()
    assert "2 repositories" in result.output


def test_multi_repo_rejects_single_repo_only_flags(tmp_path: Path) -> None:
    a = _repo(tmp_path, "svcA")
    b = _repo(tmp_path, "svcB")
    result = runner.invoke(app, ["analyze", str(a), str(b), "--hunt"])
    assert result.exit_code != 0
    assert "multi-repo mode" in _norm(result.output)


def test_multi_repo_missing_path_errors(tmp_path: Path) -> None:
    a = _repo(tmp_path, "svcA")
    result = runner.invoke(app, ["analyze", str(a), str(tmp_path / "nope")])
    assert result.exit_code != 0
    assert "does not exist" in _norm(result.output)


def test_multi_repo_links_client_to_server_end_to_end(tmp_path: Path) -> None:
    client = tmp_path / "client"
    client.mkdir()
    (client / "app.py").write_text(
        'import requests\n\n\ndef get(oid):\n'
        '    return requests.get("http://order-svc/api/orders/" + oid)\n',
        encoding="utf-8",
    )
    server = tmp_path / "server"
    server.mkdir()
    (server / "api.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n\n\n"
        '@app.route("/api/orders/<id>")\ndef order(id):\n'
        '    return db.execute("SELECT * FROM orders WHERE id=" + id)\n',
        encoding="utf-8",
    )
    out = tmp_path / "out"
    result = runner.invoke(app, ["analyze", str(client), str(server), "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert (out / "fleet-graph.md").exists()
    data = json.loads((out / "fleet-summary.json").read_text())
    links = data["cross_repo_links"]
    assert len(links) == 1
    assert links[0]["client_repo"] == "client"
    assert links[0]["server_repo"] == "server"
    assert links[0]["server_route_path"] == "/api/orders/<id>"
    assert "1 cross-repo link(s)" in result.output


def test_multi_repo_cross_boundary_flow_end_to_end(tmp_path: Path) -> None:
    # client forwards an external id to server, which trusts it into raw SQL (#146c AC1).
    client = tmp_path / "client"
    client.mkdir()
    (client / "app.py").write_text(
        'import requests\n\n\ndef get(oid):\n'
        '    return requests.get("http://order-svc/api/orders/" + oid)\n',
        encoding="utf-8",
    )
    server = tmp_path / "server"
    server.mkdir()
    (server / "api.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n\n\n"
        '@app.route("/api/orders/<id>")\ndef order(id):\n'
        '    return db.execute("SELECT * FROM orders WHERE id=" + id)\n',
        encoding="utf-8",
    )
    out = tmp_path / "out"
    result = runner.invoke(app, ["analyze", str(client), str(server), "-o", str(out)])
    assert result.exit_code == 0, result.output
    data = json.loads((out / "fleet-summary.json").read_text())
    flows = data["cross_boundary_flows"]
    assert len(flows) == 1
    f = flows[0]
    assert f["basis"] == "taint" and f["detail"] == "sql_execute"
    assert f["client_repo"] == "client" and f["server_repo"] == "server"
    assert f["speculative"] is True
    # cites both sides
    assert f["client_location"].startswith("app.py")
    assert "SPECULATIVE" in (out / "fleet-summary.md").read_text()


def test_multi_repo_validates_progress_format(tmp_path: Path) -> None:
    # --progress-format is validated before the fleet branch, same as single-repo.
    a = _repo(tmp_path, "svcA")
    b = _repo(tmp_path, "svcB")
    result = runner.invoke(
        app, ["analyze", str(a), str(b), "--progress-format", "bogus", "-o", str(tmp_path / "out")]
    )
    assert result.exit_code != 0
    assert "progress-format must be one of" in _norm(result.output)
