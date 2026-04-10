from __future__ import annotations

from pathlib import Path

import typer

from .analyzer import identify_attack_surfaces, summarize_architecture, summarize_attack_surface
from .graph import build_graph
from .report import render_console_summary, write_reports
from .scanner import scan_repo
from .threat_model import generate_attack_paths, generate_findings

app = typer.Typer(help="AttackMap: understand your system and map your attack surface.")


@app.command()
def analyze(
    path: str = typer.Argument(".", help="Path to the repository to analyze."),
    output: str = typer.Option("reports", "--output", "-o", help="Directory for generated reports."),
    format: str = typer.Option("all", "--format", help="Output format: all, markdown, or json."),
) -> None:
    repo_path = Path(path).resolve()
    if not repo_path.exists():
        raise typer.BadParameter(f"Path does not exist: {repo_path}")

    scan = scan_repo(repo_path)
    graph = build_graph(scan)
    attack_surfaces = identify_attack_surfaces(scan)
    architecture_md = summarize_architecture(scan, graph)
    attack_surface_md = summarize_attack_surface(scan, attack_surfaces)
    findings = generate_findings(scan, attack_surfaces)
    attack_paths = generate_attack_paths(scan)

    write_reports(output, scan, architecture_md, attack_surface_md, attack_surfaces, findings, attack_paths)
    typer.echo(render_console_summary(scan, findings, attack_paths))
    typer.echo("")
    typer.echo(f"Reports written to: {Path(output).resolve()}")


if __name__ == "__main__":
    app()
