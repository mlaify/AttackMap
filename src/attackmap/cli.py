from __future__ import annotations

from pathlib import Path

import typer

from .analyzer import identify_attack_surfaces, summarize_architecture, summarize_attack_surface
from .defensive_review import render_defensive_review
from .analyzers import (
    analyze_repository,
    get_available_modules,
    get_available_repository_modules,
    get_analyzer_metadata,
    resolve_run_analyzers,
    select_requested_analyzers,
)
from .graph import build_graph
from .report import render_console_summary, write_reports
from .threat_model import generate_attack_paths, generate_findings

app = typer.Typer(help="AttackMap: understand your system and map your attack surface.")


@app.command()
def analyze(
    path: str = typer.Argument(".", help="Path to the repository to analyze."),
    output: str = typer.Option("reports", "--output", "-o", help="Directory for generated reports."),
    format: str = typer.Option("all", "--format", help="Output format: all, markdown, or json."),
    module: list[str] | None = typer.Option(
        None,
        "--module",
        "-m",
        help="Analyzer module(s) to run. Repeat to select multiple. Missing external analyzers are auto-installed from the attackmap-analyzers GitLab subgroup.",
    ),
) -> None:
    repo_path = Path(path).resolve()
    if not repo_path.exists():
        raise typer.BadParameter(f"Path does not exist: {repo_path}")

    selected_analyzers = None
    if module:
        try:
            selected_analyzers = select_requested_analyzers(module, auto_install=True)
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc

    active_analyzers = resolve_run_analyzers(repo_path, analyzers=selected_analyzers)
    scan = analyze_repository(repo_path, analyzers=active_analyzers)
    graph = build_graph(scan)
    attack_surfaces = identify_attack_surfaces(scan)
    architecture_md = summarize_architecture(scan, graph)
    attack_surface_md = summarize_attack_surface(scan, attack_surfaces)
    findings = generate_findings(scan, attack_surfaces)
    attack_paths = generate_attack_paths(scan)
    defensive_review_md = render_defensive_review(scan, attack_surfaces, findings, attack_paths)

    write_reports(
        output,
        scan,
        architecture_md,
        attack_surface_md,
        defensive_review_md,
        attack_surfaces,
        findings,
        attack_paths,
        analyzer_metadata=[
            {
                "name": metadata.name,
                "description": metadata.description,
                "scope": metadata.scope,
                "ecosystems": list(metadata.ecosystems),
            }
            for metadata in (get_analyzer_metadata(analyzer) for analyzer in active_analyzers)
        ],
    )
    typer.echo(render_console_summary(scan, findings, attack_paths))
    typer.echo("")
    typer.echo(f"Reports written to: {Path(output).resolve()}")


@app.command("modules")
def modules() -> None:
    available_modules = get_available_modules()
    if not available_modules:
        typer.echo("No analyzer modules are currently available.")
    else:
        typer.echo("Available analyzer modules (installed):")
        for module_metadata in available_modules:
            ecosystems = ", ".join(module_metadata.ecosystems) if module_metadata.ecosystems else "none"
            typer.echo(f"- {module_metadata.name}: {module_metadata.description}")
            typer.echo(f"  scope: {module_metadata.scope}")
            typer.echo(f"  ecosystems: {ecosystems}")

    typer.echo("")
    typer.echo("Available module repositories (GitLab subgroup):")
    try:
        repository_modules = get_available_repository_modules()
    except ValueError as exc:
        typer.echo(f"- Unable to fetch remote module repositories: {exc}")
        return

    if not repository_modules:
        typer.echo("- No module repositories were discovered.")
        return

    for module in repository_modules:
        typer.echo(f"- {module.analyzer_name} ({module.repo_name})")
        typer.echo(f"  repo: {module.web_url}")


if __name__ == "__main__":
    app()
