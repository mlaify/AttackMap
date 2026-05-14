from __future__ import annotations

import json
from pathlib import Path

import typer

from .analyzer import summarize_architecture, summarize_attack_surface
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
from .llm_review import LlmReviewError, generate_llm_review
from .recon_to_analysis import translate_recon
from .report import render_console_summary, write_reports

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
        help="Analyzer module(s) to run. Repeat to select multiple. Missing external analyzers are auto-installed from the mlaify GitHub organization.",
    ),
    llm: bool = typer.Option(
        False,
        "--llm",
        help="Generate a narrative defensive review by calling Claude with the evidence pack. Auth resolves automatically: ANTHROPIC_API_KEY → ANTHROPIC_AUTH_TOKEN → `claude` CLI (subscription auth). Force a backend with --llm-backend.",
    ),
    llm_model: str | None = typer.Option(
        None,
        "--llm-model",
        help="Claude model ID for --llm (defaults to claude-opus-4-7).",
    ),
    llm_effort: str | None = typer.Option(
        None,
        "--llm-effort",
        help="Effort for --llm: low|medium|high|xhigh|max. Defaults to high.",
    ),
    llm_backend: str = typer.Option(
        "auto",
        "--llm-backend",
        help="Which backend --llm uses: 'auto' (default) tries ANTHROPIC_API_KEY → ANTHROPIC_AUTH_TOKEN → `claude` CLI; 'api' forces the SDK; 'cli' forces the `claude` CLI (uses your `claude login` auth, e.g. Pro/Max subscription).",
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
    analysis = translate_recon(scan)
    attack_surfaces = analysis.attack_surfaces
    architecture_md = summarize_architecture(scan, graph)
    attack_surface_md = summarize_attack_surface(scan, attack_surfaces)
    findings = analysis.findings
    attack_paths = analysis.attack_paths
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

    if llm:
        try:
            effort_value = None
            if llm_effort is not None:
                if llm_effort not in {"low", "medium", "high", "xhigh", "max"}:
                    raise typer.BadParameter(
                        f"Invalid --llm-effort '{llm_effort}'. Use one of: low, medium, high, xhigh, max."
                    )
                effort_value = llm_effort  # type: ignore[assignment]

            if llm_backend not in {"auto", "api", "cli"}:
                raise typer.BadParameter(
                    f"Invalid --llm-backend '{llm_backend}'. Use one of: auto, api, cli."
                )

            typer.echo("")
            typer.echo(
                f"Generating narrative review via Claude (backend={llm_backend}, may take a minute)..."
            )
            result = generate_llm_review(
                scan,
                attack_surfaces,
                findings,
                attack_paths,
                model=llm_model,
                effort=effort_value,  # type: ignore[arg-type]
                backend=llm_backend,  # type: ignore[arg-type]
            )
        except LlmReviewError as exc:
            typer.echo(f"LLM review skipped: {exc}", err=True)
        else:
            output_path = Path(output)
            llm_md_path = output_path / "defensive-review-llm.md"
            llm_md_path.write_text(result.markdown + "\n", encoding="utf-8")
            llm_meta_path = output_path / "defensive-review-llm.meta.json"
            llm_meta_path.write_text(
                json.dumps(
                    {
                        "backend": result.backend,
                        "model": result.model,
                        "stop_reason": result.stop_reason,
                        "usage": result.usage,
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            typer.echo(f"LLM review written to: {llm_md_path.resolve()} (backend={result.backend})")


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
    typer.echo("Available module repositories (mlaify GitHub org):")
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
