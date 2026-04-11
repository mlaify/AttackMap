from __future__ import annotations

import json
from pathlib import Path

from .context_pack import build_review_context_pack
from .models import AttackPath, AttackSurface, Finding, ScanResult
from .review_json import build_defensive_review_json


def _severity_rank(value: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(value, 3)


def write_reports(
    output_dir: str | Path,
    scan: ScanResult,
    architecture_md: str,
    attack_surface_md: str,
    defensive_review_md: str,
    attack_surfaces: list[AttackSurface],
    findings: list[Finding],
    attack_paths: list[AttackPath],
    analyzer_metadata: list[dict[str, object]] | None = None,
) -> None:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    (out / "architecture.md").write_text(architecture_md + "\n", encoding="utf-8")
    (out / "attack-surface.md").write_text(attack_surface_md + "\n", encoding="utf-8")
    (out / "defensive-review.md").write_text(defensive_review_md + "\n", encoding="utf-8")
    defensive_review_json = build_defensive_review_json(scan, attack_surfaces, findings, attack_paths)
    (out / "defensive-review.json").write_text(json.dumps(defensive_review_json, indent=2) + "\n", encoding="utf-8")
    review_context_pack = build_review_context_pack(
        defensive_review_json,
        scan,
        analyzer_metadata if analyzer_metadata is not None else [],
    )
    (out / "review-context-pack.json").write_text(json.dumps(review_context_pack, indent=2) + "\n", encoding="utf-8")

    json_report = {
        "scan": scan.model_dump(),
        "architecture_summary": architecture_md,
        "attack_surface_summary": attack_surface_md,
        "defensive_review": defensive_review_md,
        "defensive_review_json": defensive_review_json,
        "review_context_pack": review_context_pack,
        "attack_surfaces": [surface.model_dump() for surface in attack_surfaces],
        "findings": [finding.model_dump() for finding in findings],
        "attack_paths": [path.model_dump() for path in attack_paths],
    }
    (out / "attackmap-report.json").write_text(json.dumps(json_report, indent=2) + "\n", encoding="utf-8")


def render_console_summary(scan: ScanResult, findings: list[Finding], attack_paths: list[AttackPath]) -> str:
    ordered_findings = sorted(findings, key=lambda finding: (_severity_rank(finding.severity), finding.title))
    lines = [
        f"Scanned {scan.files_scanned} files",
        f"Detected languages: {', '.join(scan.languages) if scan.languages else 'none'}",
        f"Routes: {len(scan.routes)}",
        f"External calls: {len(scan.external_calls)}",
        f"Datastores: {len(scan.databases)}",
        "",
        "Findings:",
    ]
    for finding in ordered_findings:
        lines.append(f"- [{finding.severity.upper()}] {finding.title}")

    lines.append("")
    lines.append("Attack paths:")
    for path in attack_paths:
        lines.append(f"- {path.name}: {path.impact}")

    return "\n".join(lines)
