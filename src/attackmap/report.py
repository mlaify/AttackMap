from __future__ import annotations

import json
from pathlib import Path

from .analyzer import summarize_architecture, summarize_attack_surface
from .models import AttackPath, Finding, ScanResult


def write_reports(
    output_dir: str | Path,
    scan: ScanResult,
    architecture_md: str,
    attack_surface_md: str,
    findings: list[Finding],
    attack_paths: list[AttackPath],
) -> None:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    (out / "architecture.md").write_text(architecture_md + "\n", encoding="utf-8")
    (out / "attack-surface.md").write_text(attack_surface_md + "\n", encoding="utf-8")

    json_report = {
        "scan": scan.model_dump(),
        "architecture_summary": architecture_md,
        "attack_surface_summary": attack_surface_md,
        "findings": [finding.model_dump() for finding in findings],
        "attack_paths": [path.model_dump() for path in attack_paths],
    }
    (out / "attackmap-report.json").write_text(json.dumps(json_report, indent=2) + "\n", encoding="utf-8")


def render_console_summary(scan: ScanResult, findings: list[Finding], attack_paths: list[AttackPath]) -> str:
    lines = [
        f"Scanned {scan.files_scanned} files",
        f"Detected languages: {', '.join(scan.languages) if scan.languages else 'none'}",
        f"Routes: {len(scan.routes)}",
        f"External calls: {len(scan.external_calls)}",
        f"Datastores: {len(scan.databases)}",
        "",
        "Findings:",
    ]
    for finding in findings:
        lines.append(f"- [{finding.severity.upper()}] {finding.title}")

    lines.append("")
    lines.append("Attack paths:")
    for path in attack_paths:
        lines.append(f"- {path.name}")

    return "\n".join(lines)
