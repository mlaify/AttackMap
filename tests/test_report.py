from pathlib import Path
import json

from attackmap.models import AttackPath, Finding, ScanResult
from attackmap.report import render_console_summary, write_reports


def test_render_console_summary_orders_findings_by_severity() -> None:
    scan = ScanResult(root=".", languages=["python"], files_scanned=1)
    findings = [
        Finding(title="Medium issue", severity="medium", mitigation="m"),
        Finding(title="High issue", severity="high", mitigation="m"),
        Finding(title="Low issue", severity="low", mitigation="m"),
    ]
    attack_paths = [AttackPath(name="Admin function abuse", steps=["Entry: admin route"], impact="Privilege escalation.")]

    summary = render_console_summary(scan, findings, attack_paths)

    high_index = summary.index("[HIGH] High issue")
    medium_index = summary.index("[MEDIUM] Medium issue")
    low_index = summary.index("[LOW] Low issue")

    assert high_index < medium_index < low_index
    assert "Admin function abuse: Privilege escalation." in summary


def test_write_reports_includes_defensive_review_file_and_json_field(tmp_path: Path) -> None:
    scan = ScanResult(root=".", languages=["typescript"], files_scanned=3)
    findings = [Finding(title="Medium issue", severity="medium", mitigation="mitigate")]
    attack_paths = [AttackPath(name="Path A", steps=["Entry: /xrpc"], impact="Impact A")]
    architecture_md = "# Architecture Summary"
    attack_surface_md = "# Attack Surface"
    defensive_review_md = "# Defensive Review\n\n## Strengths\n- Example strength"

    write_reports(
        tmp_path,
        scan,
        architecture_md,
        attack_surface_md,
        defensive_review_md,
        [],
        findings,
        attack_paths,
    )

    assert (tmp_path / "defensive-review.md").exists()
    assert (tmp_path / "defensive-review.json").exists()
    assert (tmp_path / "review-context-pack.json").exists()
    payload = json.loads((tmp_path / "attackmap-report.json").read_text(encoding="utf-8"))
    assert payload["defensive_review"] == defensive_review_md
    assert payload["defensive_review_json"]["schema_version"] == "1.2.0"
    assert payload["review_context_pack"]["artifact_type"] == "attackmap_review_context_pack"
