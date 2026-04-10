from pathlib import Path

from attackmap.models import AttackPath, Finding, ScanResult
from attackmap.report import render_console_summary


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
