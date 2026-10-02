"""Core side of #258: typed hints, the auth_hints shim, and evidence-gated chain findings."""

from __future__ import annotations

import logging

import pytest

from attackmap import recon_to_analysis
from attackmap.models import AuthHint, DatabaseHint, EdgeHint, Route, ScanResult, ServiceHint
from attackmap.recon_to_analysis import _auth_filtered_scan, to_findings


def _rules(scan: ScanResult) -> set[str]:
    return {f.rule_id for f in to_findings(scan)}


def test_single_service_repo_gets_no_inter_service_chain() -> None:
    scan = ScanResult(
        root="/r",
        routes=[Route(path="/users", method="POST", file="src/server.js", line=3)],
        service_hints=[ServiceHint(hint="service_name:repo-service", file="src/server.js", line=1)],
        databases=[DatabaseHint(kind="postgres", file="src/db.js", line=2)],
    )
    assert "service-trust-chain" not in _rules(scan)


def test_real_inter_service_edge_with_sink_still_fires() -> None:
    scan = ScanResult(
        root="/r",
        routes=[Route(path="/orders", method="POST", file="services/api/server.js", line=3)],
        edge_hints=[EdgeHint(hint="edge:api->billing", file="services/api/client.js", line=5)],
        databases=[DatabaseHint(kind="postgres", file="services/billing/db.js", line=2)],
    )
    assert "service-trust-chain" in _rules(scan)


def test_sink_only_elsewhere_in_repo_is_not_a_chain_finding() -> None:
    scan = ScanResult(
        root="/r",
        routes=[Route(path="/orders", method="POST", file="services/api/server.js", line=3)],
        edge_hints=[EdgeHint(hint="edge:api->billing", file="services/api/client.js", line=5)],
        databases=[DatabaseHint(kind="postgres", file="scripts/seed.js", line=2)],
    )
    assert "service-trust-chain" not in _rules(scan)


def test_auth_shim_keeps_line_and_evidence() -> None:
    hint = AuthHint(hint="jwt", file="app.py", line=12, evidence_text="jwt.decode(token)")
    filtered = _auth_filtered_scan(ScanResult(root="/r", auth_hints=[hint]))
    assert [(h.hint, h.line, h.evidence_text) for h in filtered.auth_hints] == [("jwt", 12, "jwt.decode(token)")]


def test_auth_shim_drops_and_warns_on_overloaded_hints(caplog: pytest.LogCaptureFixture) -> None:
    recon_to_analysis._WARNED_OVERLOADED.discard("legacy-plugin")
    overloaded = AuthHint(hint="controller:IndexController", file="module.config.php")
    overloaded.source_analyzer = "legacy-plugin"
    with caplog.at_level(logging.WARNING, logger="attackmap.recon_to_analysis"):
        filtered = _auth_filtered_scan(ScanResult(root="/r", auth_hints=[overloaded]))
        _auth_filtered_scan(ScanResult(root="/r", auth_hints=[overloaded]))
    assert filtered.auth_hints == []
    warnings = [r for r in caplog.records if "legacy-plugin" in r.getMessage()]
    assert len(warnings) == 1


def test_env_template_secret_is_not_a_hardcoded_literal() -> None:
    from attackmap.models import SecretHint

    scan = ScanResult(
        root="/r",
        secret_hints=[SecretHint(name="DATABASE_PASSWORD", file=".env.example", line=3, kind="env_template")],
    )
    findings = {f.rule_id: f for f in to_findings(scan)}
    assert "hardcoded-secret" not in findings
    assert "secret-env-reference" in findings
