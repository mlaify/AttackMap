"""Tests for taint sanitizer / validator awareness (#137)."""

from __future__ import annotations

from pathlib import Path

from attackmap.scanner import scan_repo
from attackmap.taint import _find_sanitizer
from attackmap.threat_model import generate_findings


def _write(tmp_path: Path, body: str) -> Path:
    (tmp_path / "app.py").write_text(
        "from flask import Flask, request\n"
        "import subprocess, shlex\n"
        "app = Flask(__name__)\n\n"
        '@app.route("/lookup")\n'
        "def lookup():\n"
        '    host = request.args["host"]\n'
        f"{body}\n",
        encoding="utf-8",
    )
    return tmp_path


def _shell_chains(scan):
    return [c for c in scan.taint_chains if c.sink_kind == "subprocess_shell"]


def _high_cmd_findings(scan):
    findings = generate_findings(scan)
    return [
        f
        for f in findings
        if "taint-chain" in f.tags and f.severity == "high" and "command" in f.title.lower()
    ]


# ---------------------------------------------------------------------------
# The core acceptance criterion: source→sanitizer→sink vs source→sink
# ---------------------------------------------------------------------------


def test_sanitized_chain_yields_no_high_finding(tmp_path: Path) -> None:
    scan = scan_repo(
        _write(
            tmp_path,
            "    safe = shlex.quote(host)\n"
            '    subprocess.run("dig " + safe, shell=True)',
        )
    )
    chains = _shell_chains(scan)
    assert len(chains) == 1
    chain = chains[0]
    assert chain.sanitized is True
    assert chain.sanitizer_evidence == "shlex.quote"
    # Downgraded well below the unsanitized baseline.
    assert chain.confidence < 0.4
    assert _high_cmd_findings(scan) == []


def test_unsanitized_chain_still_yields_high_finding(tmp_path: Path) -> None:
    scan = scan_repo(
        _write(tmp_path, '    subprocess.run("dig " + host, shell=True)')
    )
    chains = _shell_chains(scan)
    assert len(chains) == 1
    assert chains[0].sanitized is False
    assert chains[0].sanitizer_evidence is None
    assert len(_high_cmd_findings(scan)) == 1


def test_sanitized_chain_is_retained_as_evidence(tmp_path: Path) -> None:
    # "drop or downgrade" — we downgrade: the chain stays in scan.taint_chains
    # (with the sanitizer node) so it remains auditable.
    scan = scan_repo(
        _write(
            tmp_path,
            "    safe = shlex.quote(host)\n"
            '    subprocess.run("dig " + safe, shell=True)',
        )
    )
    assert any(c.sanitized and c.sanitizer_evidence for c in scan.taint_chains)


# ---------------------------------------------------------------------------
# Precision: a sanitizer for a different sink kind must not neutralize
# ---------------------------------------------------------------------------


def test_wrong_kind_sanitizer_does_not_neutralize(tmp_path: Path) -> None:
    # is_safe_url is an open_redirect neutralizer, NOT a shell one — the
    # command-injection chain must still fire.
    scan = scan_repo(
        _write(
            tmp_path,
            "    ok = is_safe_url(host)\n"
            '    subprocess.run("dig " + host, shell=True)',
        )
    )
    chains = _shell_chains(scan)
    assert len(chains) == 1
    assert chains[0].sanitized is False
    assert len(_high_cmd_findings(scan)) == 1


# ---------------------------------------------------------------------------
# _find_sanitizer table unit coverage
# ---------------------------------------------------------------------------


def test_find_sanitizer_table() -> None:
    assert _find_sanitizer("subprocess_shell", "x = shlex.quote(y)") == "shlex.quote"
    assert (
        _find_sanitizer("subprocess_shell", "$s = escapeshellarg($y);")
        == "escapeshellarg/escapeshellcmd"
    )
    assert _find_sanitizer("dynamic_open", "p = secure_filename(name)") == "werkzeug.secure_filename"
    assert _find_sanitizer("open_redirect", "if is_safe_url(u):") == "is_safe_url"
    # No neutralizer present, or a kind with none defined.
    assert _find_sanitizer("subprocess_shell", "subprocess.run(cmd)") is None
    assert _find_sanitizer("eval", "shlex.quote(x)") is None
