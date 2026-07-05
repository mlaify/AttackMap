"""Tests for novel vuln-class detectors (#77): open_redirect (taint),
prototype pollution, mass assignment, JWT weakness, XXE."""

from __future__ import annotations

from pathlib import Path

import pytest

from attackmap.models import CodeWeakness, Route, ScanResult
from attackmap.scanner import scan_repo
from attackmap.threat_model import generate_findings
from attackmap.weaknesses import find_code_weaknesses


def _kinds(content: str) -> set[str]:
    return {w.kind for w in find_code_weaknesses(content, "f.js")}


# ---------------------------------------------------------------------------
# Prototype pollution
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        "obj[key]['__proto__']['x'] = 1\n",
        "target.__proto__.polluted = true\n",
        "obj['constructor']['prototype']['x'] = 1\n",
        "_.merge(target, req.body)\n",
        "$.extend(true, {}, request.query)\n",
    ],
)
def test_prototype_pollution_detected(content: str) -> None:
    assert "prototype_pollution" in _kinds(content)


def test_safe_merge_of_constant_not_flagged() -> None:
    assert "prototype_pollution" not in _kinds("_.merge(target, { a: 1 })\n")


# ---------------------------------------------------------------------------
# Mass assignment
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        "user = User(**request.json)\n",
        "User.objects.create(**request.data)\n",
        "model.update(**req.form)\n",
        "const u = new User(req.body)\n",
        "Model.create(req.body)\n",
        "Object.assign(user, req.body)\n",
        "params.permit!\n",
    ],
)
def test_mass_assignment_detected(content: str) -> None:
    assert "mass_assignment" in _kinds(content)


def test_explicit_fields_not_mass_assignment() -> None:
    assert "mass_assignment" not in _kinds("user = User(name=req.body['name'])\n")


# ---------------------------------------------------------------------------
# JWT weaknesses
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        "jwt.decode(token, key, algorithms=['none'])\n",
        "jwt.decode(token, verify=False)\n",
        "payload = jwt.decode(t, options={'verify_signature': False})\n",
        "jsonwebtoken.verify(t, k, { algorithms: ['none'] })\n",
    ],
)
def test_jwt_weakness_detected(content: str) -> None:
    assert "jwt_weakness" in _kinds(content)


def test_proper_jwt_not_flagged() -> None:
    assert "jwt_weakness" not in _kinds("jwt.decode(token, key, algorithms=['RS256'])\n")


# ---------------------------------------------------------------------------
# XXE
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        "parser = etree.XMLParser(resolve_entities=True)\n",
        "parser = etree.XMLParser(load_dtd=True)\n",
        "libxml_disable_entity_loader(false);\n",
        "factory.setExpandEntityReferences(true);\n",
    ],
)
def test_xxe_detected(content: str) -> None:
    assert "xxe" in _kinds(content)


def test_safe_xml_parser_not_flagged() -> None:
    assert "xxe" not in _kinds("parser = etree.XMLParser(resolve_entities=False)\n")


# ---------------------------------------------------------------------------
# open_redirect (taint sink) via scan_repo
# ---------------------------------------------------------------------------


def test_open_redirect_taint_sink(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import Flask, request, redirect\n"
        "app = Flask(__name__)\n"
        "@app.route('/go')\n"
        "def go():\n"
        "    return redirect(request.args['next'])\n",
        encoding="utf-8",
    )
    scan = scan_repo(tmp_path)
    assert any(c.sink_kind == "open_redirect" for c in scan.taint_chains)
    findings = [f for f in generate_findings(scan) if "taint-chain" in f.tags]
    assert any("open redirect" in f.title for f in findings)


def test_constant_redirect_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import Flask, redirect\n"
        "app = Flask(__name__)\n"
        "@app.route('/go')\n"
        "def go():\n"
        "    return redirect('/home')\n",
        encoding="utf-8",
    )
    scan = scan_repo(tmp_path)
    assert not any(c.sink_kind == "open_redirect" for c in scan.taint_chains)


# ---------------------------------------------------------------------------
# Findings via threat_model
# ---------------------------------------------------------------------------


def test_code_weakness_finding_high_with_technique() -> None:
    scan = ScanResult(
        root="/",
        code_weaknesses=[CodeWeakness(kind="jwt_weakness", file="auth.py", line=4, severity="high")],
    )
    findings = [f for f in generate_findings(scan) if "novel-vuln" in f.tags]
    assert findings
    assert findings[0].severity == "high"
    assert findings[0].attack_techniques


def test_distinct_kinds_distinct_findings() -> None:
    scan = ScanResult(
        root="/",
        code_weaknesses=[
            CodeWeakness(kind="xxe", file="a.py", line=1, severity="high"),
            CodeWeakness(kind="mass_assignment", file="b.py", line=2, severity="high"),
        ],
    )
    titles = {f.title for f in generate_findings(scan) if "novel-vuln" in f.tags}
    assert any("XXE" in t for t in titles)
    assert any("Mass assignment" in t for t in titles)


# ---------------------------------------------------------------------------
# End-to-end
# ---------------------------------------------------------------------------


def test_scan_repo_populates_code_weaknesses(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        "def create(request):\n    return User.objects.create(**request.data)\n",
        encoding="utf-8",
    )
    scan = scan_repo(tmp_path)
    assert any(w.kind == "mass_assignment" for w in scan.code_weaknesses)
    assert [f for f in generate_findings(scan) if "novel-vuln" in f.tags]
