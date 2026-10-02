"""Declarative sink registry and catalog expansion (#240).

Fixtures live under ``tests/fixtures/sinks/<kind>/<lang>_{positive,negative}.*``.
Each marks its handler with ``taint: route`` and the sink call with
``taint: sink``. A positive must yield an unsanitized chain of ``<kind>`` at
the sink line; a negative must not (a sanitized chain kept as evidence is fine).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from attackmap import taint_sinks
from attackmap.models import Route, ScanResult, TaintChain
from attackmap.taint import analyze_taint
from attackmap.taint_sinks import (
    KINDS,
    SINK_KINDS,
    SINKS,
    SinkRegistryError,
    load_registry,
    validate_sink_entry,
)
from attackmap.taxonomy import taxonomy_for
from attackmap.threat_model import _FLOW_FINDING_SPEC, _TAINT_FINDING_SPEC, generate_findings

FIX = Path(__file__).parent / "fixtures" / "sinks"
CASES = sorted((p.parent.name, p.name) for p in FIX.glob("*/*") if p.is_file())


def _marker(text: str, marker: str) -> int:
    for i, line in enumerate(text.splitlines(), start=1):
        if f"taint: {marker}" in line:
            return i
    raise AssertionError(f"no {marker} marker")


def _chains_at_sink(kind_dir: str, name: str) -> tuple[list[TaintChain], int]:
    root = FIX / kind_dir
    text = (root / name).read_text(encoding="utf-8")
    scan = ScanResult(
        root=str(root),
        routes=[Route(path="/fixture", method="GET", file=name, line=_marker(text, "route"))],
    )
    sink_line = _marker(text, "sink")
    chains = [c for c in analyze_taint(scan, root) if c.sink_file == name and c.sink_line == sink_line]
    return chains, sink_line


def test_every_new_kind_has_a_positive_and_negative_fixture() -> None:
    new_kinds = {
        "path_traversal", "zip_slip", "code_injection", "expression_injection", "jndi_injection",
        "ldap_injection", "xpath_injection", "header_injection", "regex_injection",
    }
    by_kind: dict[str, set[str]] = {}
    for kind_dir, name in CASES:
        by_kind.setdefault(kind_dir, set()).add(name)
    assert new_kinds <= set(by_kind)
    for kind_dir, names in by_kind.items():
        stems = {n.rsplit(".", 1)[0] for n in names}
        langs = {s.rsplit("_", 1)[0] for s in stems}
        for lang in langs:
            assert f"{lang}_positive" in stems and f"{lang}_negative" in stems, (kind_dir, lang)


@pytest.mark.parametrize("kind_dir,name", CASES, ids=[f"{k}/{n}" for k, n in CASES])
def test_sink_fixture(kind_dir: str, name: str) -> None:
    chains, line = _chains_at_sink(kind_dir, name)
    live = [c for c in chains if c.sink_kind == kind_dir and not c.sanitized]
    if "_positive." in name:
        assert live, f"expected an unsanitized {kind_dir} chain at line {line}, got {chains}"
        findings = generate_findings(ScanResult(root=str(FIX / kind_dir), taint_chains=live))
        assert any("taint-chain" in f.tags for f in findings)
    else:
        assert not live, f"negative fixture flagged: {live}"


# ---------------------------------------------------------------------------
# Registry schema
# ---------------------------------------------------------------------------

_GOOD = {"id": "x-sink", "kind": "code_injection", "langs": ["python"], "regex": r"\bdanger\s*\(", "cwe": 94}


def test_registry_loads_and_every_sink_carries_a_cwe() -> None:
    kinds, sinks = load_registry()
    assert sinks and all(s.cwe > 0 for s in sinks)
    assert {s.kind for s in sinks} <= set(kinds)
    assert len({s.id for s in sinks}) == len(sinks)


def test_a_sink_without_a_cwe_is_rejected() -> None:
    entry = dict(_GOOD)
    del entry["cwe"]
    with pytest.raises(SinkRegistryError, match="cwe"):
        validate_sink_entry(entry)
    with pytest.raises(SinkRegistryError, match="cwe"):
        validate_sink_entry({**_GOOD, "cwe": "not-a-cwe"})


@pytest.mark.parametrize(
    "patch,needle",
    [
        ({"kind": "made_up"}, "unknown kind"),
        ({"langs": ["cobol"]}, "langs"),
        ({"regex": "("}, "does not compile"),
        ({"gate": "sometimes"}, "gate"),
        ({"args": "everything"}, "args"),
        ({"surprise": 1}, "unknown field"),
        ({"id": "Not A Slug"}, "slug"),
    ],
)
def test_invalid_entries_are_rejected(patch: dict, needle: str) -> None:
    with pytest.raises(SinkRegistryError, match=needle):
        validate_sink_entry({**_GOOD, **patch})


def test_cwe_accepts_the_cwe_prefix() -> None:
    assert validate_sink_entry({**_GOOD, "cwe": "CWE-94"}).cwe == 94


def test_taint_chain_schema_enumerates_every_registry_kind() -> None:
    schema = TaintChain.model_json_schema()
    assert set(SINK_KINDS) <= set(schema["properties"]["sink_kind"]["enum"])


def test_every_kind_has_a_finding_and_a_taxonomy_entry() -> None:
    from attackmap.threat_model import _rule_slug_kind

    for kind, meta in KINDS.items():
        target = meta.alias_of or kind
        if target in _FLOW_FINDING_SPEC:
            rule = _FLOW_FINDING_SPEC[target]["rule_id"]
        else:
            assert target in _TAINT_FINDING_SPEC or target == "sql_execute", kind
            rule = _rule_slug_kind(target)
        assert taxonomy_for(rule) is not None, rule


# ---------------------------------------------------------------------------
# Plugin hook: the attackmap.taint_sinks entry-point group
# ---------------------------------------------------------------------------


class _EP:
    def __init__(self, name: str, value) -> None:
        self.name = name
        self._value = value

    def load(self):
        return self._value


class _EPs:
    def __init__(self, eps) -> None:
        self._eps = eps

    def select(self, group: str):
        return self._eps if group == taint_sinks.PLUGIN_GROUP else []


def test_plugins_contribute_sinks_and_bad_entries_are_skipped(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    contributed = [
        {"id": "acme-render-rule", "kind": "expression_injection", "langs": ["python"],
         "regex": r"\brules\.render\s*\(", "gate": "tainted", "cwe": 917},
        {"id": "acme-no-cwe", "kind": "code_injection", "langs": ["python"], "regex": r"\bx\s*\("},
    ]
    monkeypatch.setattr(taint_sinks, "entry_points", lambda: _EPs([_EP("acme", lambda: contributed)]))
    taint_sinks.plugin_sinks.cache_clear()
    try:
        ids = [s.id for s in taint_sinks.all_sinks()]
        assert "acme-render-rule" in ids and "acme-no-cwe" not in ids
        assert "missing required field(s) cwe" in capsys.readouterr().err
        (tmp_path / "app.py").write_text(
            "from flask import Flask, request\nimport rules\napp = Flask(__name__)\n\n"
            '@app.route("/r")\n'
            "def r():\n"
            '    expr = request.args["e"]\n'
            "    return rules.render(expr)\n",
            encoding="utf-8",
        )
        scan = ScanResult(root=str(tmp_path), routes=[Route(path="/r", method="GET", file="app.py", line=5)])
        chains = analyze_taint(scan, tmp_path)
        assert [(c.sink_kind, c.source_line) for c in chains] == [("expression_injection", 7)]
    finally:
        taint_sinks.plugin_sinks.cache_clear()


def test_core_registry_is_the_module_table() -> None:
    from attackmap import taint

    assert taint._SINK_PATTERNS is SINKS
