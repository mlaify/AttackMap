"""Deployable Sigma rules for detection opportunities (#251)."""

from __future__ import annotations

import json
import random
import re
import shutil
import tomllib
from pathlib import Path

import pytest

from attackmap import detections
from attackmap.analyzer import identify_attack_surfaces
from attackmap.defensive_review import render_defensive_review
from attackmap.detection_opportunities import detection_coverage, generate_detection_opportunities
from attackmap.detections import route_example, route_scopable, route_selector, template_data, templates
from attackmap.detections.sigma import (
    correlation_fires,
    correlation_problems,
    sigma_matches,
    sigma_problems,
)
from attackmap.models import FindingLocation
from attackmap.review_json import build_defensive_review_json
from attackmap.scanner import scan_repo
from attackmap.taxonomy import ATTACK_TECHNIQUES, RULE_TAXONOMY
from attackmap.threat_model import generate_attack_paths, generate_findings

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
TAINT_PY = FIXTURES / "taint_flow" / "py"
TAINT_JS = FIXTURES / "taint_flow" / "js"
SINKS = FIXTURES / "sinks"
IDOR = FIXTURES / "authz" / "flask_login_required_idor"
IDOR_JS = FIXTURES / "authz" / "express_router_use_auth_idor"
WEBHOOKS = ROOT / "evals" / "benchmark" / "cases" / "express-webhooks-demo"
ALL_FIXTURES = [
    TAINT_PY, TAINT_JS, SINKS, IDOR, IDOR_JS, WEBHOOKS,
    FIXTURES / "taint_repo", FIXTURES / "taint_callgraph_repo", FIXTURES / "mass_assignment",
]

_ATTACK_TAG = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)")


def _generate(root: Path):
    scan = scan_repo(root)
    surfaces = identify_attack_surfaces(scan)
    findings = generate_findings(scan, surfaces)
    return scan, surfaces, findings, generate_detection_opportunities([], findings, scan, surfaces)


def _rules(root: Path):
    return [o for o in _generate(root)[3] if o.sigma is not None]


def _by_id(root: Path):
    return {o.id: o for o in _rules(root)}


# ---------------------------------------------------------------------------
# Template library
# ---------------------------------------------------------------------------


def test_templates_load_with_required_keys() -> None:
    lib = templates()
    assert {"injection-route", "ssrf-metadata-egress", "ssrf-instance-credentials-cloudtrail",
            "bola-cardinality", "webhook-signature-missing"} <= set(lib)
    for tid, tpl in lib.items():
        for key in ("date", "title", "description", "logsource", "detection", "falsepositives", "level", "test_events"):
            assert key in tpl, (tid, key)
        assert tpl["test_events"]["positive"], tid


def test_payload_catalog_is_keyed_by_registered_rule_ids() -> None:
    payloads = template_data("injection")["payloads"]
    for rule_id, payload in payloads.items():
        assert rule_id in RULE_TAXONOMY, rule_id
        assert payload["level"] in ("low", "medium", "high", "critical")
        assert payload["contains"] and payload["sample"] and payload["benign"]
        for marker in payload["contains"]:
            # pySigma flags escaped wildcards; keep markers free of `*`, `?`, `\`.
            assert not set(marker) & set("*?\\"), (rule_id, marker)


def test_templates_ship_as_package_data() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert "*.yml" in pyproject["tool"]["setuptools"]["package-data"]["attackmap.detections"]
    assert (ROOT / "src" / "attackmap" / "detections" / "__init__.py").is_file()


def test_unknown_placeholder_is_an_error() -> None:
    with pytest.raises(detections.TemplateError):
        detections.render_rule("ssrf-metadata-egress", rule_ids=["ssrf"], key="k", params={})


def test_placeholders_in_repo_text_are_not_expanded() -> None:
    # A route containing `${level}` must stay literal text.
    filled = detections._fill("x ${a} y", {"a": "${level}"})
    assert filled == "x ${level} y"


# ---------------------------------------------------------------------------
# Every generated rule: valid Sigma, tags, logsource, test events
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("root", ALL_FIXTURES, ids=lambda p: p.name)
def test_generated_rules_are_valid_and_their_test_events_behave(root: Path) -> None:
    rules = _rules(root)
    assert rules, root
    for opp in rules:
        assert sigma_problems(opp.sigma) == [], opp.id
        sigma = opp.sigma
        assert sigma["status"] == "experimental"
        assert sigma["author"] == "AttackMap"
        attack = [m.group(1).upper() for t in sigma["tags"] if (m := _ATTACK_TAG.fullmatch(t))]
        assert attack and all(t in ATTACK_TECHNIQUES for t in attack), opp.id
        assert any(ref.startswith("https://cwe.mitre.org/") for ref in sigma["references"]), opp.id
        assert opp.logsource is not None and opp.logsource.model_dump(exclude_none=True) == sigma["logsource"]
        assert opp.fields_required and opp.false_positive_notes
        assert opp.related_rule_ids and opp.attack_techniques
        assert opp.test_events is not None and opp.test_events.positive
        for event in opp.test_events.positive:
            assert sigma_matches(sigma, event), (opp.id, event)
        for event in opp.test_events.negative:
            assert not sigma_matches(sigma, event), (opp.id, event)
        if opp.sigma_correlation is not None:
            assert correlation_problems(opp.sigma_correlation, [sigma]) == []


@pytest.mark.parametrize("root", ALL_FIXTURES, ids=lambda p: p.name)
def test_rule_ids_are_deterministic_and_unique(root: Path) -> None:
    first = [o.sigma["id"] for o in _rules(root)]
    second = [o.sigma["id"] for o in _rules(root)]
    assert first == second
    assert len(set(first)) == len(first)


def test_rules_validate_with_pysigma_when_installed() -> None:
    pytest.importorskip("sigma")
    import inspect
    import importlib
    import pkgutil

    import sigma.validators.core as core
    from sigma.collection import SigmaCollection
    from sigma.validation import SigmaValidator
    from sigma.validators.base import SigmaRuleValidator

    docs = []
    for root in ALL_FIXTURES:
        for opp in _rules(root):
            docs.append(opp.sigma)
            if opp.sigma_correlation:
                docs.append(opp.sigma_correlation)
    collection = SigmaCollection.from_dicts(docs, collect_errors=True)
    collection.resolve_rule_references()
    assert [(r.title, e) for r in collection for e in r.errors] == []
    # Every core validator except the two that download ATT&CK/D3FEND data.
    validators = []
    for info in pkgutil.iter_modules(core.__path__):
        module = importlib.import_module(f"sigma.validators.core.{info.name}")
        for name, cls in vars(module).items():
            if (inspect.isclass(cls) and issubclass(cls, SigmaRuleValidator) and not inspect.isabstract(cls)
                    and cls.__module__ == module.__name__ and name not in ("ATTACKTagValidator", "D3FENDTagValidator")):
                validators.append(cls)
    # The same route in two fixture repos legitimately shares a title.
    issues = [
        i for i in SigmaValidator(validators).validate_rules(collection)
        if type(i).__name__ != "DuplicateTitleIssue"
    ]
    assert issues == []


# ---------------------------------------------------------------------------
# Classes from the issue
# ---------------------------------------------------------------------------


def test_sql_injection_rule_is_anchored_on_the_traced_parameter() -> None:
    opp = _by_id(TAINT_PY)["detect:sql-injection:GET:/orders/search"]
    selection = opp.sigma["detection"]["selection_payload"]
    regex = selection["cs-uri-query|re|i"]
    assert regex.startswith("(?:^|&)q=")
    rule = opp.sigma
    base = {"cs-method": "GET", "cs-uri-stem": "/orders/search"}
    assert sigma_matches(rule, {**base, "cs-uri-query": "page=2&q=x%27+UNION+SELECT+1--"})
    # The payload in another parameter doesn't match.
    assert not sigma_matches(rule, {**base, "cs-uri-query": "q=shoes&note=%27"})
    # Another route doesn't match.
    assert not sigma_matches(rule, {**base, "cs-uri-stem": "/orders/other", "cs-uri-query": "q=%27"})
    assert rule["level"] == "high"


_PATH_PARAM_SQLI = """const express = require("express");
const { Pool } = require("pg");
const app = express();
const pool = new Pool();
app.get("/orders/:id", async (req, res) => {
  const id = req.params.id;
  const result = await pool.query("SELECT id FROM orders WHERE id = " + id);
  res.json(result.rows[0]);
});
module.exports = app;
"""


def test_path_parameter_source_matches_the_request_path(tmp_path: Path) -> None:
    (tmp_path / "orders.js").write_text(_PATH_PARAM_SQLI, encoding="utf-8")
    opp = _by_id(tmp_path)["detect:sql-injection:GET:/orders/:id"]
    detection = opp.sigma["detection"]
    assert detection["selection_route"] == {"cs-uri-stem|re": "^/orders/[^/]+$", "cs-method": "GET"}
    assert "cs-uri-stem|contains" in detection["selection_payload"]
    assert sigma_matches(opp.sigma, {"cs-method": "GET", "cs-uri-stem": "/orders/1%27%20or%201=1"})
    assert not sigma_matches(opp.sigma, {"cs-method": "GET", "cs-uri-stem": "/orders/42"})


def test_markers_with_sigma_wildcards_are_escaped() -> None:
    from attackmap.detection_opportunities import _payload_selector

    payload = {"contains": ["/*", "a?"]}
    selection, _, _ = _payload_selector(payload, None, "query", False)
    rule = {"detection": {"s": selection, "condition": "s"}}
    assert selection == {"cs-uri-query|contains": ["/\\*", "a\\?"]}
    assert sigma_matches(rule, {"cs-uri-query": "q=1/*x"})
    assert not sigma_matches(rule, {"cs-uri-query": "q=a/b"})
    selection, _, _ = _payload_selector(payload, "q", "query", False)
    assert selection == {"cs-uri-query|re|i": "(?:^|&)q=[^&]*(?:/\\*|a\\?)"}


def test_unknown_source_on_a_parameterized_route_checks_path_and_query() -> None:
    from attackmap.detection_opportunities import _payload_selector

    selection, where, in_stem = _payload_selector({"contains": ["%27"]}, None, None, True)
    assert selection == [{"cs-uri-query|contains": ["%27"]}, {"cs-uri-stem|contains": ["%27"]}]
    assert where == "query string or path" and not in_stem
    rule = {"detection": {"s": selection, "condition": "s"}}
    assert sigma_matches(rule, {"cs-uri-stem": "/track/1%27", "cs-uri-query": ""})
    assert sigma_matches(rule, {"cs-uri-stem": "/track/1", "cs-uri-query": "x=%27"})
    assert not sigma_matches(rule, {"cs-uri-stem": "/track/1", "cs-uri-query": "x=1"})


def test_injection_rules_state_the_encoding_limit() -> None:
    opp = _by_id(TAINT_PY)["detect:sql-injection:GET:/orders/search"]
    assert "percent-encoding" in opp.sigma["description"]
    assert any("percent-encoding" in fp for fp in opp.sigma["falsepositives"])


def test_location_gating_is_computed_once_per_rule(monkeypatch: pytest.MonkeyPatch) -> None:
    import attackmap.detection_opportunities as do

    scan, surfaces, findings, _ = _generate(SINKS)
    calls: list[str] = []
    real = do._location_keys
    monkeypatch.setattr(do, "_location_keys", lambda f: calls.append(f.rule_id) or real(f))
    scan.taint_chains = scan.taint_chains * 50
    do._taint_opportunities(scan, {f.rule_id: f for f in findings if f.rule_id})
    assert len(calls) == len({f.rule_id for f in findings if f.rule_id})


def test_body_sources_state_the_access_log_blind_spot() -> None:
    opp = _by_id(TAINT_PY)["detect:subprocess-shell:POST:/diag/ping"]
    assert "Blind spot" in opp.sigma["description"]
    assert opp.sigma["detection"]["selection_route"]["cs-method"] == "POST"


def test_ssrf_has_route_metadata_egress_and_cloudtrail_variants() -> None:
    rules = _by_id(TAINT_PY)
    route = rules["detect:ssrf:GET:/fetch"]
    egress = rules["detect:ssrf:ssrf-metadata-egress"]
    cloudtrail = rules["detect:ssrf:ssrf-instance-credentials-cloudtrail"]
    assert route.logsource.category == "webserver"
    assert egress.logsource.category == "network_connection" and egress.signal_kind == "network"
    assert (cloudtrail.logsource.product, cloudtrail.logsource.service) == ("aws", "cloudtrail")
    assert "attack.t1552.005" in cloudtrail.sigma["tags"]
    # Public-IP instances without a VPC endpoint look like this too: medium, with filters.
    assert cloudtrail.sigma["level"] == "medium"
    assert cloudtrail.sigma["detection"]["filter_aws_internal"] == {"sourceIPAddress": "AWS Internal"}
    assert any("public IP" in fp for fp in cloudtrail.sigma["falsepositives"])
    assert sigma_matches(route.sigma, {"cs-method": "GET", "cs-uri-stem": "/fetch",
                                       "cs-uri-query": "url=http://metadata.google.internal/computeMetadata/v1/"})


def test_bola_cardinality_correlation_fires_on_enumeration_only() -> None:
    opp = _by_id(IDOR)["detect:bola-read:GET:/orders/<int:order_id>"]
    base, corr = opp.sigma, opp.sigma_correlation
    assert corr is not None and corr["correlation"]["rules"] == [base["name"]]
    assert corr["correlation"]["type"] == "value_count"
    field = corr["correlation"]["condition"]["field"]
    principal = corr["correlation"]["group-by"][0]
    assert field == "cs-uri-stem"

    def event(i: int, who: str = "203.0.113.10") -> dict:
        return {"cs-method": "GET", "cs-uri-stem": f"/orders/{i}", "sc-status": 200, principal: who}

    enumeration = [event(i) for i in range(60)]
    normal = [event(i % 5) for i in range(60)] + [event(i, f"198.51.100.{i}") for i in range(60)]
    assert correlation_fires(corr, base, enumeration)
    assert not correlation_fires(corr, base, normal)
    # Sub-resources of an object are not more objects.
    sub = [{**event(1), "cs-uri-stem": f"/orders/1/item{i}"} for i in range(60)]
    assert not correlation_fires(corr, base, sub)
    assert corr["description"].startswith("At least 50 distinct")
    # Failed requests are not object accesses.
    assert not correlation_fires(corr, base, [{**e, "sc-status": 404} for e in enumeration])


def test_authenticated_idor_groups_by_user() -> None:
    opp = _by_id(IDOR_JS)["detect:bola-read:GET:/invoices/:id"]
    assert opp.sigma_correlation["correlation"]["group-by"] == ["cs-username"]


def test_webhook_rule_checks_the_provider_header() -> None:
    _, _, findings, opps = _generate(WEBHOOKS)
    [opp] = [o for o in opps if o.id == "detect:webhook-signature"]
    detection = opp.sigma["detection"]
    assert detection["condition"] == "1 of selection_*"
    assert "cs(X-Hub-Signature-256)" in detection["selection_github"]
    assert "cs(X-Slack-Signature)" in detection["selection_slack"]
    assert not sigma_matches(opp.sigma, {"cs-method": "POST", "cs-uri-stem": "/webhooks/github",
                                         "cs(X-Hub-Signature-256)": "sha256=ab"})
    assert sigma_matches(opp.sigma, {"cs-method": "POST", "cs-uri-stem": "/webhooks/github"})
    # The prose sketch from #243 is kept.
    assert opp.title == "Alert on webhook requests with missing or invalid signature headers"


def test_webhook_rule_without_scan_still_renders() -> None:
    findings = generate_findings(scan_repo(WEBHOOKS))
    [opp] = [o for o in generate_detection_opportunities([], findings) if o.id == "detect:webhook-signature"]
    assert opp.sigma is not None
    # Without surfaces the provider is unknown, so every known header is checked.
    assert list(opp.sigma["detection"]) == ["selection_unknown", "condition"]


# ---------------------------------------------------------------------------
# Gating: only what the findings cover
# ---------------------------------------------------------------------------


def test_sanitized_chains_get_no_rule() -> None:
    ids = set(_by_id(TAINT_PY))
    assert "detect:sql-injection:GET:/orders/lookup" not in ids  # sqli_sanitized.py
    assert not any(i.startswith("detect:ssti") and "re_escape" in i for i in ids)


def test_no_scan_means_no_finding_class_rules() -> None:
    _, _, findings, _ = _generate(TAINT_PY)
    opps = generate_detection_opportunities([], findings)
    assert not [o for o in opps if o.id.startswith("detect:sql-injection")]


def test_a_suppressed_location_drops_its_rule() -> None:
    scan, surfaces, findings, _ = _generate(TAINT_PY)
    [sqli] = [f for f in findings if f.rule_id == "sql-injection"]
    sqli.locations = [FindingLocation(file="elsewhere.py", line=1)]
    opps = generate_detection_opportunities([], findings, scan, surfaces)
    assert not [o for o in opps if o.id.startswith("detect:sql-injection")]


def test_rules_per_rule_id_are_capped(tmp_path: Path) -> None:
    # Scanner input only (never executed): twelve routes with a shell sink each.
    lines = ["from flask import Flask, request", "import os", "app = Flask(__name__)"]
    for i in range(12):
        lines += [
            f"@app.get('/run{i}')",
            f"def run{i}():",
            "    host = request.args['host']",
            "    os.system('ping ' + host)",
            "    return 'ok'",
        ]
    (tmp_path / "app.py").write_text("\n".join(lines) + "\n", encoding="utf-8")
    rules = [o for o in _rules(tmp_path) if o.id.startswith("detect:subprocess-shell:")]
    assert len(rules) == 5


# ---------------------------------------------------------------------------
# Report output
# ---------------------------------------------------------------------------


def test_markdown_has_rules_and_a_coverage_table() -> None:
    scan = scan_repo(SINKS)
    surfaces = identify_attack_surfaces(scan)
    findings = generate_findings(scan, surfaces)
    md = render_defensive_review(scan, surfaces, findings, generate_attack_paths(scan, surfaces))
    assert "### Deployable Sigma rules" in md
    assert "### Detection coverage" in md
    assert "| `ldap-injection` | yes (1) | webserver |" in md
    # regex-injection has no template: shown as a gap, not hidden.
    assert "| `regex-injection` | no | — |" in md


def test_coverage_rows_count_rules_per_finding_class() -> None:
    _, _, findings, opps = _generate(TAINT_PY)
    rows = {r["rule_id"]: r for r in detection_coverage(findings, opps)}
    assert rows["ssrf"]["sigma_rules"] == 3
    assert rows["ssrf"]["logsources"] == ["webserver", "network_connection", "aws/cloudtrail"]
    assert rows["bola-read"]["correlation_rules"] == 1
    assert rows["public-data-route"]["sigma_rules"] == 0


def test_review_json_validates_against_the_schema() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    scan = scan_repo(TAINT_PY)
    surfaces = identify_attack_surfaces(scan)
    findings = generate_findings(scan, surfaces)
    payload = build_defensive_review_json(scan, surfaces, findings, generate_attack_paths(scan, surfaces))
    schema = json.loads((ROOT / "schemas" / "defensive-review.schema.json").read_text(encoding="utf-8"))
    jsonschema.validate(json.loads(json.dumps(payload)), schema)
    assert payload["schema_version"] == "1.5.0"
    assert any(row["rule_id"] == "sql-injection" and row["sigma_rules"] == 1 for row in payload["detection_coverage"])
    assert any(o["sigma"] for o in payload["detection_opportunities"])


# ---------------------------------------------------------------------------
# Route globs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("route", "inside", "outside"),
    [
        ("/orders/<int:order_id>", "/orders/42", ["/orders/42/edit", "/orders/", "/orders"]),
        ("/invoices/:id", "/invoices/1", ["/invoices/1/edit", "/invoicesX/1"]),
        ("/users/{id}/posts/{post}", "/users/1/posts/2", ["/users/1/posts/2/x", "/users/1/posts"]),
        ("/blog/[slug]", "/blog/hello", ["/blog/a/b"]),
        ("/files/*", "/files/a/b.txt", ["/other/a"]),
        ("/api/:id/*", "/api/7/x/y", ["/api/x"]),
        ("/api.v2/<id>", "/api.v2/1", ["/apiXv2/1"]),
        ("/users/:id?", "/users", ["/users/1/x", "/usersX"]),
        ("/badge/<int:s>/<uuid:k>.<slug:f>", "/badge/1/abc.svg", ["/badge/1/abc", "/badge/1/a/b.svg"]),
        ("/v1/things:batchGet", "/v1/things:batchGet", ["/v1/things:other", "/v1/x:batchGet"]),
        ("/hooks/~#&@<>\"", "/hooks/~#&@<>\"", ["/hooks/x"]),
        ("/x/<id>/~raw#&", "/x/1/~raw#&", ["/x/1/raw"]),
        ("/a?b", "/a?b", ["/ab"]),
        ("/static", "/static", ["/static/x", "/STATICX"]),
    ],
)
def test_route_selector_scopes_parameters_to_one_segment(route: str, inside: str, outside: list[str]) -> None:
    field, value = route_selector(route)
    rule = {"detection": {"s": {field: value}, "condition": "s"}}
    assert sigma_matches(rule, {"cs-uri-stem": inside})
    assert sigma_matches(rule, {"cs-uri-stem": route_example(route)})
    for path in outside:
        assert not sigma_matches(rule, {"cs-uri-stem": path}), path


@pytest.mark.parametrize(
    ("route", "inside", "outside"),
    [
        ("/flights/:from-:to", "/flights/LHR-JFK", ["/flights/LHR", "/flights/LHR-JFK/x"]),
        ("/plantae/:genus.:species", "/plantae/Prunus.persica", ["/plantae/Prunus", "/plantae/a/b.c"]),
    ],
)
def test_express_params_after_dash_or_dot(route: str, inside: str, outside: list[str]) -> None:
    field, value = route_selector(route)
    assert field == "cs-uri-stem|re"
    rule = {"detection": {"s": {field: value}, "condition": "s"}}
    assert sigma_matches(rule, {"cs-uri-stem": inside})
    assert sigma_matches(rule, {"cs-uri-stem": route_example(route)})
    for path in outside:
        assert not sigma_matches(rule, {"cs-uri-stem": path}), path


@pytest.mark.parametrize(
    "route",
    ["/users/{id:[0-9]{2}}", "/users/:id(\\d+)", "/users/:id([0-9]+)/edit", '/files/<regex("[a-z]+"):slug>', "/api/{v:v[12]}/items"],
)
def test_inline_regex_params_get_no_rule(route: str) -> None:
    assert route_selector(route) is None


def test_typed_params_without_regex_still_scope() -> None:
    assert route_selector("/users/{id:int}") == ("cs-uri-stem|re", "^/users/[^/]+$")
    assert route_selector("/users/<int:id>") == ("cs-uri-stem|re", "^/users/[^/]+$")


@pytest.mark.parametrize(
    "route",
    [
        "/", "*", "", "/:id", "/<path:p>", "/*/*", "/**", "/:a/:b", "/{x}", "/" + "a" * 200,
        # Near site-wide: one literal character isn't a scope.
        "/:a.:b", "*.*", "/<p>.<ext>", "/a/:id",
        # Too many wildcards / optional segments, non-ASCII, control characters.
        "/api" + "/:p" * 9, "/api/:a?/:b?/:c?", "/caf\u00e9/:id", "/api/:id\n",
    ],
)
def test_site_wide_and_overlong_routes_are_not_scoped(route: str) -> None:
    assert route_scopable(route) is False
    assert route_selector(route) is None


_HOSTILE_PATHS = [
    "/" * 5000,
    "/x" + "/" * 5000,
    "/x" + "/a" * 3000,
    "a" * 10000,
    "." * 10000,
    "/api/" + "a." * 4000,
    "/api/" + "~#&@" * 2000,
    "/x" + "/" + "a" * 8000 + "/y",
]


def _assert_linear(regex: str) -> None:
    import time

    compiled = re.compile(regex)
    for path in _HOSTILE_PATHS:
        start = time.perf_counter()
        compiled.search(path)
        compiled.search(path + "!")
        assert time.perf_counter() - start < 0.05, (regex, path[:20])


@pytest.mark.parametrize(
    "route",
    [
        "/x" + "/*" * 50 + "/y",  # the round-2 ReDoS: many mid-route wildcards
        "/x/*/*/*/y/*",
        "/api/{a}{b}{c}{d}/data",  # adjacent parameters
        "/api/<a>.<b>.<c>/data",
        "/api/:id/*",
        "/files/*",
        "/b/<s>/<k>.<f>",
        "/api/:a?/:b?",
    ],
)
def test_route_regexes_are_linear_on_hostile_paths(route: str) -> None:
    selector = route_selector(route)
    if selector is not None and selector[0].endswith("|re"):
        _assert_linear(selector[1])


def test_every_generated_regex_passes_the_worst_case_check() -> None:
    checked = 0
    for root in ALL_FIXTURES:
        for opp in _rules(root):
            for selection in opp.sigma["detection"].values():
                maps = selection if isinstance(selection, list) else [selection]
                for field_map in maps:
                    if not isinstance(field_map, dict):
                        continue
                    for key, value in field_map.items():
                        if "|re" in key:
                            _assert_linear(value)
                            checked += 1
    assert checked > 10


def test_regex_literals_escape_operator_characters() -> None:
    from attackmap.detections import regex_literal

    assert regex_literal("a-b_c/d") == "a-b_c/d"
    assert regex_literal('~#&@<>". ') == '\\~\\#\\&\\@\\<\\>\\"\\.\\ '
    assert re.fullmatch(regex_literal("x~#&@<>\"(.)*+?[]{}|^$\\"), "x~#&@<>\"(.)*+?[]{}|^$\\")


def test_catch_all_routes_get_no_rule(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        'const express = require("express");\n'
        'const { exec } = require("child_process");\n'
        "const app = express();\n"
        'app.get("*", (req, res) => { exec("ping " + req.query.host); res.send("ok"); });\n'
        'app.get("/:id", (req, res) => { exec("ping " + req.query.host); res.send("ok"); });\n'
        "module.exports = app;\n",
        encoding="utf-8",
    )
    _, _, findings, opps = _generate(tmp_path)
    assert any(f.rule_id == "subprocess-shell" for f in findings)
    assert not [o for o in opps if o.id.startswith("detect:subprocess-shell:")]


def test_webhook_catch_all_route_is_left_out() -> None:
    from attackmap.detection_opportunities import _webhook_rule

    assert _webhook_rule(["POST /:webhook"], ["public-webhook"], []) is None
    rendered = _webhook_rule(["POST /hooks/b", "POST /:webhook", "POST /hooks/a/:id"], ["public-webhook"], [])
    selection = rendered.sigma["detection"]["selection_unknown"]
    assert selection["cs-uri-stem|re"] == "^(?:/hooks/a/[^/]+|/hooks/b)$"
    # Order of the evidence doesn't change the rule id.
    again = _webhook_rule(["POST /hooks/a/:id", "POST /hooks/b"], ["public-webhook"], [])
    assert again.sigma["id"] == rendered.sigma["id"]


def test_route_cap_is_shared_across_classes() -> None:
    from attackmap.detection_opportunities import _fair_cap
    from attackmap.models import DetectionOpportunity

    def opp(rule: str, i: int) -> DetectionOpportunity:
        return DetectionOpportunity(id=f"detect:{rule}:{i}", title="t", rationale="r", signal_kind="log",
                                    suggested_rule="s", related_rule_ids=[rule])

    many = [opp("sql-injection", i) for i in range(5)] + [opp("eval", i) for i in range(5)] + [
        opp("bola-read", i) for i in range(5)
    ]
    kept = _fair_cap(many, limit=6)
    assert [o.related_rule_ids[0] for o in kept].count("bola-read") == 2
    assert [o.id for o in kept] == [o.id for o in many if o in kept]  # original order
    assert _fair_cap(many, limit=60) == many


# ---------------------------------------------------------------------------
# Validator and matcher
# ---------------------------------------------------------------------------


def _rule(detection: dict, **extra) -> dict:
    rule = {
        "title": "t",
        "id": "5f0e7c3a-8a8b-4c7e-9f1e-2a1b3c4d5e6f",
        "status": "experimental",
        "description": "d",
        "author": "AttackMap",
        "date": "2026-10-12",
        "tags": ["attack.t1190"],
        "logsource": {"category": "webserver"},
        "detection": detection,
        "level": "low",
    }
    rule.update(extra)
    return rule


def test_validator_flags_structural_problems() -> None:
    assert sigma_problems(_rule({"a": {"f": 1}, "condition": "a"})) == []
    assert any("undefined" in p for p in sigma_problems(_rule({"a": {"f": 1}, "condition": "a and b"})))
    assert any("matches no" in p for p in sigma_problems(_rule({"a": {"f": 1}, "condition": "1 of sel_*"})))
    assert any("parse" in p for p in sigma_problems(_rule({"a": {"f": 1}, "condition": "a and"})))
    assert any("modifier" in p for p in sigma_problems(_rule({"a": {"f|bogus": 1}, "condition": "a"})))
    assert any("tag" in p for p in sigma_problems(_rule({"a": {"f": 1}, "condition": "a"}, tags=["Attack T1190"])))
    assert any("UUID" in p for p in sigma_problems(_rule({"a": {"f": 1}, "condition": "a"}, id="nope")))
    assert any("logsource" in p for p in sigma_problems(_rule({"a": {"f": 1}, "condition": "a"}, logsource={})))
    assert any("regex" in p for p in sigma_problems(_rule({"a": {"f|re": "("}, "condition": "a"})))
    assert any("CIDR" in p for p in sigma_problems(_rule({"a": {"f|cidr": "10.0.0.0/33"}, "condition": "a"})))
    assert "missing required key 'title'" in sigma_problems({k: v for k, v in _rule({"a": {"f": 1}, "condition": "a"}).items() if k != "title"})


def test_matcher_conditions_and_modifiers() -> None:
    rule = _rule({
        "sel": {"a|contains": ["x", "y"], "b|startswith": "pre"},
        "alt": [{"c": None}, {"d|endswith": ".com"}],
        "filter": {"ip|cidr": "10.0.0.0/8"},
        "allx": {"e|contains|all": ["1", "2"]},
        "condition": "(sel or allx) and not filter and 1 of alt",
    })
    assert sigma_matches(rule, {"a": "zzXzz", "b": "PREfix", "ip": "8.8.8.8"})  # c missing -> null matches
    assert not sigma_matches(rule, {"a": "zzXzz", "b": "PREfix", "ip": "10.1.1.1"})
    assert not sigma_matches(rule, {"a": "zzXzz", "b": "PREfix", "ip": "8.8.8.8", "c": "set"})
    assert sigma_matches(rule, {"e": "1-2", "c": "set", "d": "a.com", "ip": "8.8.8.8"})
    assert not sigma_matches(rule, {"e": "1", "ip": "8.8.8.8"})
    flags = _rule({"s": {"q|re|i": "union select"}, "c": {"q|re": "union select"}, "condition": "s and not c"})
    assert sigma_matches(flags, {"q": "UNION SELECT"})
    assert not sigma_matches(flags, {"q": "union select"})
    nested = _rule({"s": {"userIdentity.type": "AssumedRole"}, "condition": "all of them"})
    assert sigma_matches(nested, {"userIdentity": {"type": "AssumedRole"}})
    assert sigma_matches(nested, {"userIdentity.type": "assumedrole"})


def test_validator_and_matcher_never_raise_on_garbage() -> None:
    rng = random.Random(251)
    alphabet = "ab_1 ()*|.:-of not and or them all\n\t$\\{}[]'\""
    for _ in range(500):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 40)))
        garbage = rng.choice([text, None, 1, [text], {text: text}, {"condition": text}, {"a": [1, {}], "condition": text}])
        rule = _rule(garbage) if rng.random() < 0.7 else garbage
        sigma_problems(rule)
        correlation_problems(rule)
        sigma_matches(rule if isinstance(rule, dict) else {}, {"a": text})
        if isinstance(rule, dict):
            correlation_fires(rule, rule, [{"a": text}])
