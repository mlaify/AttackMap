"""Deployable Sigma rules, part 2 (#251): CI workflows, GitHub OIDC, leaked
AWS keys, route-less code weaknesses, and the `detections/` export."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest
import yaml

from attackmap.analyzer import identify_attack_surfaces
from attackmap.detection_opportunities import detection_coverage, generate_detection_opportunities
from attackmap.detections import RULE_FILE, rule_filename, rule_yaml
from attackmap.detections.sigma import correlation_problems, sigma_matches, sigma_problems
from attackmap.models import FindingLocation
from attackmap.report import write_detection_rules
from attackmap.review_json import build_defensive_review_json
from attackmap.scanner import scan_repo
from attackmap.threat_model import generate_attack_paths, generate_findings

WORKFLOW_FIXTURES = Path(__file__).parent / "fixtures" / "workflows"
# Built from parts so the literal never sits in the source (#235).
AWS_KEY = "AKIA" + "IOSFODNN7" + "EXAMPLE"


def _workflow_repo(tmp_path: Path) -> Path:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    for case in sorted(WORKFLOW_FIXTURES.iterdir()):
        if (case / "vulnerable.yml").is_file():
            shutil.copy(case / "vulnerable.yml", wf / f"{case.name}.yml")
    return tmp_path


def _weakness_repo(tmp_path: Path) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "config.js").write_text(f'const key = "{AWS_KEY}";\nmodule.exports = key\n', encoding="utf-8")
    (tmp_path / "app.js").write_text(
        'const _ = require("lodash")\n'
        "function update(req, target) {\n"
        "  _.merge(target, req.body)\n"
        "}\n"
        "const server = new ApolloServer({ typeDefs, resolvers, introspection: true })\n"
        "module.exports = update\n",
        encoding="utf-8",
    )
    return tmp_path


def _generate(root: Path):
    scan = scan_repo(root)
    surfaces = identify_attack_surfaces(scan)
    findings = generate_findings(scan, surfaces)
    return scan, surfaces, findings, generate_detection_opportunities([], findings, scan, surfaces)


def _rules(root: Path) -> dict:
    return {o.id: o for o in _generate(root)[3] if o.sigma is not None}


def _assert_valid(opp) -> None:
    assert sigma_problems(opp.sigma) == [], opp.id
    assert opp.test_events.positive
    assert all(sigma_matches(opp.sigma, e) for e in opp.test_events.positive), opp.id
    assert not any(sigma_matches(opp.sigma, e) for e in opp.test_events.negative), opp.id
    if opp.sigma_correlation:
        assert correlation_problems(opp.sigma_correlation, [opp.sigma]) == []


# ---------------------------------------------------------------------------
# CI workflows
# ---------------------------------------------------------------------------


def test_workflow_rules_per_untrusted_trigger(tmp_path: Path) -> None:
    rules = _rules(_workflow_repo(tmp_path))
    prt = rules["detect:workflow:pull_request_target"]
    assert sorted(prt.related_rule_ids) == ["cache-poisoning-pr-target", "pr-target-checkout"]
    assert (prt.logsource.product, prt.logsource.service) == ("github", "audit")
    assert prt.sigma["detection"]["selection"] == {
        "action": "workflows.created_workflow_run",
        "event": ["pull_request_target"],
    }
    assert "detect:workflow:issue_comment" in rules
    assert "detect:workflow:workflow_run" in rules
    for opp in rules.values():
        _assert_valid(opp)


def test_oidc_on_untrusted_trigger_gets_a_cloudtrail_rule(tmp_path: Path) -> None:
    opp = _rules(_workflow_repo(tmp_path))["detect:oidc-on-untrusted-trigger:cloudtrail"]
    assert (opp.logsource.product, opp.logsource.service) == ("aws", "cloudtrail")
    assert "attack.t1078.004" in opp.sigma["tags"]
    event = {
        "eventSource": "sts.amazonaws.com",
        "eventName": "AssumeRoleWithWebIdentity",
        "userIdentity": {
            "identityProvider": "arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com",
            "userName": "repo:o/r:pull_request",
        },
    }
    assert sigma_matches(opp.sigma, event)
    assert not sigma_matches(opp.sigma, {**event, "eventName": "AssumeRole"})


def test_hygiene_workflow_kinds_are_reported_uncovered(tmp_path: Path) -> None:
    _, _, findings, opps = _generate(_workflow_repo(tmp_path))
    rows = {r["rule_id"]: r["sigma_rules"] for r in detection_coverage(findings, opps)}
    assert rows["pr-target-checkout"] == 1
    for rule_id in ("unpinned-action", "curl-pipe-shell", "script-injection", "default-token-permissions"):
        if rule_id in rows:
            assert rows[rule_id] == 0, rule_id


def test_hardened_workflows_get_no_rules(tmp_path: Path) -> None:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    for case in sorted(WORKFLOW_FIXTURES.iterdir()):
        hardened = case / "hardened.yml"
        # That case only hardens persist-credentials; its PR-target checkout
        # is still a (correct) pr-target-checkout finding.
        if hardened.is_file() and case.name != "checkout_persist_credentials":
            shutil.copy(hardened, wf / f"{case.name}.yml")
    assert not [i for i in _rules(tmp_path) if i.startswith(("detect:workflow:", "detect:oidc"))]


# ---------------------------------------------------------------------------
# Secrets and code weaknesses
# ---------------------------------------------------------------------------


def test_leaked_aws_key_rule_uses_a_placeholder_never_the_key(tmp_path: Path) -> None:
    opp = _rules(_weakness_repo(tmp_path))["detect:hardcoded-secret:aws-access-key"]
    _assert_valid(opp)
    assert opp.sigma["detection"]["selection"] == {"userIdentity.accessKeyId": "REPLACE_WITH_LEAKED_ACCESS_KEY_ID"}
    assert "config.js" in opp.sigma["description"]
    assert AWS_KEY not in json.dumps(opp.model_dump())


def test_non_aws_secrets_get_no_cloudtrail_rule(tmp_path: Path) -> None:
    (tmp_path / "a.js").write_text('const t = "gh' + 'p_' + 'abcdefghijklmnopqrstuvwxyz0123456789";\n', encoding="utf-8")
    assert not [i for i in _rules(tmp_path) if "aws-access-key" in i]


def test_a_suppressed_secret_location_drops_the_rule(tmp_path: Path) -> None:
    scan, surfaces, findings, _ = _generate(_weakness_repo(tmp_path))
    [secret] = [f for f in findings if f.rule_id == "hardcoded-secret"]
    secret.locations = [FindingLocation(file="other.js", line=1)]
    opps = generate_detection_opportunities([], findings, scan, surfaces)
    assert not [o for o in opps if o.id == "detect:hardcoded-secret:aws-access-key"]


def test_code_weakness_rules(tmp_path: Path) -> None:
    rules = _rules(_weakness_repo(tmp_path))
    proto = rules["detect:prototype-pollution:requests"]
    graphql = rules["detect:graphql-exposure:requests"]
    for opp in (proto, graphql):
        _assert_valid(opp)
        assert opp.logsource.category == "webserver"
    assert sigma_matches(proto.sigma, {"cs-uri-query": "a%5B__proto__%5D%5Bx%5D=1"})
    assert sigma_matches(graphql.sigma, {"cs-uri-query": "query=%7B__schema%7Btypes%7Bname%7D%7D%7D"})
    assert graphql.sigma["level"] == "low"


# ---------------------------------------------------------------------------
# pySigma (dev extra)
# ---------------------------------------------------------------------------


def test_part2_rules_validate_with_pysigma(tmp_path: Path) -> None:
    pytest.importorskip("sigma")
    import importlib
    import inspect
    import pkgutil

    import sigma.validators.core as core
    from sigma.collection import SigmaCollection
    from sigma.validation import SigmaValidator
    from sigma.validators.base import SigmaRuleValidator

    docs = []
    for root in (_workflow_repo(tmp_path / "wf"), _weakness_repo(tmp_path / "wk")):
        for opp in _rules(root).values():
            docs.append(opp.sigma)
            if opp.sigma_correlation:
                docs.append(opp.sigma_correlation)
    collection = SigmaCollection.from_dicts(docs, collect_errors=True)
    collection.resolve_rule_references()
    assert [(r.title, e) for r in collection for e in r.errors] == []
    validators = []
    for info in pkgutil.iter_modules(core.__path__):
        module = importlib.import_module(f"sigma.validators.core.{info.name}")
        for name, cls in vars(module).items():
            if (inspect.isclass(cls) and issubclass(cls, SigmaRuleValidator) and not inspect.isabstract(cls)
                    and cls.__module__ == module.__name__ and name not in ("ATTACKTagValidator", "D3FENDTagValidator")):
                validators.append(cls)
    assert list(SigmaValidator(validators).validate_rules(collection)) == []


# ---------------------------------------------------------------------------
# detections/ export
# ---------------------------------------------------------------------------


def _review_opps(root: Path) -> list[dict]:
    scan = scan_repo(root)
    surfaces = identify_attack_surfaces(scan)
    findings = generate_findings(scan, surfaces)
    return build_defensive_review_json(scan, surfaces, findings, generate_attack_paths(scan, surfaces))[
        "detection_opportunities"
    ]


def test_rule_files_are_written_with_an_index(tmp_path: Path) -> None:
    opps = _review_opps(_workflow_repo(tmp_path / "repo"))
    out = tmp_path / "out"
    out.mkdir()
    written = write_detection_rules(out, opps)
    assert written and all(RULE_FILE.fullmatch(n) for n in written)
    index = json.loads((out / "detections" / "index.json").read_text(encoding="utf-8"))
    assert [e["file"] for e in index] == written
    for entry in index:
        docs = list(yaml.safe_load_all((out / "detections" / entry["file"]).read_text(encoding="utf-8")))
        assert docs[0]["id"] == entry["id"]
        assert sigma_problems(docs[0]) == []
    # Deterministic: a rerun writes the same names and bytes.
    before = {n: (out / "detections" / n).read_bytes() for n in written}
    assert write_detection_rules(out, opps) == written
    assert before == {n: (out / "detections" / n).read_bytes() for n in written}


def test_bola_rule_file_holds_the_correlation_as_a_second_document(tmp_path: Path) -> None:
    fixtures = Path(__file__).parent / "fixtures" / "authz" / "flask_login_required_idor"
    opps = _review_opps(fixtures)
    written = write_detection_rules(tmp_path, opps)
    [name] = [n for n in written if n.startswith("bola-read")]
    docs = list(yaml.safe_load_all((tmp_path / "detections" / name).read_text(encoding="utf-8")))
    assert len(docs) == 2
    assert docs[1]["correlation"]["rules"] == [docs[0]["name"]]


def test_stale_rule_files_are_removed_but_nothing_else(tmp_path: Path) -> None:
    opps = _review_opps(_workflow_repo(tmp_path / "repo"))
    out = tmp_path / "out"
    out.mkdir()
    written = write_detection_rules(out, opps)
    detections = out / "detections"
    (detections / "mine.yml").write_text("keep", encoding="utf-8")
    # A later run produces one rule fewer.
    dropped = written[0]
    survivors = [o for o in opps if not (o.get("sigma") and rule_filename(o["id"], o["sigma"]["id"]) == dropped)]
    write_detection_rules(out, survivors)
    assert not (detections / dropped).exists()
    assert (detections / "mine.yml").read_text(encoding="utf-8") == "keep"
    # A tampered index can't make it delete anything outside its own names.
    (detections / "index.json").write_text(json.dumps([{"file": "../outside.txt"}, {"file": "mine.yml"}, 5]),
                                           encoding="utf-8")
    (out / "outside.txt").write_text("x", encoding="utf-8")
    write_detection_rules(out, survivors)
    assert (out / "outside.txt").exists() and (detections / "mine.yml").exists()


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_symlinked_rule_file_is_not_followed(tmp_path: Path) -> None:
    opps = _review_opps(_workflow_repo(tmp_path / "repo"))
    out = tmp_path / "out"
    (out / "detections").mkdir(parents=True)
    victim = tmp_path / "victim.txt"
    victim.write_text("original", encoding="utf-8")
    first = next(o for o in opps if o.get("sigma"))
    (out / "detections" / rule_filename(first["id"], first["sigma"]["id"])).symlink_to(victim)
    with pytest.raises(Exception):
        write_detection_rules(out, opps)
    assert victim.read_text(encoding="utf-8") == "original"


def test_no_rules_writes_nothing(tmp_path: Path) -> None:
    assert write_detection_rules(tmp_path, [{"id": "detect:x", "sigma": None}]) == []
    assert not (tmp_path / "detections").exists()


def test_corrupt_index_is_ignored(tmp_path: Path) -> None:
    (tmp_path / "detections").mkdir()
    (tmp_path / "detections" / "index.json").write_text("{not json", encoding="utf-8")
    opps = _review_opps(_workflow_repo(tmp_path / "repo"))
    assert write_detection_rules(tmp_path, opps)


def test_rule_filename_and_yaml() -> None:
    name = rule_filename("detect:sql-injection:GET:/orders/<int:id>", "8bffd693-f16a-561e-b187-79e552876689")
    assert name == "sql-injection-get-orders-int-id-8bffd693.yml"
    assert RULE_FILE.fullmatch(name)
    assert RULE_FILE.fullmatch(rule_filename("detect:" + "x" * 500, "0" * 32))
    assert rule_yaml({"a": 1}, {"b": 2}) == "a: 1\n---\nb: 2\n"
