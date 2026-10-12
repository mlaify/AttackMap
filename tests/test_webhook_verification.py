"""Webhook signature verification (#243, part B)."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from attackmap.analyzer import identify_attack_surfaces
from attackmap.bench import canonical_category
from attackmap.detection_opportunities import generate_detection_opportunities
from attackmap.scanner import scan_repo
from attackmap.taxonomy import taxonomy_for
from attackmap.threat_model import generate_attack_paths, generate_findings
from attackmap.webhook_verification import _Line, _lines_of, classify

FIXTURES = Path(__file__).parent / "fixtures" / "webhook_verification"

# A data store, so the public-webhook gate (state change near data) is met.
DB_JS = "const { Pool } = require('pg')\nmodule.exports = new Pool()\n"


def _repo(tmp_path: Path, *names: str, extra: dict[str, str] | None = None) -> Path:
    for name in names:
        shutil.copy(FIXTURES / name, tmp_path / name)
    shutil.copytree(FIXTURES / "helpers", tmp_path / "helpers")
    (tmp_path / "db.js").write_text(DB_JS, encoding="utf-8")
    for rel, text in (extra or {}).items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return tmp_path


def _webhooks(root: Path):
    return [s for s in identify_attack_surfaces(scan_repo(root)) if s.category == "webhook"]


def _state(text: str, file: str = "a.js") -> str:
    return classify(_lines_of(file, 1, text)).state


# ---------------------------------------------------------------------------
# Fixtures: one state per handler
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "state", "provider", "evidence"),
    [
        # The four from the issue's acceptance criteria.
        ("stripe_verified.js", "verified", "stripe", "stripe_verified.js:11"),
        ("github_weak_compare.js", "weak_compare", "github", "github_weak_compare.js:9"),
        ("slack_no_timestamp.py", "no_replay_guard", "slack", "slack_no_timestamp.py:18"),
        ("bare_handler.js", "absent", None, "bare_handler.js:6"),
        # Other providers and shapes.
        ("slack_verified.js", "verified", "slack", "slack_verified.js:11"),
        ("github_verified.py", "verified", "github", "github_verified.py:16"),
        ("weak_compare.go", "weak_compare", "shopify", "weak_compare.go:18"),
        ("weak_compare.php", "weak_compare", "github", "weak_compare.php:6"),
        ("svix_verified.ts", "verified", "svix", "svix_verified.ts:9"),
        ("twilio_verified.py", "verified", "twilio", "twilio_verified.py:13"),
        ("sns_verified.js", "verified", "sns", "sns_verified.js:9"),
        # One hop into an imported helper, and `.use()` middleware.
        ("helper_verified.js", "verified", "github", "helpers/verify.js:6"),
        ("middleware_verified.js", "verified", "hmac", "middleware_verified.js:9"),
    ],
)
def test_fixture_states(tmp_path: Path, name: str, state: str, provider: str | None, evidence: str) -> None:
    [surface] = _webhooks(_repo(tmp_path, name))
    v = surface.webhook_verification
    assert v is not None
    assert (v.state, v.provider, v.evidence) == (state, provider, evidence)


def test_reserialized_body_is_noted(tmp_path: Path) -> None:
    [surface] = _webhooks(_repo(tmp_path, "reserialized_body.js"))
    v = surface.webhook_verification
    assert v is not None and v.state == "verified"
    assert any("re-serialized body at reserialized_body.js:9" in note for note in v.notes)


# ---------------------------------------------------------------------------
# Classification precision
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        # Presence and length checks aren't signature comparisons.
        "const d = crypto.createHmac('sha256', k).update(b).digest('hex')\nif (sig == null) return\n",
        "const d = crypto.createHmac('sha256', k).update(b).digest('hex')\nif (signature === '') return\n",
        # An arrow function or assignment isn't an equality test.
        "const d = crypto.createHmac('sha256', k).update(b).digest('hex')\nconst f = (sig) => send(sig)\n",
    ],
)
def test_not_a_weak_compare(text: str) -> None:
    assert _state(text) == "unknown"


def test_commented_verification_does_not_count() -> None:
    assert _state("// stripe.webhooks.constructEvent(req.body, sig, secret)\nsave(req.body)\n") == "absent"


def test_svix_verify_needs_the_library() -> None:
    lines = [_Line("a.ts", 1, "const evt = wh.verify(req.body, req.headers)")]
    assert classify(lines).state == "absent"
    assert classify(lines, imported=frozenset({"svix"})).state == "verified"


def test_signature_header_handed_off_is_unknown() -> None:
    text = "const ok = checkIt(req.get('X-Hub-Signature-256'), req.body)\n"
    assert _state(text) == "unknown"


def test_hmac_without_timestamped_scheme_needs_no_replay_guard() -> None:
    text = (
        "const sig = req.get('X-Hub-Signature-256')\n"
        "const d = crypto.createHmac('sha256', k).update(req.body).digest('hex')\n"
        "if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(d))) return\n"
    )
    assert _state(text) == "verified"
    assert _state(text.replace("X-Hub-Signature-256", "X-Slack-Signature")) == "no_replay_guard"


def test_unreachable_verification_in_the_file_is_unknown(tmp_path: Path) -> None:
    content = (
        "from flask import Flask, request\n"
        "import hmac\n"
        "from .db import save\n"
        "app = Flask(__name__)\n"
        "\n"
        "def verified(f):\n"
        "    def inner():\n"
        "        if not hmac.compare_digest(sign(request), request.headers['X-Signature']):\n"
        "            return '', 401\n"
        "        return f()\n"
        "    return inner\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "@app.post('/webhook/partner')\n"
        "@verified\n"
        "def partner():\n"
        "    save(request.json)\n"
        "    return ''\n"
    )
    root = _repo(tmp_path, extra={"app.py": content})
    [surface] = _webhooks(root)
    assert surface.webhook_verification is not None
    assert surface.webhook_verification.state == "unknown"


def test_unreadable_handler_is_unknown(tmp_path: Path) -> None:
    root = _repo(tmp_path, "bare_handler.js")
    scan = scan_repo(root)
    (root / "bare_handler.js").unlink()
    [surface] = [s for s in identify_attack_surfaces(scan) if s.category == "webhook"]
    assert surface.webhook_verification is not None
    assert surface.webhook_verification.state == "unknown"


def test_non_webhook_surfaces_are_not_assessed(tmp_path: Path) -> None:
    root = _repo(tmp_path, "bare_handler.js", extra={"orders.js": "app.post('/orders', (req, res) => res.end())\n"})
    others = [s for s in identify_attack_surfaces(scan_repo(root)) if s.category != "webhook"]
    assert others and all(s.webhook_verification is None for s in others)


# ---------------------------------------------------------------------------
# Findings follow the state
# ---------------------------------------------------------------------------


def _by_rule(root: Path) -> dict[str, list]:
    out: dict[str, list] = {}
    for f in generate_findings(scan_repo(root)):
        out.setdefault(f.rule_id, []).append(f)
    return out


def test_absent_is_a_high_public_webhook_finding(tmp_path: Path) -> None:
    rules = _by_rule(_repo(tmp_path, "bare_handler.js"))
    [finding] = rules["public-webhook"]
    assert finding.severity == "high"
    assert "no signature verification found in the handler" in finding.evidence[0]
    assert "webhook-weak-verification" not in rules


@pytest.mark.parametrize("name", ["stripe_verified.js", "helper_verified.js", "svix_verified.ts"])
def test_verified_is_suppressed(tmp_path: Path, name: str) -> None:
    rules = _by_rule(_repo(tmp_path, name))
    assert "public-webhook" not in rules
    assert "webhook-weak-verification" not in rules


def test_weak_compare_is_a_medium_finding_at_the_compare(tmp_path: Path) -> None:
    rules = _by_rule(_repo(tmp_path, "github_weak_compare.js"))
    assert "public-webhook" not in rules
    [finding] = rules["webhook-weak-verification"]
    assert finding.severity == "medium"
    assert "non-constant-time equality at github_weak_compare.js:9" in finding.evidence[0]
    assert {(loc.file, loc.line) for loc in finding.locations} == {
        ("github_weak_compare.js", 6),
        ("github_weak_compare.js", 9),
    }
    assert canonical_category(finding.model_dump()) == "webhook_exposure"


def test_missing_replay_guard_is_a_medium_finding(tmp_path: Path) -> None:
    root = _repo(tmp_path, "slack_no_timestamp.py", extra={"db.py": "import sqlite3\n"})
    [finding] = _by_rule(root)["webhook-weak-verification"]
    assert "the signed timestamp is never checked" in finding.evidence[0]


# ---------------------------------------------------------------------------
# Attack path and detection opportunity
# ---------------------------------------------------------------------------


def _webhook_path(root: Path):
    paths = generate_attack_paths(scan_repo(root))
    return next((p for p in paths if p.name == "External event spoofing into internal state change"), None)


def test_attack_path_cites_the_state_and_evidence_line(tmp_path: Path) -> None:
    path = _webhook_path(_repo(tmp_path, "github_weak_compare.js"))
    assert path is not None
    weak = next(step for step in path.steps if "Weak point" in step)
    assert "non-constant-time equality at github_weak_compare.js:9" in weak


def test_attack_path_for_an_absent_check(tmp_path: Path) -> None:
    path = _webhook_path(_repo(tmp_path, "bare_handler.js"))
    assert path is not None
    assert any("No signature verification was found" in step and "bare_handler.js:6" in step for step in path.steps)


def test_verified_webhook_does_not_anchor_a_spoofing_path(tmp_path: Path) -> None:
    assert _webhook_path(_repo(tmp_path, "stripe_verified.js")) is None


@pytest.mark.parametrize("name", ["bare_handler.js", "github_weak_compare.js"])
def test_detection_opportunity_for_absent_or_weak(tmp_path: Path, name: str) -> None:
    findings = generate_findings(scan_repo(_repo(tmp_path, name)))
    opportunities = generate_detection_opportunities([], findings)
    [opp] = [o for o in opportunities if o.id == "detect:webhook-signature"]
    assert opp.title == "Alert on webhook requests with missing or invalid signature headers"
    assert "`POST /webhook" in opp.suggested_rule
    assert opp.attack_techniques


def test_no_detection_opportunity_when_verified(tmp_path: Path) -> None:
    findings = generate_findings(scan_repo(_repo(tmp_path, "stripe_verified.js")))
    assert not [o for o in generate_detection_opportunities([], findings) if o.id == "detect:webhook-signature"]


def test_rule_is_registered() -> None:
    entry = taxonomy_for("webhook-weak-verification")
    assert entry is not None and 208 in entry.cwe and 294 in entry.cwe
