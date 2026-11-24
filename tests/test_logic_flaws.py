"""Business-logic / race-condition leads (#245)."""

from __future__ import annotations

import json
from pathlib import Path

from attackmap.logic_flaws import find_logic_flaws
from attackmap.models import Route, ScanResult
from attackmap.review_prompts import render_hunt_prompts
from attackmap.threat_model import generate_findings

_DJANGO = """from django.db import transaction

def withdraw(request):
    user = request.user
    amt = int(request.POST["amount"])
    if user.balance >= amt:
        user.balance -= amt
        user.save()
    return JsonResponse({"ok": True})
"""
_DJANGO_LOCKED = """from django.db import transaction

def withdraw(request):
    amt = int(request.POST["amount"])
    with transaction.atomic():
        user = User.objects.select_for_update().get(pk=request.user.pk)
        if user.balance >= amt:
            user.balance -= amt
            user.save()
    return JsonResponse({"ok": True})
"""
_MONGOOSE = """app.post('/api/spend', async (req, res) => {
  const acct = await Account.findOne({ _id: req.user.id });
  if (acct.balance >= req.body.amount) {
    acct.balance -= req.body.amount;
    await acct.save();
  }
  res.json({ ok: true });
});
"""
_MONGOOSE_ATOMIC = """app.post('/api/spend', async (req, res) => {
  const amt = req.body.amount;
  const acct = await Account.findOneAndUpdate({ _id: req.user.id, balance: { $gte: amt } }, { $inc: { balance: -amt } });
  if (!acct) return res.status(409).end();
  res.json({ ok: true });
});
"""


def _flaws(tmp_path: Path, name: str, text: str, route: Route) -> list:
    (tmp_path / name).write_text(text)
    scan = ScanResult(root=str(tmp_path), routes=[route])
    scan.logic_flaws = find_logic_flaws(scan, tmp_path)
    return scan


def test_check_then_act_is_flagged_unless_locked_or_atomic(tmp_path: Path) -> None:
    django = Route(path="/wallet/withdraw", method="POST", file="views.py", line=3)
    express = Route(path="/api/spend", method="POST", file="app.js", line=1)
    for name, text, route, flagged in (
        ("views.py", _DJANGO, django, True),
        ("views.py", _DJANGO_LOCKED, django, False),
        ("app.js", _MONGOOSE, express, True),
        ("app.js", _MONGOOSE_ATOMIC, express, False),
    ):
        scan = _flaws(tmp_path, name, text, route)
        races = [c for c in scan.logic_flaws if c.kind == "check_then_act"]
        assert bool(races) is flagged, (name, flagged)
        if flagged:
            assert races[0].field == "balance"
            [finding] = [f for f in generate_findings(scan) if f.rule_id == "race-check-then-act"]
            assert finding.confidence == "low" and "needs human review" in finding.evidence[0]


def test_redeem_route_without_idempotency_is_a_low_confidence_lead(tmp_path: Path) -> None:
    redeem = Route(path="/coupons/redeem", method="POST", file="coupons.js", line=1)
    body = "app.post('/coupons/redeem', async (req, res) => {\n  await Coupon.apply(req.user.id, req.body.code);\n  res.json({ ok: true });\n});\n"
    scan = _flaws(tmp_path, "coupons.js", body, redeem)
    assert [c.kind for c in scan.logic_flaws] == ["idempotency_gap"]
    [finding] = [f for f in generate_findings(scan) if f.rule_id == "idempotency-gap"]
    assert (finding.severity, finding.confidence) == ("low", "low")
    guarded = body.replace("await Coupon.apply", "if (await Redemption.exists({ code: req.body.code })) return res.status(409).end(); // already redeemed\n  await Coupon.apply")
    assert _flaws(tmp_path, "coupons.js", guarded, redeem).logic_flaws == []
    limited = redeem.model_copy(update={"guards": ["redeemRateLimiter"]})
    assert _flaws(tmp_path, "coupons.js", body, limited).logic_flaws == []


def test_hunt_pack_cites_logic_leads(tmp_path: Path) -> None:
    scan = _flaws(tmp_path, "views.py", _DJANGO, Route(path="/wallet/withdraw", method="POST", file="views.py", line=3))
    pack = json.loads(render_hunt_prompts(scan, [], generate_findings(scan), []).evidence_json)
    assert pack["logic_flaws"][0]["id"] == "logic:1"
    assert pack["logic_flaws"][0]["kind"] == "check_then_act"
