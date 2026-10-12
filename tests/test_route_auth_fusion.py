"""Tests for unauthenticated-route synthesis (#140)."""

from __future__ import annotations

from pathlib import Path

from attackmap.analyzer import identify_attack_surfaces
from attackmap.models import AttackSurface, Route, ScanResult
from attackmap.route_auth_fusion import synthesize_unauthenticated_routes
from attackmap.scanner import scan_repo
from attackmap.threat_model import generate_findings

_TAG = "state-changing"


def _unauth_findings(scan: ScanResult):
    return [f for f in generate_findings(scan) if _TAG in f.tags]


def _write(tmp_path: Path, name: str, body: str) -> ScanResult:
    (tmp_path / name).write_text(body, encoding="utf-8")
    return scan_repo(tmp_path)


# ---------------------------------------------------------------------------
# Express (JS) — end to end through the scanner
# ---------------------------------------------------------------------------


def test_express_unauthenticated_mutating_route_one_finding(tmp_path: Path) -> None:
    scan = _write(
        tmp_path,
        "server.js",
        "const app = require('express')();\n"
        "function requireAuth(req,res,next){ next(); }\n"
        "app.post('/orders', (req, res) => { db.insert(req.body); res.send('ok'); });\n"
        "app.put('/profile', requireAuth, (req, res) => { db.update(req.body); res.send('ok'); });\n",
    )
    findings = _unauth_findings(scan)
    assert len(findings) == 1
    evidence = "\n".join(findings[0].evidence)
    assert "/orders" in evidence
    assert "/profile" not in evidence  # guarded by the requireAuth middleware arg


def test_express_route_behind_middleware_arg_is_clean(tmp_path: Path) -> None:
    scan = _write(
        tmp_path,
        "server.js",
        "const app = require('express')();\n"
        "function requireAuth(req,res,next){ next(); }\n"
        "app.post('/orders', requireAuth, (req, res) => { db.insert(req.body); });\n",
    )
    assert _unauth_findings(scan) == []


def test_express_global_use_middleware_is_clean(tmp_path: Path) -> None:
    scan = _write(
        tmp_path,
        "server.js",
        "const app = require('express')();\n"
        "function requireAuth(req,res,next){ next(); }\n"
        "app.use(requireAuth);\n"
        "app.post('/orders', (req, res) => { db.insert(req.body); });\n",
    )
    assert _unauth_findings(scan) == []


def test_get_route_is_never_flagged(tmp_path: Path) -> None:
    scan = _write(
        tmp_path,
        "server.js",
        "const app = require('express')();\n"
        "app.get('/orders', (req, res) => { res.json(db.all()); });\n",
    )
    assert _unauth_findings(scan) == []


# ---------------------------------------------------------------------------
# FastAPI (Python) — end to end through the scanner
# ---------------------------------------------------------------------------


def test_fastapi_unauthenticated_mutating_route_one_finding(tmp_path: Path) -> None:
    scan = _write(
        tmp_path,
        "main.py",
        "from fastapi import FastAPI, Depends\n"
        "app = FastAPI()\n\n"
        '@app.post("/items")\n'
        "def create_item(item: dict):\n"
        "    return db.save(item)\n\n"
        '@app.put("/secure")\n'
        "def secure(item: dict, user=Depends(get_current_user)):\n"
        "    return db.save(item)\n",
    )
    findings = _unauth_findings(scan)
    assert len(findings) == 1
    evidence = "\n".join(findings[0].evidence)
    assert "/items" in evidence
    assert "/secure" not in evidence


def test_flask_login_required_decorator_is_clean(tmp_path: Path) -> None:
    scan = _write(
        tmp_path,
        "app.py",
        "from flask import Flask\n"
        "app = Flask(__name__)\n\n"
        '@app.route("/orders", methods=["POST"])\n'
        "@login_required\n"
        "def create():\n"
        "    return db.save(request.json)\n",
    )
    assert _unauth_findings(scan) == []


# ---------------------------------------------------------------------------
# Spring (Java) — via the fusion directly (the java-spring analyzer that
# supplies routes is a separate plugin, not part of the core scanner).
# ---------------------------------------------------------------------------


def _java_scan(tmp_path: Path, source: str, routes: list[Route]) -> tuple[ScanResult, list[AttackSurface]]:
    (tmp_path / "OrderController.java").write_text(source, encoding="utf-8")
    scan = ScanResult(root=str(tmp_path), routes=routes)
    surfaces = [
        AttackSurface(
            route=r.path,
            method=r.method,
            file=r.file,
            category="public_api",
            exposure="public",
            risk="medium",
            line=r.line,
        )
        for r in routes
    ]
    return scan, surfaces


_SPRING_SRC = """package com.x;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;

@RestController
@RequestMapping("/api")
public class OrderController {

    @PostMapping("/orders")
    public String create(@RequestBody Order o) {
        return repo.save(o);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/secure")
    public void del(@PathVariable Long id) {
        repo.delete(id);
    }
}
"""


def test_spring_method_annotation_distinguishes_routes(tmp_path: Path) -> None:
    scan, surfaces = _java_scan(
        tmp_path,
        _SPRING_SRC,
        [
            Route(path="/api/orders", method="POST", file="OrderController.java", line=9),
            Route(path="/api/secure", method="DELETE", file="OrderController.java", line=15),
        ],
    )
    findings = synthesize_unauthenticated_routes(scan, surfaces)
    assert len(findings) == 1
    evidence = "\n".join(findings[0].evidence)
    assert "/api/orders" in evidence  # no @PreAuthorize
    assert "/api/secure" not in evidence  # guarded by @PreAuthorize


def test_spring_class_level_annotation_protects_all(tmp_path: Path) -> None:
    src = """package com.x;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;

@RestController
@PreAuthorize("isAuthenticated()")
public class AdminController {
    @PostMapping("/things")
    public String create(@RequestBody Thing t) { return repo.save(t); }
}
"""
    (tmp_path / "OrderController.java").write_text(src, encoding="utf-8")
    scan = ScanResult(
        root=str(tmp_path),
        routes=[Route(path="/things", method="POST", file="OrderController.java", line=8)],
    )
    surfaces = [
        AttackSurface(
            route="/things", method="POST", file="OrderController.java",
            category="public_api", exposure="public", risk="medium", line=8,
        )
    ]
    assert synthesize_unauthenticated_routes(scan, surfaces) == []


# ---------------------------------------------------------------------------
# Scope + regression
# ---------------------------------------------------------------------------


def test_unauthenticated_admin_route_resolved_per_route(tmp_path: Path) -> None:
    # /admin/* gets the precise per-route answer too (#242): the category-level
    # admin finding is a file-windowed advisory, not a resolved control chain.
    scan = _write(
        tmp_path,
        "server.js",
        "const app = require('express')();\n"
        "app.post('/admin/wipe', (req, res) => { db.wipe(); });\n"
        "app.post('/admin/reset', requireAuth, (req, res) => { db.reset(); });\n",
    )
    findings = _unauth_findings(scan)
    assert len(findings) == 1
    assert any("/admin/wipe" in e for e in findings[0].evidence)
    assert not any("/admin/reset" in e for e in findings[0].evidence)


# Authentication entry points under an admin prefix (#328): the login step
# can't require authentication, so it is an `auth` surface, not an admin action.

_ADMIN_LOGIN_APP = (
    "const express = require('express');\n"
    "const app = express();\n"
    "app.use(express.json());\n"
    "app.post('/admin/login', async (req, res) => { res.json(await Admin.check(req.body)); });\n"
    "app.post('/admin/auth/token', async (req, res) => { res.json(await issue(req.body)); });\n"
    "app.post('/admin/logout', (req, res) => { res.clearCookie('sid').end(); });\n"
    "app.post('/admin/password/reset', (req, res) => { mailer.reset(req.body.email); res.end(); });\n"
    "app.post('/admin/oauth/google/callback', (req, res) => { res.end(); });\n"
    "app.post('/admin/users', (req, res) => { db.users.insert(req.body); res.end(); });\n"
    "app.post('/admin/login-as/:id', (req, res) => { res.cookie('as', req.params.id).end(); });\n"
    "app.post('/admin/users/:id/logout', (req, res) => { db.sessions.drop(req.params.id); res.end(); });\n"
    "app.post('/admin/api/token', (req, res) => { res.json(db.tokens.mint(req.body)); });\n"
)
_ADMIN_ENTRY_POINTS = {"/admin/login", "/admin/auth/token", "/admin/logout", "/admin/password/reset", "/admin/oauth/google/callback"}
_ADMIN_ACTIONS = {"/admin/users", "/admin/login-as/:id", "/admin/users/:id/logout", "/admin/api/token"}


def _routes_in(finding) -> set[str]:
    return {e.split(" ", 2)[1] for e in finding.evidence if e.startswith(("POST ", "GET "))}


def test_admin_login_is_not_an_unauthenticated_admin_action(tmp_path: Path) -> None:
    scan = _write(tmp_path, "server.js", _ADMIN_LOGIN_APP)
    findings = generate_findings(scan)
    unauth = [f for f in findings if f.rule_id == "unauth-state-change"]
    exposed = [f for f in findings if f.rule_id == "exposed-admin-route"]
    assert len(unauth) == 1 and len(exposed) == 1
    assert _routes_in(unauth[0]) == _ADMIN_ACTIONS
    assert _routes_in(exposed[0]) == _ADMIN_ACTIONS
    categories = {s.route: s.category for s in identify_attack_surfaces(scan)}
    assert {categories[r] for r in _ADMIN_ENTRY_POINTS} == {"auth"}
    assert {categories[r] for r in _ADMIN_ACTIONS} == {"admin"}


def test_admin_login_alone_raises_no_admin_findings(tmp_path: Path) -> None:
    scan = _write(
        tmp_path,
        "server.js",
        "const app = require('express')();\n"
        "app.post('/admin/login', async (req, res) => { res.json(await Admin.check(req.body)); });\n",
    )
    rules = {f.rule_id for f in generate_findings(scan)}
    assert not rules & {"unauth-state-change", "exposed-admin-route"}


def test_admin_login_is_not_an_admin_action_insight() -> None:
    from attackmap.security_overlay import build_security_overlay

    routes = [Route(path=p, method="POST", file="server.js", line=i + 1) for i, p in enumerate(["/admin/login", "/admin/users"])]
    scan = ScanResult(root=".", routes=routes)
    overlay = build_security_overlay(scan, identify_attack_surfaces(scan), [], [])
    flagged = [i for i in overlay.insights if i.kind == "admin_action_without_auth"]
    assert flagged and all("/admin/login " not in e for i in flagged for e in i.evidence)
    assert any("/admin/users" in e for i in flagged for e in i.evidence)


def test_internal_path_route_in_scope(tmp_path: Path) -> None:
    scan = _write(
        tmp_path,
        "app.py",
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.post('/internal/reindex')\n"
        "def reindex(payload: dict):\n"
        "    db.execute('reindex')\n",
    )
    findings = _unauth_findings(scan)
    assert findings and "/internal/reindex" in findings[0].evidence[0]


def test_webhook_route_still_not_double_reported(tmp_path: Path) -> None:
    # Webhooks keep their dedicated finding.
    scan = _write(
        tmp_path,
        "server.js",
        "const app = require('express')();\n"
        "app.post('/webhook/stripe', (req, res) => { db.save(req.body); });\n",
    )
    assert _unauth_findings(scan) == []


def test_auth_hints_still_emitted(tmp_path: Path) -> None:
    # #140 must not change auth_hints emission for downstream consumers.
    scan = _write(
        tmp_path,
        "server.js",
        "const app = require('express')();\n"
        "function requireAuth(req,res,next){ next(); }\n"
        "app.post('/orders', requireAuth, (req, res) => { jwt.verify(req.headers.authorization); });\n",
    )
    assert scan.auth_hints, "auth_hints should still be emitted"


def test_finding_carries_technique_and_evidence(tmp_path: Path) -> None:
    scan = _write(
        tmp_path,
        "main.py",
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n\n"
        '@app.post("/items")\n'
        "def create_item(item: dict):\n"
        "    return db.save(item)\n",
    )
    findings = _unauth_findings(scan)
    assert len(findings) == 1
    assert findings[0].attack_techniques
    assert findings[0].attack_techniques[0].technique_id == "T1190"
    assert "chain" in " ".join(findings[0].evidence).lower()


def test_path_literal_strip_is_linear_on_unterminated_backslashes(tmp_path: Path) -> None:
    # CodeQL py/redos: `"` followed by a run of backslashes used to backtrack
    # exponentially while stripping the path literal from the middleware list.
    import time

    scan = _write(
        tmp_path,
        "server.js",
        "const app = require('express')();\n"
        "app.post(\"" + "\\" * 5000 + "\n"
        "app.post('/x', (req, res) => { db.save(req.body); });\n",
    )
    start = time.perf_counter()
    _unauth_findings(scan)
    assert time.perf_counter() - start < 2.0
