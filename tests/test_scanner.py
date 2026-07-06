from pathlib import Path

from attackmap.analyzers import AnalyzerSignals, get_builtin_analyzers, merge_analyzer_signals
from attackmap.models import AuthHint, DatabaseHint, ExternalCall, Route, ScanResult, SecretHint
from attackmap.scanner import scan_repo


def test_builtin_analyzers_are_explicitly_registered() -> None:
    analyzers = get_builtin_analyzers()

    assert [analyzer.name for analyzer in analyzers] == [
        "routes",
        "external_calls",
        "databases",
        "auth",
        "secrets",
    ]


def test_merge_analyzer_signals_applies_core_merge_rules() -> None:
    scan = ScanResult(root=".")
    signals = AnalyzerSignals(
        routes=[
            Route(path="/users", method="GET", file="api.py"),
            Route(path="/users", method="GET", file="api.py"),
        ],
        external_calls=[
            ExternalCall(target="https://api.example.com/a", file="api.py"),
            ExternalCall(target="https://api.example.com/a", file="api.py"),
        ],
        databases=[
            DatabaseHint(kind="postgresql", file="db.py"),
            DatabaseHint(kind="postgresql", file="db.py"),
        ],
        auth_hints=[
            AuthHint(hint="jwt", file="auth.py"),
            AuthHint(hint="jwt", file="auth.py"),
        ],
        secret_hints=[
            SecretHint(name="STRIPE_SECRET_KEY", file="api.py"),
            SecretHint(name="STRIPE_SECRET_KEY", file="api.py"),
        ],
    )

    merge_analyzer_signals(scan, signals)

    assert len(scan.routes) == 2
    assert len(scan.external_calls) == 2
    assert len(scan.secret_hints) == 2
    assert scan.databases == [DatabaseHint(kind="postgresql", file="db.py")]
    assert scan.auth_hints == [AuthHint(hint="jwt", file="auth.py")]


def test_scan_repo_detects_fastapi_routes_and_secrets(tmp_path: Path) -> None:
    app_file = tmp_path / "app.py"
    app_file.write_text(
        '''
from fastapi import APIRouter, Depends, FastAPI
from fastapi.security import OAuth2PasswordBearer
import os
import requests

app = FastAPI()
api = APIRouter(prefix="/api")
router = APIRouter(prefix="/v1")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

api.include_router(router)

@app.post("/webhook/stripe")
def stripe_hook():
    secret = os.getenv("STRIPE_SECRET_KEY")
    requests.post("https://api.example.com/process")
    return {"ok": True}

@router.api_route("/items", methods=["GET", "PATCH"])
def items(token: str = Depends(oauth2_scheme)):
    return {"ok": True}
''',
        encoding="utf-8",
    )

    result = scan_repo(tmp_path)

    assert result.files_scanned == 1
    assert any(route.path == "/webhook/stripe" for route in result.routes)
    assert any(route.path == "/api/v1/items" and route.method == "GET" for route in result.routes)
    assert any(route.path == "/api/v1/items" and route.method == "PATCH" for route in result.routes)
    assert any(secret.name == "STRIPE_SECRET_KEY" for secret in result.secret_hints)
    assert any(call.target == "https://api.example.com/process" for call in result.external_calls)
    assert any(hint.hint == "oauth" for hint in result.auth_hints)
    assert any(hint.hint == "depends_auth" for hint in result.auth_hints)


def test_scan_repo_detects_flask_blueprint_routes(tmp_path: Path) -> None:
    app_file = tmp_path / "app.py"
    app_file.write_text(
        '''
from flask import Blueprint, Flask
from flask_login import login_required

app = Flask(__name__)
api = Blueprint("api", __name__, url_prefix="/api")
admin = Blueprint("admin", __name__, url_prefix="/admin")
api.register_blueprint(admin, url_prefix="/v1")

@app.route("/login", methods=["POST"])
def login():
    return {"ok": True}

@login_required
@admin.route("/users", methods=["GET", "DELETE"])
def manage_users():
    return {"ok": True}
''',
        encoding="utf-8",
    )

    result = scan_repo(tmp_path)

    assert any(route.path == "/login" and route.method == "POST" for route in result.routes)
    assert any(route.path == "/api/v1/admin/users" and route.method == "GET" for route in result.routes)
    assert any(route.path == "/api/v1/admin/users" and route.method == "DELETE" for route in result.routes)
    assert any(hint.hint == "login_required" for hint in result.auth_hints)


def test_scan_repo_detects_express_mounted_and_chained_routes(tmp_path: Path) -> None:
    app_file = tmp_path / "server.js"
    app_file.write_text(
        """
const express = require("express");
const app = express();
const router = express.Router();
const adminRouter = express.Router();
const passport = require("passport");
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();

app.use("/api/v1", router);
router.use("/admin", adminRouter);
app.get("/health", (_req, res) => res.send("ok"));
router.route("/users")
  .get((_req, res) => res.send("users"))
  .post((_req, res) => res.send("created"));
adminRouter.get("/audit", passport.authenticate("jwt", { session: false }), (_req, res) => res.send("audit"));
router.delete("/users/:id", (_req, res) => res.send("deleted"));
""",
        encoding="utf-8",
    )

    result = scan_repo(tmp_path)

    assert any(route.path == "/health" and route.method == "GET" for route in result.routes)
    assert any(route.path == "/api/v1/users" and route.method == "GET" for route in result.routes)
    assert any(route.path == "/api/v1/users" and route.method == "POST" for route in result.routes)
    assert any(route.path == "/api/v1/users/:id" and route.method == "DELETE" for route in result.routes)
    assert any(route.path == "/api/v1/admin/audit" and route.method == "GET" for route in result.routes)
    assert any(db.kind == "sql" for db in result.databases)
    assert any(hint.hint == "passport" for hint in result.auth_hints)


def test_scan_repo_detects_database_and_auth_patterns_without_duplicate_keyword_noise(tmp_path: Path) -> None:
    app_file = tmp_path / "service.py"
    app_file.write_text(
        '''
from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import create_engine
import redis
import sqlite3

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
engine = create_engine("postgresql+psycopg://app:pw@localhost/app")
cache = redis.Redis(host="localhost", port=6379)
local = sqlite3.connect("tmp.db")

def endpoint(token: str = Depends(oauth2_scheme)):
    return {"ok": True}
''',
        encoding="utf-8",
    )

    result = scan_repo(tmp_path)

    kinds = {(db.kind, db.file) for db in result.databases}
    hints = {(hint.hint, hint.file) for hint in result.auth_hints}

    assert ("sql", "service.py") in kinds
    assert ("postgresql", "service.py") in kinds
    assert ("redis", "service.py") in kinds
    assert ("sqlite", "service.py") in kinds
    assert ("oauth", "service.py") in hints
    assert ("depends_auth", "service.py") in hints
    assert len([hint for hint in result.auth_hints if hint.file == "service.py" and hint.hint == "oauth"]) == 1


def test_scan_repo_keeps_javascript_typescript_extraction_generic(tmp_path: Path) -> None:
    api_file = tmp_path / "services" / "api" / "src" / "server.ts"
    api_file.parent.mkdir(parents=True, exist_ok=True)
    api_file.write_text(
        """
import express from "express";
const app = express();
const relayBaseUrl = process.env.RELAY_URL;
const signingKey = process.env.SERVICE_SIGNING_KEY;

app.post("/xrpc/com.atproto.server.createSession", async (_req, res) => {
  await fetch("https://relay.example.net/xrpc/com.atproto.sync.subscribeRepos");
  return res.json({ ok: true, relayBaseUrl });
});
""",
        encoding="utf-8",
    )

    worker_file = tmp_path / "services" / "relay" / "src" / "consumer.ts"
    worker_file.parent.mkdir(parents=True, exist_ok=True)
    worker_file.write_text(
        """
export async function startConsumer(queue: { subscribe: (topic: string) => Promise<void> }) {
  await queue.subscribe("sync.events");
}
""",
        encoding="utf-8",
    )

    result = scan_repo(tmp_path)
    hints = {(hint.hint, hint.file) for hint in result.auth_hints}
    calls = {(call.target, call.file) for call in result.external_calls}
    routes = {(route.path, route.method, route.file) for route in result.routes}
    secrets = {(secret.name, secret.file) for secret in result.secret_hints}

    assert ("/xrpc/com.atproto.server.createSession", "POST", "services/api/src/server.ts") in routes
    assert ("https://relay.example.net/xrpc/com.atproto.sync.subscribeRepos", "services/api/src/server.ts") in calls
    assert ("SERVICE_SIGNING_KEY", "services/api/src/server.ts") in secrets

    # Scanner remains generic and no longer emits node-service/atproto overlays.
    assert not any(hint.startswith("service_name:") for hint, _ in hints)
    assert not any(hint.startswith("service_role:") for hint, _ in hints)
    assert not any(hint.startswith("handler_type:") for hint, _ in hints)
    assert not any(hint.startswith("handler_visibility:") for hint, _ in hints)
    assert not any(hint.startswith("edge:") for hint, _ in hints)
    assert not any(hint.startswith("atproto_") for hint, _ in hints)


# ---------------------------------------------------------------------------
# Route detection improvements for issue #1:
#   - Add detection for FastAPI, Flask, and Express
#   - Normalize extracted routes: HTTP method + full path
#   - Ensure consistent output format across frameworks
# ---------------------------------------------------------------------------


def test_scan_repo_normalizes_paths_without_leading_slash(tmp_path: Path) -> None:
    """Routes written without a leading ``/`` are normalized to ``/foo`` form."""
    app_file = tmp_path / "app.py"
    app_file.write_text(
        '''
from fastapi import FastAPI, APIRouter
from flask import Blueprint, Flask
import express

app = FastAPI()
api = APIRouter(prefix="api")  # no leading slash on prefix
fa = Flask(__name__)
fa_admin = Blueprint("admin", __name__, url_prefix="admin")  # no leading slash

@app.get("users")
def list_users():
    return []

@api.post("create")
def create():
    return {}

fa.register_blueprint(fa_admin, url_prefix="v1")  # no leading slash

@fa_admin.route("audit", methods=["GET"])
def audit():
    return {}
''',
        encoding="utf-8",
    )

    result = scan_repo(tmp_path)
    paths = {route.path for route in result.routes}

    # FastAPI: path and prefix without leading slash are normalized.
    assert "/users" in paths
    assert "/api/create" in paths
    # Flask: blueprint and register url_prefix without leading slash are normalized.
    assert "/v1/admin/audit" in paths

    # Every emitted route must start with a single forward slash.
    for route in result.routes:
        assert route.path.startswith("/"), f"Path not normalized: {route.path!r}"
        assert "//" not in route.path, f"Path has double slash: {route.path!r}"


def test_scan_repo_detects_express_app_all(tmp_path: Path) -> None:
    """Express ``app.all``/``router.all`` is detected and emitted as method ``ANY``."""
    app_file = tmp_path / "server.js"
    app_file.write_text(
        """
const express = require("express");
const app = express();
const router = express.Router();

app.all("/health", (_req, res) => res.send("ok"));
router.all("/items", (_req, res) => res.send("any"));

router.route("/probe")
  .all((_req, res) => res.send("probe"))
  .get((_req, res) => res.send("probe-get"));
""",
        encoding="utf-8",
    )

    result = scan_repo(tmp_path)
    pairs = {(route.path, route.method) for route in result.routes}

    assert ("/health", "ANY") in pairs
    assert ("/items", "ANY") in pairs
    assert ("/probe", "ANY") in pairs
    assert ("/probe", "GET") in pairs


def test_scan_repo_normalizes_express_double_slash_paths(tmp_path: Path) -> None:
    """Paths containing ``//`` are collapsed to a single ``/`` for consistency."""
    app_file = tmp_path / "server.js"
    app_file.write_text(
        """
const express = require("express");
const app = express();

app.get("//users", (_req, res) => res.send("u"));
app.get("/a//b//c", (_req, res) => res.send("x"));
""",
        encoding="utf-8",
    )

    result = scan_repo(tmp_path)
    paths = [route.path for route in result.routes]

    assert "/users" in paths
    assert "/a/b/c" in paths


def test_scan_repo_consistent_route_shape_across_frameworks(tmp_path: Path) -> None:
    """All three frameworks emit the same (method, path) shape with leading ``/``."""
    fastapi_file = tmp_path / "fa_app.py"
    fastapi_file.write_text(
        '''
from fastapi import FastAPI
app = FastAPI()

@app.get("ping")
def ping():
    return {"ok": True}
''',
        encoding="utf-8",
    )

    flask_file = tmp_path / "fl_app.py"
    flask_file.write_text(
        '''
from flask import Flask
app = Flask(__name__)

@app.route("ping", methods=["GET"])
def ping():
    return {"ok": True}
''',
        encoding="utf-8",
    )

    express_file = tmp_path / "ex_app.js"
    express_file.write_text(
        """
const express = require("express");
const app = express();
app.get("ping", (_req, res) => res.send("ok"));
""",
        encoding="utf-8",
    )

    result = scan_repo(tmp_path)
    paths_methods = [(route.path, route.method) for route in result.routes]

    # Each framework's bare "/ping" GET route must produce the same canonical
    # (path, method) pair, regardless of source language.
    assert ("/ping", "GET") in paths_methods
    assert paths_methods.count(("/ping", "GET")) >= 3

    # Every emitted method is uppercase; every path is normalized.
    for route in result.routes:
        assert route.method == route.method.upper(), f"Lowercase method: {route.method!r}"
        assert route.path.startswith("/"), f"Path missing leading slash: {route.path!r}"


def test_scan_repo_detects_deeply_nested_express_app_use(tmp_path: Path) -> None:
    """Three-level deep ``app.use`` nesting produces the fully-prefixed route path."""
    app_file = tmp_path / "server.js"
    app_file.write_text(
        """
const express = require("express");
const app = express();
const v1 = express.Router();
const orgs = express.Router();
const orgsUsers = express.Router();

app.use("/api", v1);
v1.use("/v1", orgs);
orgs.use("/orgs/:orgId", orgsUsers);

app.get("/health", (_req, res) => res.send("ok"));
orgsUsers.get("/members", (_req, res) => res.send("members"));
orgsUsers.post("/invite", (_req, res) => res.send("invite"));
""",
        encoding="utf-8",
    )

    result = scan_repo(tmp_path)
    pairs = {(route.path, route.method) for route in result.routes}

    assert ("/health", "GET") in pairs
    assert ("/api/v1/orgs/:orgId/members", "GET") in pairs
    assert ("/api/v1/orgs/:orgId/invite", "POST") in pairs


# ---------------------------------------------------------------------------
# #2: deeper datastore + auth signal detection.
# ---------------------------------------------------------------------------


def _scan_source(tmp_path: Path, source: str, name: str = "app.py") -> ScanResult:
    (tmp_path / name).write_text(source, encoding="utf-8")
    return scan_repo(tmp_path)


def test_sqlalchemy_sessionmaker_declarative_base_are_detected_as_sql(tmp_path: Path) -> None:
    scan = _scan_source(
        tmp_path,
        """
from sqlalchemy.orm import sessionmaker, declarative_base

Base = declarative_base()
SessionLocal = sessionmaker(bind=engine)
""",
    )
    kinds = {(hint.kind, hint.file) for hint in scan.databases}
    assert ("sql", "app.py") in kinds


def test_sqlalchemy_async_engine_and_session_are_detected(tmp_path: Path) -> None:
    scan = _scan_source(
        tmp_path,
        """
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession

engine = create_async_engine("postgresql+asyncpg://user@localhost/db")
async_session = AsyncSession(engine)
""",
    )
    kinds = {hint.kind for hint in scan.databases}
    assert "sql" in kinds


def test_raw_sql_execute_with_sql_verb_string_is_detected(tmp_path: Path) -> None:
    scan = _scan_source(
        tmp_path,
        """
import sqlite3
db = sqlite3.connect("orders.db")
cursor = db.cursor()
cursor.execute("SELECT id, sku FROM orders WHERE customer_id = ?", (cid,))
""",
    )
    kinds = {hint.kind for hint in scan.databases}
    # Both sqlite (from connect) and sql (from raw execute) should fire
    assert "sqlite" in kinds
    assert "sql" in kinds


def test_pymongo_and_asyncio_motor_are_detected_as_mongodb(tmp_path: Path) -> None:
    scan = _scan_source(
        tmp_path,
        """
from pymongo import MongoClient
from motor.motor_asyncio import AsyncIOMotorClient

client = pymongo.MongoClient("mongodb://localhost:27017")
async_client = AsyncIOMotorClient("mongodb://localhost:27017")
""",
    )
    kinds = {hint.kind for hint in scan.databases}
    assert "mongodb" in kinds


def test_redis_from_url_is_detected(tmp_path: Path) -> None:
    scan = _scan_source(
        tmp_path,
        """
import redis
client = redis.from_url("redis://localhost:6379/0")
""",
    )
    assert any(h.kind == "redis" for h in scan.databases)


# --- Auth detection improvements ------------------------------------------


def test_jwt_decode_call_produces_jwt_auth_hint(tmp_path: Path) -> None:
    scan = _scan_source(
        tmp_path,
        """
import jwt

def get_user(token):
    payload = jwt.decode(token, key, algorithms=["HS256"])
    return payload
""",
    )
    hints = {(h.hint, h.file) for h in scan.auth_hints}
    assert ("jwt", "app.py") in hints


def test_python_authorization_header_access_produces_authorization_hint(tmp_path: Path) -> None:
    scan = _scan_source(
        tmp_path,
        """
def get_user(request):
    header = request.headers.get("authorization")
    return header
""",
    )
    hints = {h.hint for h in scan.auth_hints}
    assert "authorization" in hints


def test_js_authorization_header_access_produces_authorization_hint(tmp_path: Path) -> None:
    scan = _scan_source(
        tmp_path,
        """
app.get("/me", (req, res) => {
  const header = req.headers["authorization"];
  res.json({ header });
});
""",
        name="app.js",
    )
    hints = {h.hint for h in scan.auth_hints}
    assert "authorization" in hints


def test_common_middleware_names_are_recognized(tmp_path: Path) -> None:
    scan = _scan_source(
        tmp_path,
        """
app.get("/admin", requireAuth(), isAuthenticated(), (req, res) => res.send("ok"));
""",
        name="app.js",
    )
    hints = {h.hint for h in scan.auth_hints}
    assert "auth_middleware" in hints


def test_express_session_middleware_and_req_session_produce_session_hints(tmp_path: Path) -> None:
    scan = _scan_source(
        tmp_path,
        """
const session = require("express-session");
app.use(session({ secret: "s" }));
app.get("/me", (req, res) => res.json(req.session.user));
""",
        name="app.js",
    )
    hints = {h.hint for h in scan.auth_hints}
    assert "session_middleware" in hints
    assert "session_state" in hints


def test_naked_noisy_keywords_no_longer_produce_auth_hints(tmp_path: Path) -> None:
    """The bare words `session`, `password`, `token`, `mfa`, `bearer` used to
    fire everywhere via AUTH_KEYWORDS; #2 removed them from that list to
    fix the file-scoped-noise problem documented in Bluesky FINDINGS §55.
    Only specific compound patterns (session_middleware, session_state,
    password_flow, etc.) should fire now."""
    scan = _scan_source(
        tmp_path,
        """
# Words used in non-auth context — should NOT emit bare auth hints.
def parse(session_name, password_field, token_length, bearer_kind, mfa_days):
    return f"{session_name}/{password_field}/{token_length}/{bearer_kind}/{mfa_days}"
""",
    )
    hints = {h.hint for h in scan.auth_hints}
    for noisy in ("session", "password", "token", "mfa", "bearer"):
        assert noisy not in hints, (
            f"{noisy!r} should not be a bare AUTH_KEYWORD anymore (was noisy)"
        )


def test_password_flow_compound_patterns_still_fire(tmp_path: Path) -> None:
    scan = _scan_source(
        tmp_path,
        """
def register(user, pw):
    user.password_hash = bcrypt.hash(pw, salt)
    return user
""",
    )
    hints = {h.hint for h in scan.auth_hints}
    assert "password_flow" in hints


def test_mfa_compound_patterns_still_fire(tmp_path: Path) -> None:
    scan = _scan_source(
        tmp_path,
        """
def sensitive_action(user):
    if user.mfa_required and totp_verify(user.otp):
        return True
    return False
""",
    )
    hints = {h.hint for h in scan.auth_hints}
    assert "mfa" in hints


def test_auth_hint_dedup_at_kind_file_level(tmp_path: Path) -> None:
    """Same auth hint kind + file should appear only once even if the
    pattern matches multiple times in the file."""
    scan = _scan_source(
        tmp_path,
        """
import jwt
a = jwt.decode(t1, k)
b = jwt.decode(t2, k)
c = jwt.encode({}, k)
""",
    )
    hints = [h for h in scan.auth_hints if h.hint == "jwt" and h.file == "app.py"]
    assert len(hints) == 1


# ---------------------------------------------------------------------------
# #39: hard-coded secret detection.
# ---------------------------------------------------------------------------


def _has_kind(scan, kind: str) -> bool:
    return any(h.kind == kind for h in scan.secret_hints)


def _hint_of_kind(scan, kind: str):
    return next(h for h in scan.secret_hints if h.kind == kind)


# Tokens below are assembled at runtime from prefix + body fragments so
# the *source file* checked into git never contains a full-length match
# for GitHub's own push-protection secret patterns. The fixture files
# written to tmp_path receive the concatenated form, so the scanner sees
# a real pattern to detect.
_AWS_KEY = "AKIA" + "IOSFODNN7" + "EXAMPLE"
_GH_PAT = "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz0123456789"
_SLACK = "xox" + "b-" + "123456789012-987654321098-abcdefghijklmnopqrstuvwx"
_STRIPE = "sk_" + "live_" + "51ABcdefghijklmnopqrstuvwx"
_SENDGRID = "SG" + ".aaaaaaaaaaaaaaaaaaaaaa." + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
_GOOGLE = "AI" + "za" + "SyDDSb-abcdefghijklmnopqrstuvwx1234"  # 4 + 35 total
_ANTHROPIC = "sk-" + "ant-" + "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ"
_JWT = (
    "ey" + "JhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    "." + "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
    "." + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


def test_hardcoded_aws_access_key_detected(tmp_path: Path) -> None:
    scan = _scan_source(
        tmp_path,
        f'const key = "{_AWS_KEY}";\n',
        name="app.js",
    )
    assert _has_kind(scan, "aws_access_key")


def test_hardcoded_github_pat_detected_and_redacted(tmp_path: Path) -> None:
    scan = _scan_source(
        tmp_path,
        f'TOKEN = "{_GH_PAT}"\n',
    )
    hint = _hint_of_kind(scan, "github_pat")
    # Redaction — full literal must NOT appear in name; head/tail preserved.
    assert _GH_PAT not in hint.name
    assert hint.name.startswith("gh" + "p_")
    assert hint.name.endswith("6789")
    assert "…" in hint.name


def test_hardcoded_slack_bot_token_detected(tmp_path: Path) -> None:
    scan = _scan_source(tmp_path, f'slack = "{_SLACK}"\n')
    assert _has_kind(scan, "slack_token")


def test_hardcoded_stripe_live_key_detected(tmp_path: Path) -> None:
    scan = _scan_source(tmp_path, f'STRIPE = "{_STRIPE}"\n')
    assert _has_kind(scan, "stripe_key")


def test_hardcoded_sendgrid_key_detected(tmp_path: Path) -> None:
    scan = _scan_source(tmp_path, f'SG = "{_SENDGRID}"\n')
    assert _has_kind(scan, "sendgrid_key")


def test_hardcoded_google_api_key_detected(tmp_path: Path) -> None:
    scan = _scan_source(
        tmp_path,
        f'const G = "{_GOOGLE}"\n',
        name="app.js",
    )
    assert _has_kind(scan, "google_api_key")


def test_hardcoded_anthropic_key_detected(tmp_path: Path) -> None:
    scan = _scan_source(tmp_path, f'KEY = "{_ANTHROPIC}"\n')
    assert _has_kind(scan, "anthropic_key")


def test_hardcoded_pem_private_key_block_detected(tmp_path: Path) -> None:
    # Assemble the PEM header from fragments so the checked-in test
    # source never contains a full BEGIN/END block that a secret
    # scanner might flag.
    begin = "-----" + "BEGIN " + "RSA PRIVATE KEY" + "-----"
    end = "-----" + "END " + "RSA PRIVATE KEY" + "-----"
    body = "MIIEpAIBAAKCAQEAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    scan = _scan_source(tmp_path, f"PRIVATE_KEY = '''{begin}\n{body}\n{end}'''\n")
    assert _has_kind(scan, "pem_private_key")


def test_hardcoded_jwt_detected(tmp_path: Path) -> None:
    # Real-ish JWT: {"alg":"HS256","typ":"JWT"} + payload + sig.
    scan = _scan_source(tmp_path, f'const token = "{_JWT}";\n', name="app.js")
    assert _has_kind(scan, "jwt")


def test_shape_alone_without_valid_jwt_header_is_not_flagged(tmp_path: Path) -> None:
    """Three dot-separated base64-ish segments where the header doesn't
    decode to a JSON `{"alg":...}` object should NOT fire jwt."""
    bogus = "ey" + "Jzb21ldGhpbmdxxxxx." + "eyJlbHNlxxxxx." + "aWxsZWdhbHBhcnR4xxxxx"
    scan = _scan_source(tmp_path, f'x = "{bogus}"\n')
    assert not _has_kind(scan, "jwt")


def test_high_entropy_string_flagged_when_no_provider_matches(tmp_path: Path) -> None:
    # 40 chars, random-looking, high entropy — no provider prefix.
    body = "aB9x2z8Kq7Vn3W6yF1jH5tR4mE0uC" + "8pI6oXsL7dS"
    scan = _scan_source(tmp_path, f'secret = "{body}"\n')
    assert _has_kind(scan, "high_entropy")


def test_hex_hash_does_not_trip_entropy_fallback(tmp_path: Path) -> None:
    """A 40-char hex string looks high-entropy in Shannon terms but is
    almost always a commit SHA / checksum, not a secret."""
    scan = _scan_source(
        tmp_path,
        'sha = "0123456789abcdef0123456789abcdef01234567"\n',
    )
    assert not _has_kind(scan, "high_entropy")


def test_url_does_not_trip_entropy_fallback(tmp_path: Path) -> None:
    scan = _scan_source(
        tmp_path,
        'homepage = "https://cdn.example.com/vendor/xyz/abcdefghij/config.json"\n',
    )
    assert not _has_kind(scan, "high_entropy")


def test_env_reference_gets_kind_env_reference(tmp_path: Path) -> None:
    """Regression: existing env-referenced secrets keep their kind
    default so downstream code can distinguish them."""
    scan = _scan_source(
        tmp_path,
        'API_KEY = os.getenv("API_KEY")\n',
    )
    env_hints = [h for h in scan.secret_hints if h.kind == "env_reference"]
    assert env_hints
    assert not any(h.kind == "high_entropy" for h in scan.secret_hints)


def test_hardcoded_secret_appears_only_once_even_when_repeated(tmp_path: Path) -> None:
    scan = _scan_source(
        tmp_path,
        f"""
KEY = "{_AWS_KEY}"
def refresh():
    return "{_AWS_KEY}"
""",
    )
    aws_hints = [h for h in scan.secret_hints if h.kind == "aws_access_key"]
    # Two literal occurrences on distinct lines — both count (they're
    # separate exposures). But the same line must not double-emit.
    lines = [h.line for h in aws_hints]
    assert len(lines) == len(set(lines))


def test_base64_alphabet_constant_not_flagged_as_secret(tmp_path: Path) -> None:
    """A base64/hex alphabet constant is high-entropy but not a secret (#96)."""
    (tmp_path / "sourcemap.js").write_text(
        'var base64Digits = '
        '"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";\n',
        encoding="utf-8",
    )
    result = scan_repo(tmp_path)
    assert not [s for s in result.secret_hints if s.kind == "high_entropy"]


def test_real_high_entropy_secret_still_flagged(tmp_path: Path) -> None:
    (tmp_path / "cfg.js").write_text(
        'const apiToken = "s3cr3tR4nd0mK3yZ9xQvB2mNw8LpT4hJ7";\n',
        encoding="utf-8",
    )
    result = scan_repo(tmp_path)
    assert any(s.kind == "high_entropy" for s in result.secret_hints)


def test_route_extraction_ignores_non_router_method_calls(tmp_path: Path) -> None:
    """`x.get("s")` on a non-router receiver with a non-URL string is not a
    route — `headers.delete`, `params.get`, config lookups (#99)."""
    (tmp_path / "util.js").write_text(
        "const ct = headers.delete('content-type')\n"
        "const uri = params.get('request_uri')\n"
        "const fav = settings.get('application.favicon')\n"
        "const cached = cache.get('user:42')\n",
        encoding="utf-8",
    )
    result = scan_repo(tmp_path)
    assert result.routes == []


def test_route_extraction_keeps_real_routes(tmp_path: Path) -> None:
    (tmp_path / "api.js").write_text(
        "const app = express()\n"
        "app.get('/users', listUsers)\n"          # leading slash
        "router.post('/orders', createOrder)\n"   # router receiver
        "userRouter.delete('/u/:id', removeUser)\n"  # *Router receiver
        "app.all('*', catchAll)\n",               # wildcard
        encoding="utf-8",
    )
    result = scan_repo(tmp_path)
    got = {(r.method, r.path) for r in result.routes}
    assert ("GET", "/users") in got
    assert ("POST", "/orders") in got
    assert ("DELETE", "/u/:id") in got
    assert ("ANY", "/*") in got
