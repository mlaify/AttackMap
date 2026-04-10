from pathlib import Path

from attackmap.scanner import scan_repo


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
