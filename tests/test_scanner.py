from pathlib import Path

from attackmap.scanner import scan_repo


def test_scan_repo_detects_fastapi_routes_and_secrets(tmp_path: Path) -> None:
    app_file = tmp_path / "app.py"
    app_file.write_text(
        '''
from fastapi import APIRouter, FastAPI
import os
import requests

app = FastAPI()
router = APIRouter(prefix="/api")

@app.post("/webhook/stripe")
def stripe_hook():
    secret = os.getenv("STRIPE_SECRET_KEY")
    requests.post("https://api.example.com/process")
    return {"ok": True}

@router.api_route("/items", methods=["GET", "PATCH"])
def items():
    return {"ok": True}
''',
        encoding="utf-8",
    )

    result = scan_repo(tmp_path)

    assert result.files_scanned == 1
    assert any(route.path == "/webhook/stripe" for route in result.routes)
    assert any(route.path == "/api/items" and route.method == "GET" for route in result.routes)
    assert any(route.path == "/api/items" and route.method == "PATCH" for route in result.routes)
    assert any(secret.name == "STRIPE_SECRET_KEY" for secret in result.secret_hints)
    assert any(call.target == "https://api.example.com/process" for call in result.external_calls)


def test_scan_repo_detects_flask_blueprint_routes(tmp_path: Path) -> None:
    app_file = tmp_path / "app.py"
    app_file.write_text(
        '''
from flask import Blueprint, Flask

app = Flask(__name__)
admin = Blueprint("admin", __name__, url_prefix="/admin")

@app.route("/login", methods=["POST"])
def login():
    return {"ok": True}

@admin.route("/users", methods=["GET", "DELETE"])
def manage_users():
    return {"ok": True}
''',
        encoding="utf-8",
    )

    result = scan_repo(tmp_path)

    assert any(route.path == "/login" and route.method == "POST" for route in result.routes)
    assert any(route.path == "/admin/users" and route.method == "GET" for route in result.routes)
    assert any(route.path == "/admin/users" and route.method == "DELETE" for route in result.routes)


def test_scan_repo_detects_express_mounted_and_chained_routes(tmp_path: Path) -> None:
    app_file = tmp_path / "server.js"
    app_file.write_text(
        """
const express = require("express");
const app = express();
const router = express.Router();

app.use("/api/v1", router);
app.get("/health", (_req, res) => res.send("ok"));
router.route("/users")
  .get((_req, res) => res.send("users"))
  .post((_req, res) => res.send("created"));
router.delete("/users/:id", (_req, res) => res.send("deleted"));
""",
        encoding="utf-8",
    )

    result = scan_repo(tmp_path)

    assert any(route.path == "/health" and route.method == "GET" for route in result.routes)
    assert any(route.path == "/api/v1/users" and route.method == "GET" for route in result.routes)
    assert any(route.path == "/api/v1/users" and route.method == "POST" for route in result.routes)
    assert any(route.path == "/api/v1/users/:id" and route.method == "DELETE" for route in result.routes)
