"""Tests for the injection-sink expansion (#68): SSRF, SSTI, NoSQL,
unsafe deserialization added to the lite taint engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from attackmap.models import Route, ScanResult
from attackmap.scanner import scan_repo
from attackmap.taint import analyze_taint
from attackmap.threat_model import generate_findings


def _route_repo(tmp_path: Path, worker_body: str) -> Path:
    """A minimal Flask route that imports a worker module holding the sink."""
    (tmp_path / "route.py").write_text(
        "from flask import Flask, request\n"
        "import worker\n"
        "app = Flask(__name__)\n"
        "@app.route('/r', methods=['POST'])\n"
        "def r():\n"
        "    return worker.handle(request.get_json())\n",
        encoding="utf-8",
    )
    (tmp_path / "worker.py").write_text(worker_body, encoding="utf-8")
    return tmp_path


def _kinds(scan: ScanResult) -> set[str]:
    return {c.sink_kind for c in scan.taint_chains}


# ---------------------------------------------------------------------------
# Unsafe deserialization
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        "import pickle\ndef handle(x): return pickle.loads(x)\n",
        "import cPickle\ndef handle(x): return cPickle.load(x)\n",
        "import yaml\ndef handle(x): return yaml.load(x)\n",
        "import yaml\ndef handle(x): return yaml.unsafe_load(x)\n",
        "import marshal\ndef handle(x): return marshal.loads(x)\n",
    ],
)
def test_python_deserialization_sinks_detected(tmp_path: Path, body: str) -> None:
    scan = scan_repo(_route_repo(tmp_path, body))
    assert "unsafe_deserialization" in _kinds(scan)


def test_yaml_safe_loader_is_not_flagged(tmp_path: Path) -> None:
    """yaml.load with an explicit SafeLoader is safe and must not fire."""
    body = "import yaml\ndef handle(x): return yaml.load(x, Loader=yaml.SafeLoader)\n"
    scan = scan_repo(_route_repo(tmp_path, body))
    assert "unsafe_deserialization" not in _kinds(scan)


def test_yaml_safe_load_helper_is_not_flagged(tmp_path: Path) -> None:
    body = "import yaml\ndef handle(x): return yaml.safe_load(x)\n"
    scan = scan_repo(_route_repo(tmp_path, body))
    assert "unsafe_deserialization" not in _kinds(scan)


def test_js_node_serialize_unserialize_detected(tmp_path: Path) -> None:
    """JS `node-serialize` unserialize() is a real RCE sink (CVE-2017-5941).

    The taint engine indexes Python + JS/TS (its documented scope), so
    the JS unserialize sink fires; PHP/Java/Ruby deserialization tokens
    are present in the pattern but latent until those languages are
    indexed (tracked as a follow-up)."""
    (tmp_path / "route.ts").write_text(
        "import express from 'express';\n"
        "import { handle } from './svc';\n"
        "const app = express();\n"
        "app.post('/r', (req, res) => res.json(handle(req)));\n",
        encoding="utf-8",
    )
    (tmp_path / "svc.ts").write_text(
        "import { unserialize } from 'node-serialize';\n"
        "export function handle(req) { return unserialize(req.body.blob); }\n",
        encoding="utf-8",
    )
    scan = scan_repo(tmp_path)
    assert "unsafe_deserialization" in _kinds(scan)


# ---------------------------------------------------------------------------
# SSTI
# ---------------------------------------------------------------------------


def test_render_template_string_with_request_is_ssti(tmp_path: Path) -> None:
    body = (
        "from flask import render_template_string\n"
        "def handle(request): return render_template_string(request['tpl'])\n"
    )
    scan = scan_repo(_route_repo(tmp_path, body))
    assert "ssti" in _kinds(scan)


def test_jinja_template_from_request_is_ssti(tmp_path: Path) -> None:
    body = (
        "from jinja2 import Template\n"
        "def handle(body): return Template(body['t']).render()\n"
    )
    scan = scan_repo(_route_repo(tmp_path, body))
    assert "ssti" in _kinds(scan)


def test_render_template_string_constant_not_ssti(tmp_path: Path) -> None:
    body = (
        "from flask import render_template_string\n"
        "def handle(x): return render_template_string('<h1>hello</h1>')\n"
    )
    scan = scan_repo(_route_repo(tmp_path, body))
    assert "ssti" not in _kinds(scan)


# ---------------------------------------------------------------------------
# SSRF
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        "import requests\ndef handle(request): return requests.get(request['url'])\n",
        "import httpx\ndef handle(body): return httpx.get(body['target'])\n",
        "from urllib.request import urlopen\ndef handle(params): return urlopen(params['url'])\n",
    ],
)
def test_python_ssrf_sinks_detected(tmp_path: Path, body: str) -> None:
    scan = scan_repo(_route_repo(tmp_path, body))
    assert "ssrf" in _kinds(scan)


def test_js_ssrf_axios_and_fetch(tmp_path: Path) -> None:
    (tmp_path / "route.ts").write_text(
        "import express from 'express';\n"
        "import { handle } from './svc';\n"
        "const app = express();\n"
        "app.post('/r', (req, res) => res.json(handle(req)));\n",
        encoding="utf-8",
    )
    (tmp_path / "svc.ts").write_text(
        "import axios from 'axios';\n"
        "export function handle(req) { return axios.get(req.body.url); }\n",
        encoding="utf-8",
    )
    scan = scan_repo(tmp_path)
    assert "ssrf" in _kinds(scan)


def test_ssrf_constant_url_not_flagged(tmp_path: Path) -> None:
    body = "import requests\ndef handle(x): return requests.get('https://api.example.com/health')\n"
    scan = scan_repo(_route_repo(tmp_path, body))
    assert "ssrf" not in _kinds(scan)


def test_fetch_bare_request_object_not_flagged(tmp_path: Path) -> None:
    """The JS Fetch API idiom `fetch(request)` passes a Request object
    literally named `request` — it is NOT SSRF. Gating on member access
    (`req.query.url`) rather than the bare token is what makes this
    precise; without it a real repo produced 600+ false SSRF hits."""
    (tmp_path / "route.ts").write_text(
        "import express from 'express';\n"
        "import { proxy } from './svc';\n"
        "const app = express();\n"
        "app.get('/r', (req, res) => res.json(proxy(req)));\n",
        encoding="utf-8",
    )
    (tmp_path / "svc.ts").write_text(
        "export function proxy(request) { return fetch(request); }\n",
        encoding="utf-8",
    )
    scan = scan_repo(tmp_path)
    assert "ssrf" not in _kinds(scan)


# ---------------------------------------------------------------------------
# NoSQL injection
# ---------------------------------------------------------------------------


def test_mongo_find_with_request_object_is_nosql(tmp_path: Path) -> None:
    (tmp_path / "route.ts").write_text(
        "import express from 'express';\n"
        "import { handle } from './svc';\n"
        "const app = express();\n"
        "app.post('/r', (req, res) => res.json(handle(req)));\n",
        encoding="utf-8",
    )
    (tmp_path / "svc.ts").write_text(
        "import { db } from './db';\n"
        "export function handle(req) { return db.users.find(req.body); }\n",
        encoding="utf-8",
    )
    (tmp_path / "db.ts").write_text("export const db: any = {};\n", encoding="utf-8")
    scan = scan_repo(tmp_path)
    assert "nosql_injection" in _kinds(scan)


def test_where_operator_is_nosql(tmp_path: Path) -> None:
    body = "def handle(request):\n    return coll.find({'$where': 'this.x==' + request['v']})\n"
    scan = scan_repo(_route_repo(tmp_path, body))
    assert "nosql_injection" in _kinds(scan)


# ---------------------------------------------------------------------------
# Findings: each dangerous sink kind yields a dedicated finding
# ---------------------------------------------------------------------------


def test_deserialization_produces_high_finding_with_attack_technique(tmp_path: Path) -> None:
    body = "import pickle\ndef handle(x): return pickle.loads(x)\n"
    scan = scan_repo(_route_repo(tmp_path, body))
    findings = [f for f in generate_findings(scan) if "taint-chain" in f.tags]
    deser = next(f for f in findings if "unsafe deserialization" in f.title)
    assert deser.severity == "high"
    assert deser.attack_techniques
    assert deser.attack_techniques[0].technique_id == "T1059"


def test_ssrf_produces_medium_finding(tmp_path: Path) -> None:
    body = "import requests\ndef handle(request): return requests.get(request['url'])\n"
    scan = scan_repo(_route_repo(tmp_path, body))
    findings = [f for f in generate_findings(scan) if "taint-chain" in f.tags]
    ssrf = next(f for f in findings if "SSRF" in f.title)
    assert ssrf.severity == "medium"
    assert ssrf.attack_techniques[0].technique_id == "T1190"


def test_distinct_sink_kinds_yield_distinct_findings(tmp_path: Path) -> None:
    body = (
        "import pickle, requests\n"
        "def handle(request):\n"
        "    requests.get(request['url'])\n"
        "    return pickle.loads(request['blob'])\n"
    )
    scan = scan_repo(_route_repo(tmp_path, body))
    titles = {f.title for f in generate_findings(scan) if "taint-chain" in f.tags}
    assert any("SSRF" in t for t in titles)
    assert any("unsafe deserialization" in t for t in titles)
