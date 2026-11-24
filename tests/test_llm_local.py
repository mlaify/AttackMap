"""Local model provider (#203): OpenAI-compatible server, evidence stays local."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from typer.testing import CliRunner

from attackmap.cli import app
from attackmap.llm_review import LlmReviewError, _run_via_local


class _Handler(BaseHTTPRequestHandler):
    requests: list[dict] = []

    def do_POST(self) -> None:  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).requests.append({"path": self.path, "body": body})
        reply = {
            "model": body["model"],
            "choices": [{"message": {"role": "assistant", "content": "## Review\\nGrounded in finding:1."}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 120, "completion_tokens": 9},
        }
        data = json.dumps(reply).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args) -> None:
        pass


@pytest.fixture
def local_server():
    _Handler.requests = []
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}/v1"
    server.shutdown()


def test_local_chat_completion(local_server: str) -> None:
    result = _run_via_local("sys", "user", model="qwen2.5-coder", max_tokens=100, base_url=local_server)
    assert result.markdown.startswith("## Review") and result.usage == {"input_tokens": 120, "output_tokens": 9}
    [req] = _Handler.requests
    assert req["path"] == "/v1/chat/completions" and req["body"]["messages"][0] == {"role": "system", "content": "sys"}


@pytest.mark.parametrize("url", ["https://api.example.com/v1", "http://8.8.8.8:8000/v1"])
def test_non_local_hosts_are_refused(url: str, monkeypatch) -> None:
    monkeypatch.delenv("ATTACKMAP_LOCAL_LLM_ALLOW_REMOTE", raising=False)
    with pytest.raises(LlmReviewError, match="leave"):
        _run_via_local("s", "u", model="m", max_tokens=10, base_url=url)


def test_model_is_required(monkeypatch) -> None:
    monkeypatch.delenv("ATTACKMAP_LOCAL_LLM_MODEL", raising=False)
    with pytest.raises(LlmReviewError, match="needs a model"):
        _run_via_local("s", "u", model=None, max_tokens=10, base_url="http://127.0.0.1:1/v1")


def test_analyze_llm_with_a_local_model(tmp_path: Path, local_server: str) -> None:
    (tmp_path / "repo").mkdir()
    (tmp_path / "repo" / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n@app.route('/x', methods=['POST'])\ndef x():\n    return 'x'\n")
    result = CliRunner().invoke(app, [
        "analyze", str(tmp_path / "repo"), "-o", str(tmp_path / "out"), "--no-progress",
        "--llm", "--llm-provider", "local", "--llm-model", "qwen2.5-coder", "--llm-base-url", local_server,
    ])
    assert result.exit_code == 0, result.output
    assert len(_Handler.requests) == 1 and _Handler.requests[0]["body"]["model"] == "qwen2.5-coder"
    reviews = list((tmp_path / "out").glob("*review*.md"))
    assert any("Grounded in finding:1." in p.read_text() for p in reviews), [p.name for p in reviews]
