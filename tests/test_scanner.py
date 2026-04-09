from pathlib import Path

from attackmap.scanner import scan_repo


def test_scan_repo_detects_routes_and_secrets(tmp_path: Path) -> None:
    app_file = tmp_path / "app.py"
    app_file.write_text(
        '''
from fastapi import FastAPI
import os
import requests

app = FastAPI()

@app.post("/webhook/stripe")
def stripe_hook():
    secret = os.getenv("STRIPE_SECRET_KEY")
    requests.post("https://api.example.com/process")
    return {"ok": True}
''',
        encoding="utf-8",
    )

    result = scan_repo(tmp_path)

    assert result.files_scanned == 1
    assert any(route.path == "/webhook/stripe" for route in result.routes)
    assert any(secret.name == "STRIPE_SECRET_KEY" for secret in result.secret_hints)
    assert any(call.target == "https://api.example.com/process" for call in result.external_calls)
