from __future__ import annotations

import json

from typer.testing import CliRunner

from attackmap.cli import app

runner = CliRunner()


def test_modules_json_emits_installed_modules_as_array() -> None:
    result = runner.invoke(app, ["modules", "--json"])
    assert result.exit_code == 0, result.output

    payload = json.loads(result.output)
    assert isinstance(payload, list) and payload, "expected a non-empty JSON array"

    for entry in payload:
        assert set(entry) >= {
            "name",
            "display_name",
            "description",
            "scope",
            "ecosystems",
            "enabled_by_default",
        }
        assert isinstance(entry["name"], str) and entry["name"]
        assert isinstance(entry["ecosystems"], list)
        assert isinstance(entry["enabled_by_default"], bool)

    # The built-in Python web analyzer ships in-tree and runs by default.
    by_name = {e["name"]: e for e in payload}
    assert "python-web" in by_name
    assert by_name["python-web"]["enabled_by_default"] is True


def test_modules_json_is_network_free_and_omits_remote_section() -> None:
    # --json must not print the "module repositories (mlaify GitHub org)" block
    # (that section does network I/O); the output is pure JSON.
    result = runner.invoke(app, ["modules", "--json"])
    assert result.exit_code == 0
    assert "GitHub org" not in result.output
    json.loads(result.output)  # parses cleanly as a whole
