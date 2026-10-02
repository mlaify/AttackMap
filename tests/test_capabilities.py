"""`attackmap capabilities` gives front-ends a structured feature list."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from attackmap import __version__
from attackmap.cli import app
from attackmap.progress import PROGRESS_PROTOCOL_VERSION


def test_capabilities_json() -> None:
    result = CliRunner().invoke(app, ["capabilities"])
    assert result.exit_code == 0, result.output
    caps = json.loads(result.output)
    assert caps["schema"] == 1
    assert caps["version"] == __version__
    assert {"analyze", "modules", "capabilities", "suggest"} <= set(caps["commands"])
    options = set(caps["analyze"]["options"])
    for flag in ("--progress-format", "--recall", "--triage", "--verify-votes", "--no-suppress",
                 "--llm-provider", "--llm-speed", "--format", "--strict-analyzers", "--no-progress"):
        assert flag in options, flag
    assert caps["analyze"]["multi_repo"] is True
    assert caps["progress_protocol"] == PROGRESS_PROTOCOL_VERSION
