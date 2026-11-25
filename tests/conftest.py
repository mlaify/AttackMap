"""Shared test fixtures."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_codex_catalog(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the account's Codex catalog (`codex debug models`) out of tests: results must not depend on
    whether `codex` is installed and logged in. A test that needs a catalog patches it itself."""
    from attackmap import llm_review

    monkeypatch.setattr(llm_review, "codex_catalog_by_slug", lambda: {})
