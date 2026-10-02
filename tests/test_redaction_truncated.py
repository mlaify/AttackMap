"""A secret in a snippet cut at its length cap is still masked (0.5.1)."""

from __future__ import annotations

from attackmap.redact import redact_text


def test_unterminated_quoted_secret_is_masked() -> None:
    secret = "p" + "Q7x" * 20  # long, random-looking value
    snippet = f'db_password = "{secret[:40]}…'  # evidence cut mid-value, no closing quote
    out = redact_text(snippet)
    assert secret[:40] not in out
    assert secret[:12] not in out


def test_terminated_value_still_masked_and_reference_kept() -> None:
    assert "hunter2hunter2" not in redact_text('password = "hunter2hunter2"')
    assert redact_text('password = "${DB_PASSWORD}"') == 'password = "${DB_PASSWORD}"'
