"""Tests for the config-file analyzer (#43)."""

from __future__ import annotations

from pathlib import Path

from attackmap.analyzers import BuiltinConfigAnalyzer, analyze_repository
from attackmap.config_scanner import scan_config_repo, should_scan_config_file


# ---------------------------------------------------------------------------
# File selection
# ---------------------------------------------------------------------------


def test_should_scan_covers_yaml_toml_json_ini_env(tmp_path: Path) -> None:
    for name in ("app.yaml", "app.yml", "app.toml", "app.json", "app.ini", "app.cfg", ".env"):
        assert should_scan_config_file(tmp_path / name), f"expected {name} to be scannable"


def test_should_scan_excludes_lockfiles_and_editor_configs(tmp_path: Path) -> None:
    for name in (
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "cargo.lock",
        "tsconfig.json",
        ".eslintrc.json",
        "package.json",
    ):
        assert not should_scan_config_file(tmp_path / name), f"expected {name} to be excluded"


# ---------------------------------------------------------------------------
# DB URL extraction
# ---------------------------------------------------------------------------


def test_db_url_in_yaml_emits_database_hint(tmp_path: Path) -> None:
    (tmp_path / "config.yaml").write_text(
        "database:\n  url: postgresql://user:pass@localhost:5432/mydb\n",
        encoding="utf-8",
    )
    result = scan_config_repo(tmp_path)
    kinds = {(d.kind, d.file) for d in result.databases}
    assert ("postgresql", "config.yaml") in kinds


def test_db_url_password_becomes_hardcoded_secret_hint(tmp_path: Path) -> None:
    """The acceptance criterion — `postgresql://user:pass@…` produces
    both a DatabaseHint and a SecretHint for the embedded password."""
    (tmp_path / "config.yaml").write_text(
        "database:\n  url: postgresql://user:s3cretpass@localhost:5432/mydb\n",
        encoding="utf-8",
    )
    result = scan_config_repo(tmp_path)
    assert any(d.kind == "postgresql" for d in result.databases)
    secrets = [s for s in result.secret_hints if s.kind == "postgresql_url_password"]
    assert len(secrets) == 1
    # Redacted — full password must not leak into the hint name.
    assert "s3cretpass" not in secrets[0].name
    assert "…" in secrets[0].name


def test_db_url_with_placeholder_password_does_not_fire_secret_hint(tmp_path: Path) -> None:
    (tmp_path / "config.yaml").write_text(
        "database:\n  url: postgresql://user:changeme@localhost:5432/mydb\n",
        encoding="utf-8",
    )
    result = scan_config_repo(tmp_path)
    # DB kind still fires — the URL shape is real.
    assert any(d.kind == "postgresql" for d in result.databases)
    # Password is a placeholder — no secret hint.
    assert not any(s.kind == "postgresql_url_password" for s in result.secret_hints)


def test_multiple_db_schemes_each_produce_a_hint(tmp_path: Path) -> None:
    (tmp_path / "config.toml").write_text(
        """
[database]
primary = "postgresql://user:pass@db-primary:5432/app"
cache = "redis://cache-host:6379/0"
docs = "mongodb://user:pass@mongo:27017/docs"
""",
        encoding="utf-8",
    )
    result = scan_config_repo(tmp_path)
    kinds = {d.kind for d in result.databases}
    assert kinds == {"postgresql", "redis", "mongodb"}


# ---------------------------------------------------------------------------
# HTTP target extraction
# ---------------------------------------------------------------------------


def test_service_endpoint_url_becomes_external_call(tmp_path: Path) -> None:
    (tmp_path / "settings.yaml").write_text(
        "integrations:\n  webhook_target: https://internal-billing.example-corp.io/reconcile\n",
        encoding="utf-8",
    )
    result = scan_config_repo(tmp_path)
    assert any("internal-billing.example-corp.io" in c.target for c in result.external_calls)


def test_common_non_target_hosts_are_skipped(tmp_path: Path) -> None:
    """localhost/example.com/github.com/CDNs are metadata, not real
    outbound calls — don't spam ExternalCall with them."""
    (tmp_path / "package.info.yaml").write_text(
        """
homepage: https://github.com/mlaify/AttackMap
repository: https://github.com/mlaify/AttackMap.git
docs: https://example.com/docs
local: http://localhost:3000
""",
        encoding="utf-8",
    )
    result = scan_config_repo(tmp_path)
    assert result.external_calls == []


# ---------------------------------------------------------------------------
# Secret KV extraction
# ---------------------------------------------------------------------------


def test_secret_key_value_pair_emits_hint(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(
        "STRIPE_API_KEY=sk_live_thisisalongenoughvalue\n",
        encoding="utf-8",
    )
    result = scan_config_repo(tmp_path)
    # STRIPE_API_KEY should fire both via the config-literal secret KV path
    # AND via the stripe_key hardcoded-secret path — but we're scanning via
    # the config scanner only, so just check the config-literal side.
    kinds = {s.kind for s in result.secret_hints}
    assert "config_literal" in kinds or "stripe_key" in kinds


def test_placeholder_values_do_not_fire_secret_hints(tmp_path: Path) -> None:
    (tmp_path / ".env.example").write_text(
        """
API_KEY=changeme
STRIPE_SECRET=your-secret-here
DB_PASSWORD=<put-your-password-here>
INTERPOLATED=${REAL_KEY}
""",
        encoding="utf-8",
    )
    result = scan_config_repo(tmp_path)
    # `.env.example` is legitimately a secrets template — never a real
    # secret. No config-literal hints should fire.
    assert not any(s.kind == "config_literal" for s in result.secret_hints)


def test_yaml_secret_key_value_pair_emits_hint(tmp_path: Path) -> None:
    (tmp_path / "config.yaml").write_text(
        """
auth:
  api_key: "abcdefghijklmnop"
""",
        encoding="utf-8",
    )
    result = scan_config_repo(tmp_path)
    assert any(s.kind == "config_literal" and "api_key" in s.name for s in result.secret_hints)


def test_json_secret_key_value_pair_emits_hint(tmp_path: Path) -> None:
    (tmp_path / "credentials.json").write_text(
        '{"token": "abcdefghijklmnopqrstuvwxyz"}\n',
        encoding="utf-8",
    )
    result = scan_config_repo(tmp_path)
    assert any(s.kind == "config_literal" and s.name == "token" for s in result.secret_hints)


def test_file_path_values_do_not_fire_secret_hints(tmp_path: Path) -> None:
    (tmp_path / "config.yaml").write_text(
        """
tls:
  privkey: /etc/ssl/private/site.key
  cert: /etc/ssl/certs/site.pem
""",
        encoding="utf-8",
    )
    result = scan_config_repo(tmp_path)
    # These are keyfile *paths*, not the key material. No hint.
    assert not any(s.kind == "config_literal" for s in result.secret_hints)


# ---------------------------------------------------------------------------
# Exclusions
# ---------------------------------------------------------------------------


def test_lockfile_content_is_not_scanned(tmp_path: Path) -> None:
    """A DB URL in a lockfile is registry metadata, not application
    config — don't flag it."""
    (tmp_path / "package-lock.json").write_text(
        '{"dependencies": {"pg": {"resolved": "https://registry.npmjs.org/pg/-/pg-8.11.0.tgz"}}}\n',
        encoding="utf-8",
    )
    result = scan_config_repo(tmp_path)
    assert result.files_scanned == 0


def test_node_modules_directories_are_skipped(tmp_path: Path) -> None:
    vendored = tmp_path / "node_modules" / "some-dep"
    vendored.mkdir(parents=True)
    (vendored / "config.yaml").write_text(
        "database:\n  url: postgresql://user:pass@x/y\n", encoding="utf-8"
    )
    result = scan_config_repo(tmp_path)
    assert result.files_scanned == 0
    assert result.databases == []


# ---------------------------------------------------------------------------
# End-to-end integration with analyze_repository
# ---------------------------------------------------------------------------


def test_builtin_config_analyzer_detects_repos_with_yaml(tmp_path: Path) -> None:
    (tmp_path / "config.yaml").write_text("key: value\n", encoding="utf-8")
    assert BuiltinConfigAnalyzer().detect(tmp_path) is True


def test_builtin_config_analyzer_skips_repos_without_config_files(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    assert BuiltinConfigAnalyzer().detect(tmp_path) is False


def test_analyze_repository_merges_config_signals_with_source_signals(tmp_path: Path) -> None:
    """A repo with a config.yaml carrying a DB URL AND app.py referencing
    the same DB should produce one hint per file — dedup is by (kind, file)
    so different files are separate signals, but same-file matches don't
    double-count."""
    (tmp_path / "config.yaml").write_text(
        "db:\n  url: postgresql://user:pass@host/mydb\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "import psycopg2\nconn = psycopg2.connect('postgresql://user:pass@host/mydb')\n",
        encoding="utf-8",
    )
    result = analyze_repository(tmp_path)
    files_with_pg = {d.file for d in result.databases if d.kind == "postgresql"}
    # Two hints, one per file — each is a distinct piece of evidence.
    assert "config.yaml" in files_with_pg
    assert "app.py" in files_with_pg


def test_analyze_repository_preserves_provenance_on_config_signals(tmp_path: Path) -> None:
    """Provenance from #14 must survive through the config analyzer's
    contribution — every signal should be tagged `config` since that's
    the analyzer name."""
    (tmp_path / "app.yaml").write_text(
        "db:\n  url: postgresql://user:pass@host/mydb\n",
        encoding="utf-8",
    )
    result = analyze_repository(tmp_path)
    config_dbs = [d for d in result.databases if d.file == "app.yaml"]
    assert config_dbs
    assert config_dbs[0].source_analyzer == "config"


# ---------------------------------------------------------------------------
# Large-file / feedback-loop hang regression (config_scanner _line_of O(n^2))
# ---------------------------------------------------------------------------

import attackmap.config_scanner as _cfg
from attackmap.config_scanner import _LineIndex


def test_line_index_matches_naive_line_numbers() -> None:
    content = "a\nbb\n\nccc\nd"
    expected = {0: 1, 1: 1, 2: 2, 4: 2, 5: 3, 6: 4, 9: 4, 10: 5}
    index = _LineIndex(content)
    for offset, line in expected.items():
        assert index.line_of(offset) == line, (offset, index.line_of(offset))
    assert index.line_of(-5) == 1


def test_skips_attackmap_output_dir(tmp_path: Path) -> None:
    # AttackMap writes reports into .attackmap-gui/ inside scanned repos; scanning
    # them back is a feedback loop that hung on the multi-MB report (#gui-hang).
    (tmp_path / "app.json").write_text('{"api": "https://api.real-service.com/v1"}')
    reports = tmp_path / ".attackmap-gui" / "reports"
    reports.mkdir(parents=True)
    (reports / "attackmap-report.json").write_text('{"u": "https://leaked.internal-host.net/x"}')

    files = {c.file for c in scan_config_repo(tmp_path).external_calls}
    assert not any(".attackmap-gui" in f for f in files)
    assert any("app.json" in f for f in files)


def test_skips_oversized_config_file(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(_cfg, "_MAX_CONFIG_BYTES", 200)
    (tmp_path / "big.json").write_text('{"u":"https://api.real-service.com/"}' + " " * 500)
    (tmp_path / "small.json").write_text('{"u":"https://api.real-service.com/"}')

    files = {c.file for c in scan_config_repo(tmp_path).external_calls}
    assert "big.json" not in files
    assert "small.json" in files
