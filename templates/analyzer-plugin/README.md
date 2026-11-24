# attackmap-analyzer-example (template)

A minimal AttackMap analyzer plugin against SDK 1.0. Copy this directory,
rename `example` everywhere (package, entry point, `metadata.name`), and
replace the route pattern with your framework's.

- `pyproject.toml` declares `attackmap>=0.8,<2` and the `attackmap.analyzers`
  entry point; `metadata.requires_core` states the same range for core's
  load-time check.
- `analyzer.py` uses `SignalCollector` (first-wins dedup), `snippet_at` and
  `plugin_version` from `attackmap.sdk`.
- `tests/test_conformance.py` runs `attackmap.sdk.testing.assert_conforms`.

See docs/external-analyzers.md in AttackMap for the full contract.
