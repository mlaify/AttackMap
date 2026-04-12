# Recon-To-Analysis Translation Layer

## Purpose

Introduce a formal, explicit stage that converts low-level recon output (`ScanResult`) into higher-level security analysis artifacts:

- `AttackSurface`
- `Finding`
- `AttackPath`

This separates analyzer execution (signal extraction) from analysis synthesis (security interpretation).

## Scope (Incremental v1)

- Added `src/attackmap/recon_to_analysis.py`.
- Translation uses only existing recon signals:
  - `routes`
  - `external_calls`
  - `databases`
  - `auth_hints`
  - `secret_hints`
- No plugin/analyzer contract redesign.
- No behavior expansion in analyzers.
- Translation explicitly accounts for temporarily overloaded `auth_hints`.

## API

- `to_attack_surface(scan: ScanResult) -> list[AttackSurface]`
- `to_findings(scan: ScanResult, attack_surfaces: list[AttackSurface] | None = None) -> list[Finding]`
- `to_attack_paths(scan: ScanResult) -> list[AttackPath]`
- `translate_recon(scan: ScanResult) -> AnalysisOutputs`

`AnalysisOutputs` is a small immutable dataclass bundling the three outputs.

## Heuristic Characteristics

- Deterministic: no randomness, no external calls.
- Conservative: empty/weak scans yield a low-confidence, low-severity fallback finding and no forced attack path.
- Explainable: translation relies on existing signal-driven logic in `analyzer.py` and `threat_model.py`.

## Handling Overloaded `auth_hints`

Because `auth_hints` currently carries both auth and non-auth concepts, translation applies a split:

- For `AttackSurface` and `Finding` generation:
  - use an auth-filtered ScanResult view
  - retain only likely auth-related hint values
  - treat service/protocol/edge metadata as non-auth for conservative risk language
- For `AttackPath` generation:
  - use full raw hints
  - preserve chain-linking signals (for example `service_name:*`, `edge:*`) during migration

This avoids over-crediting auth controls in findings while preserving useful chain reasoning.

## Integration

- CLI now uses this translation stage:
  - analyze repository -> `ScanResult`
  - `translate_recon(scan)` -> surfaces/findings/paths
  - reporting remains unchanged

This preserves current CLI behavior while making the recon-to-analysis boundary explicit and testable.

## Tests Added

- `tests/test_recon_to_analysis.py`
  - end-to-end translation emits all three artifact types for realistic recon signals
  - helper functions are consistent with `translate_recon`
  - empty scan behavior remains conservative

## Future Follow-Ups

- Move additional scoring/prioritization knobs into this layer as explicit policy inputs.
- Add richer trace metadata from recon signal -> surface/finding/path for explainability.
- Keep analyzer outputs strictly structured while evolving this translation stage independently.
