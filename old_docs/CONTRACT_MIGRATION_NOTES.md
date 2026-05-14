# Contract Migration Notes (Phase 1)

## What changed
Phase 1 introduces shared contract/model modules without changing analyzer behavior.

New shared modules:
- [`src/attackmap/analyzer_contracts.py`](/Volumes/Dev/repos/GitHub/mlaify/attackmap/AttackMap/src/attackmap/analyzer_contracts.py)
  - `AnalyzerResult = ScanResult`
  - `AnalyzerMetadata`
  - `AnalyzerRepositoryModule`
  - `AnalyzerProtocol`
- [`src/attackmap/recon_models.py`](/Volumes/Dev/repos/GitHub/mlaify/attackmap/AttackMap/src/attackmap/recon_models.py)
  - re-exports `Route`, `ExternalCall`, `DatabaseHint`, `AuthHint`, `SecretHint`, `ScanResult`

SDK-style import paths added:
- [`src/attackmap/sdk/contracts.py`](/Volumes/Dev/repos/GitHub/mlaify/attackmap/AttackMap/src/attackmap/sdk/contracts.py)
- [`src/attackmap/sdk/models.py`](/Volumes/Dev/repos/GitHub/mlaify/attackmap/AttackMap/src/attackmap/sdk/models.py)

Core updated to consume shared modules:
- `src/attackmap/analyzers.py` now imports analyzer contracts from `analyzer_contracts`.
- `src/attackmap/scanner.py` now imports recon models from `recon_models`.

## Backward compatibility
- Existing imports from `attackmap.analyzers` continue to work.
  - `AnalyzerMetadata`, `AnalyzerResult`, and `Analyzer` remain available.
  - `Analyzer` is now a compatibility alias to `AnalyzerProtocol`.
- Existing imports from `attackmap.models` continue to work unchanged.
- `ScanResult` shape and field semantics are unchanged.
- `auth_hints` semantics are intentionally unchanged in phase 1.

## Recommended import targets going forward
For repository/plugin analyzer contracts:
- `from attackmap.sdk.contracts import AnalyzerProtocol, AnalyzerMetadata, AnalyzerResult`

For recon/result models:
- `from attackmap.sdk.models import Route, ExternalCall, DatabaseHint, AuthHint, SecretHint, ScanResult`

## Not included in phase 1
- No schema changes to `ScanResult`.
- No split of overloaded `auth_hints` semantics.
- No changes to analyzer discovery, merge logic, or CLI behavior.
