# Refactor Notes: Analyzer Contract Unification

## Scope
This pass focused on ensuring analyzer packages use shared AttackMap contracts/models instead of local duplicated definitions.

## What changed in core
- Updated [`src/attackmap/analyzers.py`](/Volumes/Dev/repos/GitHub/mlaify/attackmap/AttackMap/src/attackmap/analyzers.py) to import canonical shared types from:
  - `attackmap.sdk.contracts`
  - `attackmap.sdk.models`
- Behavior is unchanged; this is an import-path unification cleanup.

## External analyzer package status
Reviewed local analyzer repos under:
- `/Volumes/Dev/repos/GitHub/mlaify/attackmap/attackmap-analyzer-node-service`
- `/Volumes/Dev/repos/GitHub/mlaify/attackmap/attackmap-analyzer-atproto`
- `/Volumes/Dev/repos/GitHub/mlaify/attackmap/attackmap-analyzer-omeka-s`
- `/Volumes/Dev/repos/GitHub/mlaify/attackmap/attackmap-analyzer-php-laminas`
- `/Volumes/Dev/repos/GitHub/mlaify/attackmap/attackmap-analyzer-php-web`

Each currently imports `AnalyzerMetadata`/`AnalyzerProtocol` from `attackmap.sdk.contracts` and recon/result models from `attackmap.sdk.models`. No duplicated local model definitions were found in those repos.

## Compatibility
- No signal schema changes.
- `auth_hints` semantics are intentionally unchanged in this pass.
- Public analyzer exports remain intact.
