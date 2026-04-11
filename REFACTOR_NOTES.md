# Analyzer Contract Refactor Notes

This refactor removes duplicated local analyzer contract models in external analyzer packages and uses the shared AttackMap SDK contract surface directly.

## What changed

- Switched external analyzer `contracts.py` modules to import canonical contracts/models from:
  - `attackmap.sdk.contracts`
  - `attackmap.sdk.models`
- Removed local fallback copies of:
  - `AnalyzerMetadata`
  - `AttackMapAnalyzerProtocol`
  - `Route`, `ExternalCall`, `DatabaseHint`, `AuthHint`, `SecretHint`, `ScanResult`
- Kept a minimal compatibility alias:
  - `AttackMapAnalyzerProtocol = AnalyzerProtocol`
- Added a missing `contracts.py` for `node-service` so its existing analyzer imports resolve consistently.
- Added compatibility tests in each external analyzer repo to assert shared SDK type reuse.

## Scope

- External analyzers updated:
  - `node-service`
  - `atproto`
  - `omeka-s`
  - `php-laminas`
  - `php-web`
- Core built-ins (`javascript-web`, `default`) already used shared core contracts and required no contract-layer changes.

## Behavior impact

- Analyzer behavior and emitted recon signals are unchanged.
- `auth_hints` semantics are unchanged.
- This is a contract-source unification and cleanup step only.

## Compatibility note

- External analyzers now require AttackMap core SDK imports at runtime (expected in plugin usage, where analyzers are loaded by AttackMap).
