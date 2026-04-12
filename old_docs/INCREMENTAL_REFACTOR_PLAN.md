# Incremental Refactor Plan (Analyzer + Translation Architecture)

## Goals

- Unify contracts first.
- Preserve current behavior and CLI output shape.
- Keep `translate_recon(scan)` as the single formal translation gateway.
- Remove duplicated specialized scanner logic (already started) and prevent drift.
- Migrate safely while `auth_hints` remains temporarily overloaded.

## Phase 0: Baseline and Guardrails (No Behavior Change)

1. Freeze architectural invariants with tests:
- `analyze_repository(...)` returns merged `ScanResult`.
- `translate_recon(...)` remains single entrypoint from recon to higher-level outputs.
- scanner stays generic-only (no node-service/atproto overlays).

2. Add contract surface tests for:
- `attackmap.analyzer_contracts` and `attackmap.sdk.contracts` equivalence.
- `attackmap.recon_models` and `attackmap.sdk.models` equivalence.

## Phase 1: Contract Unification (Done/Keep Stable)

1. Canonical analyzer contract module:
- `src/attackmap/analyzer_contracts.py`.

2. Canonical recon model module:
- `src/attackmap/recon_models.py` backed by `models.py`.

3. SDK facade:
- `src/attackmap/sdk/contracts.py`
- `src/attackmap/sdk/models.py`

4. Keep compatibility aliases:
- `AnalyzerResult = ScanResult`
- legacy ecosystems coercion in `AnalyzerMetadata`.

Exit criteria:
- no plugin interface redesign
- behavior unchanged

## Phase 2: Scanner/Analyzer Boundary Hardening

1. Keep scanner generic-only:
- routes, external calls, DB, auth, secrets, file walking/filtering only.

2. Ensure specialized signals come from specialized analyzers:
- node-service / atproto overlays emitted by those analyzers only.

3. Add anti-regression tests:
- scanner must not emit `service_name:*`, `edge:*`, `atproto_*` overlays.
- analyzer-driven overlays still merged and consumed end-to-end.

Exit criteria:
- no duplicated node-service/atproto ownership inside scanner.

## Phase 3: Translation Consolidation (Gateway-Centric)

Current state:
- `translate_recon(scan)` is canonical gateway.
- constructors are split across `analyzer.py` and `threat_model.py`.

Plan:
1. Keep `translate_recon` as orchestrator contract.
2. Gradually move conversion-policy helpers into gateway-owned submodules (or gateway-local wrappers) while preserving existing function signatures.
3. Route all CLI/reporting paths through gateway only (already true), and avoid parallel direct generation paths in new code.

Exit criteria:
- one formal gateway, no competing translation modules.

## Phase 4: `auth_hints` De-overloading (Staged, Backward-Compatible)

1. Introduce typed non-auth hint categories in result model (additive).
2. Dual-write from analyzers (new fields + legacy `auth_hints`) during migration.
3. Update translation/threat logic to prefer typed fields, fallback to legacy prefixes.
4. Deprecate non-auth encodings in `auth_hints` after compatibility window.

Exit criteria:
- `auth_hints` mostly auth-only semantics
- explicit typed fields for service/entrypoint/edge/protocol signals

## Phase 5: Attack-Path Input Reuse Optimization

Current tension:
- `generate_attack_paths(scan)` recomputes surfaces via `identify_attack_surfaces(scan)`.

Plan:
1. Add optional `attack_surfaces` parameter to `generate_attack_paths(...)`.
2. In `translate_recon`, pass already-computed surfaces to avoid recomputation drift.
3. Keep old call signature compatible initially.

Exit criteria:
- deterministic reuse of one surface derivation per translation pass.

## Risk Controls

- Keep each phase small and test-backed.
- Prefer additive compatibility layers over rewrites.
- Avoid plugin contract churn until typed hint migration phase.
- Maintain stable CLI and report artifact shapes unless explicitly versioned.

## Recommended Next Immediate Step

Implement Phase 3 small step:
- introduce a thin translation-internals module used only by `recon_to_analysis.py` (no external API changes),
- keep existing constructors intact,
- add tests asserting `translate_recon` is the only CLI translation path.

