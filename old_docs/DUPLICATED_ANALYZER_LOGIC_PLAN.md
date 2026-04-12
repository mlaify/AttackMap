# Duplicated Analyzer Logic Removal Plan

## Goal

Remove Node-service and ATProto overlay duplication from core `scanner.py` while preserving current user-visible behavior.

## Constraints

- Keep generic route/auth/db/secret extraction in scanner.
- Treat node-service and atproto overlays as specialized analyzer responsibilities.
- Avoid behavior loss during migration.

## Staged Plan

### Phase A: Guardrails First

1. Add explicit regression tests that capture current output invariants for:
   - scanner-only runs
   - scanner + node-service
   - scanner + atproto
2. Assert deduplication and no severe output drop in findings/paths for representative fixtures.

### Phase B: Feature-flag Scanner Overlays (Compatibility Window)

1. Introduce internal scanner options for overlays:
   - `enable_node_service_overlay` (default `True` initially)
   - `enable_atproto_overlay` (default `True` initially)
2. Route existing `scan_repo` behavior through those flags without changing defaults.

### Phase C: Prefer Specialized Analyzers in Orchestrated Runs

1. In analyzer orchestration path, disable scanner overlays when corresponding analyzers are active:
   - if `node-service` selected/detected, disable node overlay in scanner-backed analyzer path
   - if `atproto` selected/detected, disable atproto overlay in scanner-backed analyzer path
2. Keep scanner overlays enabled for fallback runs where specialized analyzers are unavailable.

### Phase D: Remove Duplicated Overlay Code from Scanner

After compatibility window and stable test signal:

1. Delete Node overlay functions/constants from scanner:
   - `_append_node_service_signals`
   - node service env/event helper patterns + service inference helpers used only by overlay
2. Delete ATProto overlay functions/constants from scanner:
   - `_append_atproto_overlay_signals`
   - atproto literal/event patterns used only by overlay
3. Keep only generic extraction code paths in scanner.

### Phase E: Cleanup + Documentation

1. Update AGENTS/docs to clarify scanner vs analyzer boundaries.
2. Document fallback behavior:
   - scanner provides generic baseline
   - specialized analyzers provide ecosystem overlays

## Immediate First Implementation Step (Recommended)

Implement **Phase B only**:

- add scanner overlay feature flags (default-on)
- add tests for both enabled/disabled modes

This is low-risk, transparent, and creates the migration lever without immediate behavior change.

## Success Criteria

- No duplicated Node/ATProto overlay emission in runs where specialized analyzers are active.
- Scanner remains a stable generic recon engine.
- Findings/attack paths remain credible and non-regressive on existing fixtures.

