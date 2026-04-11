# Result Model Migration (Staged)

## Problem
`ScanResult.auth_hints` is currently overloaded as a generic hint bus. It includes true auth signals plus non-auth concepts (service identity, edges, framework/protocol notes, entrypoint markers), which makes translation and prioritization noisy.

## Migration goals
- Introduce dedicated non-auth hint categories.
- Preserve backward compatibility while analyzers migrate.
- Keep `translate_recon(scan)` behavior stable.
- Reduce auth filtering complexity over time.

## Staged plan
1. **Phase 2.1 (this patch): Add new hint buckets + compatibility readers**
   - Add new `ScanResult` fields:
     - `service_hints`
     - `edge_hints`
     - `entrypoint_hints`
     - `protocol_hints`
     - `framework_hints`
   - Keep `auth_hints` unchanged for compatibility.
   - Update core consumers to read new buckets first, then fall back to `auth_hints`.
   - Keep report/CLI outputs stable.

2. **Phase 2.2: Analyzer emission migration (node-service + atproto first)**
   - Update analyzers to emit service/edge/protocol data into dedicated fields.
   - Keep temporary dual-write to `auth_hints` where needed for compatibility.

3. **Phase 2.3: Translation tightening**
   - Simplify `recon_to_analysis` auth filtering by relying on dedicated buckets instead of large prefix-based exclusions.
   - Reduce legacy prefix compatibility logic.

4. **Phase 2.4: De-overload outputs**
   - Update downstream outputs that currently assume non-auth hints in `auth_signals`.
   - Move to explicit auth vs non-auth evidence sections.

5. **Phase 2.5: Compatibility removal**
   - Remove legacy `auth_hints`-as-bus assumptions once analyzer migration is complete and coverage is stable.

## Phase 2.1 changes included
- Added new hint models and `ScanResult` fields in core models.
- Exposed new hint models via `recon_models` and `attackmap.sdk.models`/`attackmap.sdk`.
- Updated merge logic to deduplicate and merge new hint fields across analyzers.
- Updated threat modeling chain extraction to consume dedicated buckets with `auth_hints` fallback.
- Updated translation filtering to ignore hints that have already migrated to dedicated buckets.
- Added tests for:
  - shared SDK import paths for new hint types
  - merged result dedupe across new fields
  - chain generation from dedicated service/edge/protocol hints
  - translation behavior stability with migrated hints

## Compatibility notes
- `auth_hints` behavior is still supported.
- Existing analyzers/tests that only emit `auth_hints` continue to work.
- No CLI shape or report artifact shape changes in this step.
