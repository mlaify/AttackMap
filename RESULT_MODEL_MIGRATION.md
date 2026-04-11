# Result Model Migration (Phase 2)

## Problem

`auth_hints` currently mixes true auth/security signals with non-auth concepts such as:

- service identity / role
- entrypoint markers
- inter-service edges
- protocol overlays (for example AT Protocol namespace and XRPC notes)

This reduces model clarity and makes downstream threat logic harder to reason about.

## Migration goals

1. Introduce dedicated result-model fields for non-auth concepts.
2. Keep backward compatibility while analyzers migrate.
3. Avoid breaking current report/threat behavior during transition.

## Staged plan

### Step 1 (implemented now): Add model categories + compatibility reads

- Added dedicated hint models and `ScanResult` fields:
  - `service_hints`
  - `entrypoint_hints`
  - `edge_hints`
  - `protocol_hints`
- Kept `auth_hints` unchanged and fully supported.
- Updated core merge logic to merge/dedupe new hint fields.
- Updated threat modeling helpers to read **both**:
  - legacy encoded hints in `auth_hints`
  - new typed categories

Result: no analyzer changes required yet; existing behavior remains stable.

### Step 2 (next): Migrate `node-service` and `atproto` emitters

- Update analyzers to emit non-auth hints into dedicated fields.
- Keep dual-write temporarily for compatibility:
  - write to new field + legacy `auth_hints`.
- Add analyzer tests asserting new-field emission.

### Step 3: Migrate remaining analyzers

- Apply same dual-write migration for:
  - `php-web`
  - `php-laminas`
  - `omeka-s`
  - built-in/default/javascript paths where relevant.

### Step 4: Shift downstream consumers to new fields first

- Prefer dedicated fields in threat/review logic.
- Keep legacy read fallback for one compatibility window.

### Step 5: Deprecate and remove legacy non-auth usage in `auth_hints`

- Remove prefixed non-auth encodings from `auth_hints`.
- Keep `auth_hints` strictly auth-related.
- Update docs/tests to reflect final contract.

## Compatibility notes

- This step is intentionally additive and non-breaking.
- Existing analyzers that only emit `auth_hints` continue to work.
- Existing tests remain valid, with added coverage for new-field compatibility.
