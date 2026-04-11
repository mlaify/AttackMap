# Updated Analyzer Metadata (Canonical Model)

AttackMap now uses one canonical `AnalyzerMetadata` model across built-in and plugin analyzers.

Canonical model location:
- [`src/attackmap/analyzer_contracts.py`](/Volumes/Dev/repos/GitLab/matthewd.xyzAI/attackmap/src/attackmap/analyzer_contracts.py)

## Canonical fields
- `name`
- `display_name`
- `version`
- `description`
- `scope`
- `targets`
- `languages`
- `priority`
- `experimental`
- `enabled_by_default`

Derived property:
- `ecosystems` (ordered, deduplicated, lowercase tuple from `languages + targets`)

## Runtime behavior
- Built-in analyzers now instantiate this richer canonical metadata model directly.
- Plugin metadata is normalized into the canonical model during analyzer load/validation.
- Registry and metadata access paths now use canonical normalization.

## Backward compatibility
- Legacy metadata construction using `ecosystems=...` is still accepted.
  - In compatibility mode, `ecosystems` is mapped into `languages` when `languages` and `targets` are omitted.
- Existing imports from `attackmap.analyzers` remain valid.
- Existing analyzer discovery and merge behavior is unchanged.

## SDK import path
Preferred import path for plugin/analyzer repos:
- `from attackmap.sdk.contracts import AnalyzerMetadata`

`AnalyzerMetadata` from SDK maps to the same canonical model.
