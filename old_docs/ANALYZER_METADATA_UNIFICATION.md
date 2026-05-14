# Analyzer Metadata Unification

## Canonical Model

AttackMap now uses a single canonical `AnalyzerMetadata` model for both:

- built-in repository analyzers
- plugin/discovered analyzers

Canonical definition:
- [`src/attackmap/analyzer_contracts.py`](/Volumes/Dev/repos/GitHub/mlaify/attackmap/AttackMap/src/attackmap/analyzer_contracts.py)

Fields preserved:

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

Derived compatibility property:
- `ecosystems` (from `languages + targets`)

## Where It Is Applied

- Built-ins instantiate canonical `AnalyzerMetadata` directly:
  - [`src/attackmap/analyzers.py`](/Volumes/Dev/repos/GitHub/mlaify/attackmap/AttackMap/src/attackmap/analyzers.py)
- Plugin/discovered analyzers are normalized through:
  - `normalize_analyzer_metadata(...)`
  - called during discovery/validation and metadata access paths in `analyzers.py`

## Validation and Registry Behavior

Analyzer loading/selection behavior is preserved while validation now consistently uses canonical metadata normalization:

- discovery load path normalizes metadata
- candidate validation uses normalized metadata
- `get_analyzer_metadata(...)` returns canonical metadata for built-ins and plugins

## Backward Compatibility

- Legacy metadata inputs using `ecosystems` are still accepted.
- `display_name` defaults to `name` when omitted in legacy-style metadata payloads.
- No analyzer loading/selecting behavior changes were introduced.

## Test Coverage Added/Updated

- Metadata normalization preserves rich plugin fields and derived `ecosystems`.
- External analyzer metadata provided as dict is normalized through canonical path.
- Existing built-in metadata behavior and legacy `ecosystems` compatibility remain covered.

