# Contract Unification Plan (Phase 1, No Behavior Change)

## Goal
Unify analyzer contracts first, while keeping:
- current analyzer behavior unchanged,
- current merge pipeline unchanged,
- `ScanResult` as the plugin analyzer result shape.

## Constraints Applied
- Minimal and incremental.
- No functionality removal.
- No reporting/threat-model pipeline rewrite.
- Preserve CLI behavior.

## Phase 1 Scope (Contract Unification Only)

### 1. Introduce a shared core contract module
Create a dedicated module in core, for example:
- `src/attackmap/analyzer_contracts.py`

Move/define shared repository-analyzer contract types there:
- `AnalyzerResult = ScanResult`
- `AnalyzerProtocol` (name, optional detect, analyze)
- `AnalyzerMetadata` as a canonical core representation
- `normalize_analyzer_metadata(metadata_obj) -> AnalyzerMetadata`

Important: do not remove legacy file-level contracts in phase 1.

### 2. Keep legacy file-level contracts intact
Leave these where they are for now:
- `AnalyzerSignals`
- `AnalyzerContext`
- `FileAnalyzer` and `FILE_ANALYZERS`

Reason: low-risk phase separation; this plan unifies plugin contracts first.

### 3. Add metadata adapter normalization in loader
Update analyzer loading path in `src/attackmap/analyzers.py` to normalize external metadata into one core shape:
- Accept both:
  - current core dataclass metadata
  - plugin pydantic metadata objects (`display_name`, `targets`, `languages`, etc.)
- Preserve runtime behavior and existing analyzer selection rules.

### 4. Keep `AnalyzerResult = ScanResult`
Do not change result schema in phase 1.
Do not introduce new required fields in plugin outputs yet.

### 5. Provide one import path for external analyzers
Document and expose a stable import target for plugin repos, e.g.:
- `from attackmap.analyzer_contracts import AnalyzerProtocol, AnalyzerMetadata, AnalyzerResult`

External repos can keep fallback shims temporarily, but phase-1 objective is to make fallback unnecessary over time.

## Minimal File Touch Plan (Phase 1)

Primary:
- `src/attackmap/analyzer_contracts.py` (new)
- `src/attackmap/analyzers.py` (switch to shared contracts + metadata normalization)

Optional docs/tests:
- `README.md` (short contract import guidance for external analyzers)
- `tests/test_analyzers.py` (add/adjust metadata normalization tests)

No required changes:
- `src/attackmap/scanner.py`
- `src/attackmap/models.py`
- report/threat-model/CLI behavior.

## Non-Goals in Phase 1
- Do not split `auth_hints` semantics yet.
- Do not change analyzer output beyond `ScanResult`.
- Do not change plugin installation/discovery mechanism.
- Do not move to remote analyzer retrieval changes.

## Why This Is the Smallest High-Value Step
- Eliminates contract drift risk between core and plugin repos.
- Reduces duplicate contract definitions across analyzer repos.
- Keeps all runtime behavior stable while preparing clean follow-on refactors.

## Suggested Phase 2 (After Phase 1 Lands)
- Introduce optional structured extension fields for non-auth semantic hints (service identity, role, edges, handler visibility) without breaking current `auth_hints`.
- Add provenance/source metadata per signal in merged results.
