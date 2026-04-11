# AttackMap Analyzer Architecture Summary

## Current State (Two Analyzer Systems)
AttackMap currently runs two analyzer systems in parallel:

1. Legacy file-level scanner analyzers
- Purpose: scanner decomposition and lower-level signal tests.
- Contract: `AnalyzerSignals` + `FileAnalyzer`.
- Output shape: intermediate signal bundle merged into `ScanResult`.

2. Repository-level analyzers (plugin architecture)
- Purpose: built-ins + external analyzer packages discovered via entry points.
- Contract: `Analyzer` protocol + metadata + `AnalyzerResult`.
- Output shape: `AnalyzerResult` (currently alias of `ScanResult`).

## Files Defining Core Contracts and Runtime Behavior

### Shared data/result models
- [`src/attackmap/models.py`](/Volumes/Dev/repos/GitLab/matthewd.xyzAI/attackmap/src/attackmap/models.py)
  - Defines `Route`, `ExternalCall`, `DatabaseHint`, `AuthHint`, `SecretHint`, `ScanResult`, `AttackSurface`, `Finding`, `AttackPath`.

### Legacy file-level analyzer contracts and wiring
- [`src/attackmap/analyzers.py`](/Volumes/Dev/repos/GitLab/matthewd.xyzAI/attackmap/src/attackmap/analyzers.py)
  - `AnalyzerSignals` (legacy signal contract).
  - `AnalyzerContext`, `FileAnalyzer`, and `RouteAnalyzer` / `ExternalCallAnalyzer` / `DatabaseAnalyzer` / `AuthAnalyzer` / `SecretAnalyzer`.
  - `FILE_ANALYZERS`, `get_builtin_analyzers()`, `merge_analyzer_signals()`.

### Repository-level analyzer contracts
- [`src/attackmap/analyzers.py`](/Volumes/Dev/repos/GitLab/matthewd.xyzAI/attackmap/src/attackmap/analyzers.py)
  - `AnalyzerResult = ScanResult` alias.
  - `AnalyzerMetadata` (core dataclass contract).
  - `AnalyzerRepositoryModule`.
  - `Analyzer` protocol (`name`, optional `detect`, `analyze`).

### Analyzer discovery/loading/selection
- [`src/attackmap/analyzers.py`](/Volumes/Dev/repos/GitLab/matthewd.xyzAI/attackmap/src/attackmap/analyzers.py)
  - Entry point group: `attackmap.analyzers`.
  - `discover_installed_analyzers()`, `_load_discovered_analyzer()`, `_coerce_analyzer_instance()`, `_is_valid_analyzer()`.
  - `get_registered_analyzers()`.
  - `select_requested_analyzers()` and module auto-install.
  - `get_available_modules()`, `get_available_repository_modules()`.

### Analyzer execution and merge
- [`src/attackmap/analyzers.py`](/Volumes/Dev/repos/GitLab/matthewd.xyzAI/attackmap/src/attackmap/analyzers.py)
  - `resolve_run_analyzers()` and `_should_run_analyzer()` (detect gating).
  - `analyze_repository()` orchestration.
  - `merge_analyzer_results()` (deduplicates routes/external/databases/auth/secrets).

### Scanner-backed built-ins (repo-level built-ins currently wrap scanner)
- [`src/attackmap/analyzers.py`](/Volumes/Dev/repos/GitLab/matthewd.xyzAI/attackmap/src/attackmap/analyzers.py)
  - `BuiltinPythonWebAnalyzer` -> `scan_repo(..., suffixes={".py"})`
  - `BuiltinJavaScriptWebAnalyzer` -> `scan_repo(..., suffixes={".js"})`
  - `DefaultAnalyzer` -> fallback suffix coverage.
- [`src/attackmap/scanner.py`](/Volumes/Dev/repos/GitLab/matthewd.xyzAI/attackmap/src/attackmap/scanner.py)
  - `scan_repo()`, route extraction, DB/auth/secret/external extraction, Node-service and thin ATProto overlay hints.

### CLI orchestration
- [`src/attackmap/cli.py`](/Volumes/Dev/repos/GitLab/matthewd.xyzAI/attackmap/src/attackmap/cli.py)
  - Resolves selected analyzers, runs `analyze_repository()`, then analysis/report pipeline.

### Tests covering architecture behavior
- [`tests/test_analyzers.py`](/Volumes/Dev/repos/GitLab/matthewd.xyzAI/attackmap/tests/test_analyzers.py)
  - Discovery, selection, metadata, detect behavior, merge behavior.
- [`tests/test_scanner.py`](/Volumes/Dev/repos/GitLab/matthewd.xyzAI/attackmap/tests/test_scanner.py)
  - Scanner extraction behavior and scanner-emitted service/protocol hints.

## External Plugin Contract Duplication (Observed)
External analyzer repos currently duplicate contract shims via local `contracts.py` files:
- `/Volumes/Dev/repos/GitLab/matthewd.xyzAI/attackmap-analyzers/attackmap-analyzer-node-service/src/attackmap_analyzer_node_service/contracts.py`
- `/Volumes/Dev/repos/GitLab/matthewd.xyzAI/attackmap-analyzers/attackmap-analyzer-atproto/src/attackmap_analyzer_atproto/contracts.py`
- `/Volumes/Dev/repos/GitLab/matthewd.xyzAI/attackmap-analyzers/attackmap-analyzer-omeka-s/src/attackmap_analyzer_omeka_s/contracts.py`
- `/Volumes/Dev/repos/GitLab/matthewd.xyzAI/attackmap-analyzers/attackmap-analyzer-php-laminas/src/attackmap_analyzer_php_laminas/contracts.py`
- `/Volumes/Dev/repos/GitLab/matthewd.xyzAI/attackmap-analyzers/attackmap-analyzer-php-web/src/attackmap_analyzer_php_web/contracts.py`

These contracts typically try `from attackmap.models import ...` and fall back to local model definitions.

## Practical Architecture Notes
- `ScanResult` is already the de facto cross-analyzer output contract.
- `auth_hints` currently carries both auth and non-auth recon semantics (service identity, role, entrypoint, edge, visibility, protocol hints).
- Core and external metadata schemas are not identical:
  - Core: simple dataclass (`name`, `description`, `scope`, `ecosystems`).
  - Plugins: richer pydantic metadata (`display_name`, `version`, `targets`, `languages`, etc.) with derived `ecosystems`.
