# AttackMap Architecture Summary (Current)

## High-Level Pipeline

1. Recon collection:
- `scan_repo(...)` in [scanner.py](/Volumes/Dev/repos/GitHub/mlaify/attackmap/AttackMap/src/attackmap/scanner.py) provides generic extraction only.
- Built-in and plugin analyzers run via [analyzers.py](/Volumes/Dev/repos/GitHub/mlaify/attackmap/AttackMap/src/attackmap/analyzers.py) and each return `ScanResult`-compatible output.

2. Recon merge:
- `analyze_repository(...)` merges analyzer outputs with `merge_analyzer_results(...)` into one `ScanResult`.

3. Recon -> higher-level translation:
- `translate_recon(scan)` in [recon_to_analysis.py](/Volumes/Dev/repos/GitHub/mlaify/attackmap/AttackMap/src/attackmap/recon_to_analysis.py) is the canonical gateway.
- It produces:
  - `AttackSurface` via `identify_attack_surfaces(...)`
  - `Finding` via `generate_findings(...)`
  - `AttackPath` via `generate_attack_paths(...)`

4. Downstream reporting/prioritization:
- [defensive_review.py](/Volumes/Dev/repos/GitHub/mlaify/attackmap/AttackMap/src/attackmap/defensive_review.py), [review_json.py](/Volumes/Dev/repos/GitHub/mlaify/attackmap/AttackMap/src/attackmap/review_json.py), [report.py](/Volumes/Dev/repos/GitHub/mlaify/attackmap/AttackMap/src/attackmap/report.py) consume translated models.

## Contracts and Model Sources of Truth

### Analyzer/plugin contract
- Canonical module: [analyzer_contracts.py](/Volumes/Dev/repos/GitHub/mlaify/attackmap/AttackMap/src/attackmap/analyzer_contracts.py)
  - `AnalyzerProtocol`
  - `AnalyzerMetadata`
  - `AnalyzerRepositoryModule`
  - `AnalyzerResult = ScanResult`

### Recon/result contract
- Canonical recon exports: [recon_models.py](/Volumes/Dev/repos/GitHub/mlaify/attackmap/AttackMap/src/attackmap/recon_models.py)
- Base model definitions: [models.py](/Volumes/Dev/repos/GitHub/mlaify/attackmap/AttackMap/src/attackmap/models.py)
  - `Route`, `ExternalCall`, `DatabaseHint`, `AuthHint`, `SecretHint`, `ScanResult`
  - higher-level `AttackSurface`, `Finding`, `AttackPath`

### SDK import surface
- [sdk/contracts.py](/Volumes/Dev/repos/GitHub/mlaify/attackmap/AttackMap/src/attackmap/sdk/contracts.py)
- [sdk/models.py](/Volumes/Dev/repos/GitHub/mlaify/attackmap/AttackMap/src/attackmap/sdk/models.py)

## Current Module Responsibilities

### `scanner.py` (generic scanner)
- file walking / suffix filtering
- generic Python/JS route extraction
- generic external call, DB, auth, secret extraction
- no node-service or atproto overlay logic

### `analyzers.py` (execution + registry + merge)
- built-in scanner-backed analyzers (`python-web`, `javascript-web`, `default`)
- plugin discovery (entry points), selection, optional install
- repository-level analyzer orchestration and merge

### `recon_to_analysis.py` (formal gateway)
- canonical translation entrypoint used by CLI
- conservative auth filtering for surface/finding translation due to overloaded `auth_hints`
- attack-path generation still uses full hints to preserve chain-linking during migration

### `analyzer.py` and `threat_model.py` (constructor logic)
- `analyzer.py`: constructs `AttackSurface`
- `threat_model.py`: constructs `Finding` and `AttackPath`

## Known Architectural Tensions

1. `auth_hints` overload:
- holds true auth signals plus non-auth metadata (service/edge/protocol/framework hints)
- translation mitigates this conservatively, but schema remains overloaded

2. Constructor logic is split:
- formal gateway exists (`translate_recon`), but concrete constructors remain in `analyzer.py` and `threat_model.py`

3. Path generation recomputes surfaces:
- `generate_attack_paths(scan)` internally calls `identify_attack_surfaces(scan)` rather than reusing translated surfaces from gateway output

## Call Relationship (CLI path)

- [cli.py](/Volumes/Dev/repos/GitHub/mlaify/attackmap/AttackMap/src/attackmap/cli.py)
  - `scan = analyze_repository(...)`
  - `analysis = translate_recon(scan)`
  - downstream rendering consumes `analysis.attack_surfaces/findings/attack_paths`
