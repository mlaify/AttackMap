# Higher-Level Analysis Flow

## Constructor Sites (`AttackSurface`, `Finding`, `AttackPath`)

### Production code

- `AttackSurface(...)`
  - [`src/attackmap/analyzer.py`](/Volumes/Dev/repos/GitLab/matthewd.xyzAI/attackmap/src/attackmap/analyzer.py)
  - Function: `identify_attack_surfaces(scan: ScanResult) -> list[AttackSurface]`
- `Finding(...)`
  - [`src/attackmap/threat_model.py`](/Volumes/Dev/repos/GitLab/matthewd.xyzAI/attackmap/src/attackmap/threat_model.py)
  - Function: `generate_findings(scan: ScanResult, attack_surfaces: list[AttackSurface] | None = None) -> list[Finding]`
- `AttackPath(...)`
  - [`src/attackmap/threat_model.py`](/Volumes/Dev/repos/GitLab/matthewd.xyzAI/attackmap/src/attackmap/threat_model.py)
  - Function: `generate_attack_paths(scan: ScanResult) -> list[AttackPath]`

### Test-only constructor usage

Tests instantiate these models directly for fixtures/expected behavior in:
- `tests/test_defensive_review.py`
- `tests/test_report.py`
- `tests/test_review_json.py`
- `tests/test_review_prompts.py`
- plus related tests where model objects are manually built.

## Translation Flow From `ScanResult` to Higher-Level Models

### Upstream recon production

1. Analyzer execution produces `ScanResult`:
   - `analyze_repository(...)` in [`src/attackmap/analyzers.py`](/Volumes/Dev/repos/GitLab/matthewd.xyzAI/attackmap/src/attackmap/analyzers.py)
   - via built-ins + discovered analyzers, merged by `merge_analyzer_results(...)`.

### Formal translation entrypoint

2. CLI invokes translation layer:
   - [`src/attackmap/cli.py`](/Volumes/Dev/repos/GitLab/matthewd.xyzAI/attackmap/src/attackmap/cli.py)
   - `analysis = translate_recon(scan)` from [`src/attackmap/recon_to_analysis.py`](/Volumes/Dev/repos/GitLab/matthewd.xyzAI/attackmap/src/attackmap/recon_to_analysis.py)

3. `translate_recon(scan)` delegates:
   - `to_attack_surface(scan)` -> `identify_attack_surfaces(...)`
   - `to_findings(scan, attack_surfaces)` -> `generate_findings(...)`
   - `to_attack_paths(scan)` -> `generate_attack_paths(...)`

### Downstream consumption (not construction)

4. The produced lists are consumed by:
   - `summarize_attack_surface(...)` in `analyzer.py`
   - `render_defensive_review(...)` in [`src/attackmap/defensive_review.py`](/Volumes/Dev/repos/GitLab/matthewd.xyzAI/attackmap/src/attackmap/defensive_review.py)
   - report writers in [`src/attackmap/report.py`](/Volumes/Dev/repos/GitLab/matthewd.xyzAI/attackmap/src/attackmap/report.py)
   - review JSON/prompt layers.

## Key Relationship Notes

- There is one formal orchestration function (`translate_recon`) used by CLI.
- Construction logic itself remains distributed:
  - `AttackSurface` creation in `analyzer.py`
  - `Finding`/`AttackPath` creation in `threat_model.py`
- `generate_attack_paths(scan)` internally calls `identify_attack_surfaces(scan)` again, so surface classification is recomputed within path generation.

