# Recon Translation Consolidation

## Intent
Consolidate the existing recon-to-analysis flow around the canonical gateway (`translate_recon(scan)`) without introducing a second translation layer.

## Changes
- Extended attack-path generation to optionally consume precomputed attack surfaces:
  - `generate_attack_paths(scan, attack_surfaces=None)`
  - `to_attack_paths(scan, attack_surfaces=None)`
- Default behavior remains unchanged:
  - if no surfaces are provided, attack paths still derive surfaces via `identify_attack_surfaces(scan)`.

## Why this helps
- Removes unnecessary recomputation in call paths that already have attack surfaces available.
- Keeps existing model shapes and scanner/analyzer contracts intact.
- Preserves compatibility while result-model cleanup (`auth_hints` decomposition) is still in progress.

## Compatibility notes
- CLI/report behavior is preserved because default call paths are unchanged.
- `auth_hints` filtering behavior in `recon_to_analysis` is unchanged:
  - findings/surfaces remain auth-filtered via `_auth_filtered_scan`
  - attack-path logic still uses full scan hints unless callers explicitly pass surfaces.
