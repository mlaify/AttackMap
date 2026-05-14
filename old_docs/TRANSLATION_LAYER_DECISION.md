# Translation Layer Decision

## Current State Assessment

### Is there a formal translation layer?

Yes, partially.

- Formal module exists: [`src/attackmap/recon_to_analysis.py`](/Volumes/Dev/repos/GitHub/mlaify/attackmap/AttackMap/src/attackmap/recon_to_analysis.py)
- Formal entrypoint exists: `translate_recon(scan) -> AnalysisOutputs`
- CLI uses it as the translation stage before downstream reporting.

### Is there a single implementation layer?

Not fully.

There is a **single orchestration layer**, but **multiple construction layers**:

- `AttackSurface` construction lives in `analyzer.py`
- `Finding` and `AttackPath` construction live in `threat_model.py`
- `recon_to_analysis.py` orchestrates these functions rather than owning all constructors directly

This means translation is centralized at the call boundary, but not yet centralized at the implementation boundary.

## Decision

## Do **not** create a second parallel translation module.

Refactor the existing layer (`recon_to_analysis.py`) and the underlying functions incrementally.

## Why

- A formal layer already exists and is wired into CLI.
- Creating another module would duplicate orchestration and increase ambiguity.
- Existing downstream consumers already rely on the current flow.
- Incremental consolidation into the existing layer is lower risk and more testable.

## Recommended Refactor Direction (Incremental)

1. Keep `translate_recon(...)` as the canonical entrypoint.
2. Move/alias construction helpers over time so `recon_to_analysis.py` becomes the canonical home for conversion policies.
3. Keep `analyzer.py` focused on architecture/attack-surface summarization presentation concerns.
4. Keep `threat_model.py` focused on chain/link heuristics that feed findings/paths, but expose them through `recon_to_analysis`.
5. Preserve current model outputs and CLI behavior during migration.

## Practical Conclusion

Current system = **single formal translation gateway with distributed constructor logic**.

Best next step = **refactor and consolidate the existing gateway**, not add a new one.

