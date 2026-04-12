# AttackMap

AttackMap is a defensive security analysis engine that helps engineers answer:

1. What is exposed in this codebase?
2. What trust boundaries are implied?
3. How could an attacker plausibly move through the system?
4. What should we fix first?

It is not a generic code explainer and not a full static-analysis platform. The core value is attacker-path-oriented defensive triage.

## What problem it solves

Most code security tooling produces isolated checks. AttackMap focuses on system-level security reasoning from repository evidence:

- entry points
- boundary crossings (service/external/data)
- likely attack chains
- prioritized defensive recommendations

This is useful for early threat review, architecture-oriented security triage, and “unknown repo” onboarding.

## High-level architecture

AttackMap core (`src/attackmap`) owns orchestration and higher-level reasoning:

- CLI orchestration (`cli.py`)
- analyzer discovery/selection/install/run/merge (`analyzers.py`)
- generic scanner (`scanner.py`)
- formal recon-to-analysis gateway (`recon_to_analysis.py`)
- attack-surface classification (`analyzer.py`)
- findings and attack paths (`threat_model.py`)
- defensive review synthesis and scoring (`defensive_review.py`)
- report/json/context artifacts (`report.py`, `review_json.py`, `context_pack.py`)

External analyzers (plugin packages) emit structured signals and are discovered through Python entry points (`attackmap.analyzers`).

## Pipeline stages

Current runtime pipeline (`attackmap analyze ...`) is:

1. Recon collection: analyzers emit/merge `ScanResult`
2. Attack surface: routes are classified into `AttackSurface`
3. Findings: prioritized `Finding` objects are generated
4. Attack paths: plausible `AttackPath` chains are generated
5. Defensive review: markdown + JSON triage outputs are rendered

The canonical translation boundary is `translate_recon(scan)` in `src/attackmap/recon_to_analysis.py`.

## Analyzer model

There are three layers:

1. Generic scanner logic (`scanner.py`)
- Generic route/external/db/auth/secret extraction only.
- Intentionally avoids ecosystem-specific overlays.

2. Built-in analyzers (`analyzers.py`)
- `python-web`
- `javascript-web`
- `default` (fallback)

3. External/plugin analyzers
- discovered by entry points
- optionally auto-installed from:
  - `https://gitlab.com/matthewd.xyzAI/attackmap-analyzers`

Analyzer contracts:
- canonical: `src/attackmap/analyzer_contracts.py`
- SDK import surface: `src/attackmap/sdk/`

Current result contract:
- `AnalyzerResult` aliases `ScanResult` (intentional staged compatibility).

## Current status / maturity

What is strong today:

- modular analyzer execution + merge pipeline
- scanner-backed FastAPI/Flask/Express route extraction
- chain-aware threat modeling (framework/service/ATProto-aware heuristics)
- defensive review prioritization with source-quality weighting
- stable machine-readable review artifacts + local eval harness

What is still maturing:

- hint taxonomy migration (reducing legacy non-auth use of `auth_hints`)
- deeper control/asset modeling
- detection-opportunity outputs
- richer service topology graphing

In short: strong for defensive code-level triage, not yet a complete threat-ops platform.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Run

```bash
attackmap analyze .
attackmap analyze . --output reports
attackmap analyze . --module php-web --module javascript-web
attackmap modules
```

Notes:
- `--module` is repeatable.
- Missing requested external analyzers are auto-installed (when possible) from the analyzer subgroup.

## Generated artifacts

By default, AttackMap writes:

- `architecture.md`
- `attack-surface.md`
- `defensive-review.md`
- `defensive-review.json`
- `review-context-pack.json`
- `attackmap-report.json`

## Evaluation harness

AttackMap ships a local review-quality eval harness:

```bash
python -m attackmap.review_eval \
  --fixture evals/fixtures/bluesky-atproto-review-v1.json \
  --review evals/samples/bluesky-atproto-good-review.md
```

Suite mode:

```bash
python -m attackmap.review_eval \
  --fixtures-dir evals/fixtures \
  --reviews-dir evals/samples
```

## Where to look next

Repository docs:
- `AGENTS.md`
- `VISION.md`
- `old_docs/` (historical generated design docs)

Primary maintainer documentation now lives in the GitLab wiki:
- <https://gitlab.com/matthewd.xyzAI/attackmap/-/wikis/home>

Recommended wiki pages:
- `docs/ARCHITECTURE_OVERVIEW`
- `docs/DATA_FLOW`
- `docs/ANALYZER_ECOSYSTEM`
- `docs/ANALYZER_CONTRACT`
- `docs/HINT_TAXONOMY`
- `docs/FILE_GUIDE`
- `docs/TEST_STRATEGY`
- `docs/BEHAVIOR_GUARANTEES`
- `docs/THREAT_OPS_POSITIONING`

## License

MIT
