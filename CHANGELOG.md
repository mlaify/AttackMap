# Changelog

All notable changes to AttackMap will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-04

Initial public release of AttackMap — an AI-assisted defensive security analyzer
for codebases.

### Added

- **Four-layer analysis pipeline.** Heuristic scanner and analyzer plugins feed
  an asset/control overlay, which feeds a cross-cutting insight engine, which
  feeds an LLM-narrated defensive review.
- **Eleven ecosystem analyzer plugins**, each distributable as a separate
  package and auto-discovered through the `attackmap.analyzers` entry-point
  group: Rust, Go, Java/Kotlin Spring, .NET, Terraform, C, C++, Python,
  Node.js/TypeScript, AT Protocol (Bluesky), and PHP (generic web, Laminas/Zend,
  Omeka-S).
- **Asset and control modeling.** Identifies what is at risk (credentials,
  sessions, PII, payment data, internal secrets — with criticality tiers) and
  what protects it (auth, authorization, input validation, rate limiting, CSRF,
  encryption-at-rest/in-transit, audit logging, RBAC, MFA), including detection
  of *absent* expected controls.
- **Cross-cutting insight detectors:** `sensitive_asset_reachability`,
  `shared_secret_blast_radius`, `single_point_of_failure`,
  `defense_gap_in_chain`, `control_strength_mismatch`, `asymmetric_protection`,
  `audit_gap`, `admin_action_without_auth`, `control_bypass`,
  `trust_boundary_violation`, and `stale_or_contradictory_signal`.
- **MITRE ATT&CK technique mapping** on every insight and finding, with linkouts
  to attack.mitre.org.
- **Detection opportunities.** For each insight AttackMap suggests a runtime
  signal (log, metric, trace, network, config audit) and a Sigma/KQL-style
  rule sketch that catches the same condition in production.
- **LLM narrative review (`--llm`).** Generates `defensive-review-llm.md` using
  Claude Opus 4.7 with adaptive thinking. Two backends:
  - **API backend** — uses `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN`.
  - **Claude Code CLI backend** — shells out to the `claude` CLI so existing
    Pro/Max subscribers can run reviews without API credits.
- **Signal v2.** Every analyzer signal carries `file:line`, an evidence-text
  snippet, and a confidence score. Every claim in the review is grounded in
  cited evidence.
- **Output artifacts.** Each run produces `architecture.md`, `attack-surface.md`,
  `defensive-review.md`, `defensive-review.json` (schema v1.2.0),
  `review-context-pack.json`, and `attackmap-report.json`. With `--llm`, also
  `defensive-review-llm.md` and `defensive-review-llm.meta.json`.
- **Local eval harness** (`attackmap.review_eval`) for grading review quality
  against golden fixtures.

### Security

- All evidence-text snippets are read from local source files only; AttackMap
  does not exfiltrate code unless the user opts into `--llm`, in which case the
  evidence pack is sent to the configured LLM backend.
- See [SECURITY.md](SECURITY.md) for vulnerability disclosure.

[Unreleased]: https://github.com/mlaify/AttackMap/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mlaify/AttackMap/releases/tag/v0.1.0
