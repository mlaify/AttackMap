# AttackMap Vision

## What AttackMap Is

AttackMap is an open-source defensive security analysis engine that helps engineers understand, evaluate, and improve the security of real systems.

It models architecture, maps attack surfaces, traces trust boundaries, identifies risk chains, highlights strengths, and recommends improvements — all in a transparent, reproducible, and explainable way.

## Why AttackMap Exists

Modern systems are distributed, protocol-driven, config-heavy, and service-oriented. Most tools are expensive, opaque, and shallow.

AttackMap exists so anyone can understand and improve their system’s security without relying on black-box tools.

## Core Philosophy

### Evidence First
All findings must be grounded in real signals and analyzers.

### Explainability Over Noise
Every insight should answer:
- Why this matters
- How we know
- What to do next

### Strengths Matter
Good security includes recognizing what is already working.

### Defensive, Not Offensive
AttackMap focuses on risk understanding and improvement, not exploitation.

### Open and Accessible
Free, open-source, local-first, and community-driven.

## What AttackMap Does

### Understand
Languages, frameworks, services, protocols, entry points, data stores, and
third-party dependencies (with an SBOM inventory and optional OSV.dev CVE
cross-reference).

### Model
Service graphs, trust boundaries, request-to-sink data flow, privilege and
object-ownership relationships, protocol surface.

### Reason
Exposure, trust, sensitivity, reachability, boundary crossings, injection sinks,
and broken object-level authorization.

### Report
System overview, attack surface, strengths, weaknesses, evidence chains, and
recommendations — as Markdown, JSON, SARIF, and Mermaid/Graphviz diagrams, with
an optional LLM-narrated review and a PR-diff mode.

## Roadmap

Status as of v0.2.0.

### Phase 1 — Signal Quality — *ongoing*
Cleaner, more accurate signals; precision-first heuristics (e.g. request-container
gating on injection sinks).

### Phase 2 — Risk Scoring — *shipped, deepening*
Severity × confidence scoring and triage ordering; CVSS-mapped CVE severity.

### Phase 3 — Distributed System Modeling — *shipped*
Service topology graph and trust boundaries, exported to Mermaid/Graphviz.

### Phase 4 — Protocol Awareness — *shipped*
AT Protocol (Bluesky) analyzer with XRPC/lexicon awareness.

### Phase 5 — Review Mode Maturity — *shipped*
High-quality defensive reports with evidence chains, SARIF, and diff/baseline
gating for CI.

### Phase 6 — Data-Flow & Authorization — *shipped, expanding*
Import-graph taint for injection sinks (SSRF, SSTI, NoSQL, deserialization,
code/command execution) and BOLA/IDOR detection. Expanding to more languages,
query-parameter/RPC-method authorization, and insecure-crypto / web-hardening
checks.

### Phase 7 — Analyzer Ecosystem — *live*
14 community-installable analyzer plugins auto-discovered via entry points;
`attackmap suggest` recommends the right set per repository.

### Phase 8 — Local AI Integration — *planned*
Optional fully-local LLM narrative (today's `--llm` uses the Anthropic API or the
`claude` CLI).

## Long-Term Vision

AttackMap becomes the open-source standard for defensive system security analysis.

Anyone can:
- run it locally
- understand their system
- identify risks
- improve security
- contribute analyzers

## Tagline

AttackMap — Understand your system. Defend it better.
