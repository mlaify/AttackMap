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

Status as of v0.4.25.

### Phase 1 — Signal Quality — *ongoing*
Cleaner, more accurate signals; precision-first heuristics (e.g. request-container
gating on injection sinks).

### Phase 2 — Risk Scoring — *shipped, deepening*
Severity × confidence scoring and triage ordering; CVSS-mapped CVE severity.
Deterministic, explainable **exploitability fusion** (0–100 "exploitable now"
score) that ranks route→sink combinations by sink danger, exposure, entry auth,
reachability, and data sensitivity.

### Phase 3 — Distributed System Modeling — *shipped*
Service topology graph and trust boundaries, exported to Mermaid/Graphviz.

### Phase 4 — Protocol Awareness — *shipped*
AT Protocol (Bluesky) analyzer with XRPC/lexicon awareness.

### Phase 5 — Review Mode Maturity — *shipped*
High-quality defensive reports with evidence chains, SARIF, and diff/baseline
gating for CI.

### Phase 6 — Data-Flow & Authorization — *shipped, expanding*
Import-graph taint for injection sinks (SSRF, SSTI, NoSQL, deserialization,
code/command execution, open redirect) and BOLA/IDOR detection, now across
**Python, JS/TS, Go (module-path resolution), and PHP (PSR-4 autoload)**.
Insecure-crypto / weak-randomness (all four languages) and web-hardening
(CORS/CSRF/cookies/CSP/debug) checks shipped. CVE→exploitability fusion links
known-vulnerable deps on a path into the score. Expanding to query-parameter /
RPC-method authorization.

### Phase 7 — Analyzer Ecosystem — *live*
14 community-installable analyzer plugins auto-discovered via entry points;
`attackmap suggest` recommends the right set per repository.

### Phase 8 — Novel Vulnerability Hunting — *shipped*
Detectors for bug classes beyond the taint families (prototype pollution, mass
assignment, JWT weakness, XXE, ReDoS, insecure upload, GraphQL exposure);
within-repo **anomaly / outlier** detection (the odd-one-out among sibling
routes); and **`--hunt`**, an LLM red-team mode that proposes evidence-cited,
human-verifiable exploit-chain *hypotheses* (leads, not detections) — the honest
core of the "find the unknown" ask. `--hunt --verify` adjudicates each lead
(CONFIRMED / REFUTED / NEEDS-REVIEW) against the actual source; `--remediate`
proposes review-first fixes.

### Phase 9 — Product & Workflow — *shipped*
A reusable GitHub **Action + PR bot** (inline SARIF annotations + a summary
comment with the exploitability ranking and diff-gate status), so AttackMap runs
on every pull request.

### Phase 10 — Unknown-Bug Discovery — *shipped*
Finding **novel, un-signatured** bugs by reasoning over a bigger, better-connected
surface and *verifying hard* — everything gated on, or feeding, one asset: a
strong verifier.

- **Multi-pass hunt harness.** `--hunt --verify` became a jury: `--verify-votes`
  (N independent skeptics, majority vote), `--hunt-lenses` (failure-mode-
  specialist generation passes, deduped), `--hunt-rounds` (loop-until-dry with a
  completeness critic seeding each round), `--hunt-budget` (token cap).
- **Within-repo invariant mining.** Signature-free: infer an implicit invariant
  from repeated structure (handlers guard a request before a sink) and flag the
  site that violates it.
- **Recall mode (`--recall`).** Verifier-gated aggressive discovery — widened
  taint knobs + capability-reach enumeration, all marked speculative and routed
  through the verifier/triage filter.
- **Cross-repo / fleet analysis.** `attackmap analyze repoA repoB …` scans a
  fleet, links outbound calls to peer routes into a service graph, and detects
  the bugs that live in the seams: cross-boundary (confused-deputy) flows,
  trust-assumption gaps, and the sibling service that omits a sibling-enforced
  control. Cross-repo findings are speculative until adjudicated.

### Phase 11 — Local AI Integration — *planned*
Optional fully-local LLM narrative (today's `--llm` / `--hunt` use the Anthropic
API / `claude` CLI, or OpenAI / the `codex` CLI).

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
