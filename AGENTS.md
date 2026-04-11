# AGENTS.md

## Project
AttackMap is an open-source defensive security analysis engine.

Its purpose is to help engineers understand and improve the security of real systems by:
- inferring architecture
- mapping attack surface
- identifying trust boundaries
- linking evidence into risk chains
- highlighting strengths and weaknesses
- generating actionable defensive recommendations

AttackMap is not a generic chatbot, not a simple code scanner, and not an exploit-generation tool.

## Product direction
AttackMap should evolve into a strong, general-purpose defensive security product that can analyze:
- applications
- services
- distributed systems
- protocol-driven systems
- config-heavy systems
- infrastructure and deployment surfaces over time

AttackMap should work well for:
- Bluesky / ATProto
- PHP / Laminas / Omeka S
- Node / TypeScript service architectures
- and eventually any ecosystem supported by analyzers

## Core philosophy

### Evidence first
All meaningful output should be grounded in:
- analyzer-emitted structured signals
- deterministic parsing and modeling
- explicit evidence chains
- explainable heuristics

Do not invent evidence.

### Defensive, not offensive
AttackMap is a defensive analysis product.
It should:
- map architecture
- surface strengths
- identify weaknesses
- highlight risky trust chains
- recommend improvements
- support engineering triage

It should not:
- generate exploit instructions
- produce offensive attack playbooks
- optimize for compromise

### Explainability over noise
AttackMap should help a human understand:
- what was observed
- what was inferred
- why it matters
- what to improve next

### Strengths matter
A good review includes:
- positive controls already present
- architectural strengths
- auth/signing/validation signals
- boundaries that appear well-designed

### Incremental, maintainable engineering
Prefer small, reviewable improvements over broad rewrites.

## Current architecture
AttackMap is organized as:
- `attackmap` = core engine
- external analyzers live under GitLab subgroup:
  - `matthewd.xyzAI/attackmap-analyzers`

Core owns:
- CLI orchestration
- analyzer discovery/loading
- normalized analysis models
- merge behavior
- graph/service/trust modeling
- findings generation
- attack path and evidence-chain generation
- defensive review output
- scoring and prioritization

Analyzers own:
- applicability detection
- structured signal extraction
- analyzer-scoped notes/hints where appropriate

Analyzers must not:
- render final reports
- own global scoring policy
- directly control CLI formatting
- bypass the core merge/modeling pipeline

## Analyzer design rules
Analyzers should be:
- broad when possible
- layered when useful
- heuristic but explainable
- easy to test with fixtures

Preferred analyzer layering:
- language analyzers
- framework analyzers
- application/protocol overlays

Examples:
- `php-web`
- `php-laminas`
- `omeka-s`
- `node-service`
- `atproto`

Keep analyzers focused on structured extraction.
Do not move core reasoning into analyzers.

## Output quality rules
AttackMap output must strive to be:
- evidence-backed
- prioritized
- readable
- actionable
- appropriately uncertain

Prefer:
- “observed” vs “inferred” distinctions
- confidence labels
- provenance where available
- source-quality weighting
- fewer stronger findings over many noisy ones

Down-rank or exclude low-quality sources such as:
- `tests/`
- `__tests__/`
- `fixtures/`
- `mocks/`
- `examples/`
unless a task explicitly asks to analyze them.

## Defensive review expectations
AttackMap should increasingly produce a high-quality defensive review that includes:
- system overview
- attack surface
- strengths
- weaknesses / risk hotspots
- key evidence chains
- recommendations
- analyst notes

Good recommendations are:
- concrete
- prioritized
- tied to evidence
- useful to engineers

## Risk reasoning expectations
When ranking or prioritizing, prefer explainable scoring based on:
- exposure
- privilege sensitivity
- reachability
- trust-boundary crossing
- chain depth
- confidence
- operational impact

Scoring should remain in core, not in analyzers.

## Bluesky / ATProto guidance
Bluesky and ATProto are an important motivating domain for AttackMap.

When working on Bluesky/ATProto support, optimize for:
- service boundary detection
- inter-service trust modeling
- XRPC / lexicon surface inference
- identity / signing / auth hotspots
- datastore and downstream dependency chains
- distributed system reasoning

Do not treat Bluesky work as a one-off special case unless necessary.
Prefer reusable general capabilities first, then thin protocol/application overlays.

## Coding preferences
- prefer minimal diffs
- preserve current CLI behavior unless explicitly asked to change it
- avoid unnecessary dependencies
- keep functions focused and readable
- favor explicit data models
- add comments only where they improve clarity
- avoid over-engineering
- keep naming consistent with the current architecture

## Testing expectations
When making changes:
- update or add focused tests
- use small fixtures
- run the smallest relevant verification set
- summarize what was verified

Prefer:
- unit tests for analyzers and merge/scoring logic
- fixture-based tests for real-world patterns
- targeted integration-style checks when appropriate

## Workflow expectations
Before changing code:
1. inspect relevant files
2. summarize current behavior
3. identify the smallest useful change
4. implement that change
5. run relevant tests
6. summarize changed files, commands run, results, and remaining risks

Do not jump into large rewrites without being asked.

## Documentation expectations
Keep docs aligned with implementation.
When architecture changes materially, update:
- README if user-facing behavior changes
- analyzer contract docs if analyzer-facing behavior changes
- examples or fixtures if they are part of validation

## Current priorities
In general, prioritize:
1. output credibility
2. source-quality weighting
3. observed vs inferred clarity
4. hotspot ranking and recommendation quality
5. distributed system/service-boundary modeling
6. protocol-aware overlays
7. analyzer ecosystem growth

## Definition of done
A task is done when:
- the patch is focused and reviewable
- current behavior is preserved unless intentionally changed
- tests are updated and relevant verification is run
- output quality or modeling quality is measurably improved
- limitations are stated honestly
- the next incremental step is clear