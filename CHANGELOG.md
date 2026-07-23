# Changelog

All notable changes to AttackMap will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.25] - 2026-07-22

### Added

- **Trust-assumption gaps + cross-repo anomaly (#146d / #149b).** Final phase of
  cross-repo analysis (epic #150) — the second cross-repo acceptance criterion,
  and the last epic lever. Two fleet detectors in `crossrepo.py`, both riding the
  per-repo auth-signal detection now exposed as `anomalies.route_auth_signals`:
  - **Trust-assumption gap** — a state-changing call crosses a link (#146b) to a
    route the callee serves with **no authentication control**. If the caller
    assumes the callee enforces and the callee assumes only trusted callers
    reach it, nobody does. Restricted to write methods (a public read is
    commonly intentional); cites both sides.
  - **Cross-repo anomaly (#149b)** — the fleet-level odd-one-out: among ≥3
    services serving the same resource route, the one that omits an auth control
    a strong majority of its siblings enforce. Reuses the strong-majority split
    from the within-repo anomaly pass.

  Both are **speculative** (a route may be protected by a gateway/mTLS the marker
  heuristics miss) — verifier-gated leads, surfaced in dedicated fleet-summary
  sections and `fleet-summary.json`. Single-repo behavior unchanged. **This
  completes epic #150** (detect unknown bugs).

## [0.4.24] - 2026-07-22

### Added

- **Cross-boundary trust analysis (#146c).** Third phase of cross-repo analysis
  (epic #150) — the confused-deputy detection, and the epic's first cross-repo
  acceptance criterion. Riding the contract links (#146b), a new `crossrepo.py`
  flags a value that repo A forwards across a link which repo B then **trusts**
  into a dangerous sink or an unguarded object access — each repo looks locally
  fine; the bug lives in the seam. Two bases, both reusing B's already-computed
  per-repo signals (no new scanning): **taint** (the linked server route reaches
  an unsanitized dangerous sink) and **bola** (the route is an id-bearing object
  access with no ownership check). Findings are **speculative** — cross-repo
  trust is a judgement call, so they're leads for the #147 verifier to
  adjudicate — and each cites *both* sides (the caller's call site and the
  callee's sink/route). Surfaced in a **Cross-boundary trust** section of the
  fleet summary and in `fleet-summary.json`. Trust-assumption-gap and cross-repo
  anomaly detection land in #146d.

## [0.4.23] - 2026-07-22

### Added

- **Cross-repo contract linking + fleet graph (#146b).** Second phase of
  cross-repo analysis (epic #150). In a multi-repo (`analyze repoA repoB …`)
  run, AttackMap now links one repo's **outbound HTTP calls** to another repo's
  **routes** — the client↔server seam. New `contracts.py` matches by normalized
  path template + method: concrete ids and path params collapse to `*` so
  `/users/123` ↔ `/users/{id}` ↔ `/users/:id` align, and the common
  string-concatenation idiom (`base + "/api/orders/" + oid`, captured up to the
  trailing slash) links to the templated route while staying distinct from the
  bare collection route. Precision guards: a static segment must anchor the path
  (a bare `/{id}` won't link), infra/static routes are excluded, methods must be
  compatible, and client ≠ server. The fleet summary gains a **Cross-repo links**
  table (each link cites both sides — caller `file:line` and served route), and
  a new `fleet-graph.md` renders the repo-to-repo graph as Mermaid. `ExternalCall`
  now captures the HTTP `method`. Single-repo behavior unchanged. Richer linking
  dimensions (RPC callers, shared schemas, queues, DB tables, token iss/aud) and
  the cross-boundary taint / trust-gap detections that ride these links land in
  #146c–#146d.

## [0.4.22] - 2026-07-22

### Added

- **Multi-repo fleet input (#146a).** First phase of cross-repo analysis (epic
  #150). `attackmap analyze repoA repoB …` now accepts two or more repositories:
  each is scanned **independently** into its own `ScanResult` (own root, own
  relative paths — no cross-repo collisions), its reports are written to
  `output/<repo_id>/`, and a top-level `fleet-summary.md` + `fleet-summary.json`
  index the run (per-repo severity counts, top findings, links). New `fleet.py`
  holds the pure `FleetScan`/`FleetRepoResult` container and summary rendering
  (the input surface the later cross-repo phases build on). Repo ids are
  slugified directory names, disambiguated on collision (`api`, `api-2`, …).
  This phase adds **no** cross-repo detection — contract linking, cross-boundary
  taint, and trust-gap analysis land in #146b–#146d. **Single-repo invocation
  (one path) is byte-for-byte unchanged**; single-repo-only flags (`--baseline`,
  `--diff-output`, `--fail-on-new-high`, `--pr-comment`, `--llm`, `--hunt`,
  `--remediate`, `--triage`) are rejected in multi-repo mode until they're made
  fleet-aware.

## [0.4.21] - 2026-07-22

### Added

- **Capability-reach enumeration under `--recall` (#148b).** Second slice of
  recall mode (epic #150). The default taint pass only flags network/template/
  filesystem/redirect sinks when the argument is request-shaped (a constant URL
  or path is fine). Recall now additionally surfaces the reach to the
  *capability itself* — a new `_CAPABILITY_PATTERNS` matches the bare call form
  (`requests.get(…)`, `httpx`/`urlopen`/`axios`/`fetch`, `render_template_string`/
  `Template(`, `open(`, `redirect(`/`res.redirect(`) with **no request-token
  gate**, so it lists reaches a signature-based pass misses. These are
  recall-only, marked `speculative` (their own LOW-severity finding, out of
  `--fail-on-new-high`), deduped against any gated hit at the same line (a
  genuine request-derived sink stays a confirmed finding, not a duplicate), and
  still bounded to what a route reaches. NoSQL is deliberately excluded — a bare
  `.find(` is overwhelmingly JS array iteration without the request-token gate.
  Adjudicate with `--hunt --verify`.

## [0.4.20] - 2026-07-22

### Added

- **Recall mode — `--recall` (#148a).** First slice of verifier-gated aggressive
  discovery (epic #150). Aggressiveness is only useful *behind* a verifier, so
  `--recall` widens the taint walk and marks the extra reach speculative rather
  than asserting it. A new `RecallConfig` (threaded through `analyze_taint`)
  raises the max import-hop depth (2 → 4) and per-route visit cap, and relaxes
  the static-literal-argument suppression the default pass applies to
  eval/exec/deserialize sinks. Any chain surfaced *only* because a knob was
  widened — past the default hop depth, or through a relaxed gate — is tagged
  `TaintChain.speculative` with docked confidence. Speculative chains get their
  own **LOW-severity, clearly-marked finding** per sink kind (`SPECULATIVE
  (recall mode)…`), kept **out of `--fail-on-new-high`** and left for
  `--hunt --verify` / `--triage` to adjudicate. Default (non-recall) behavior is
  byte-for-byte unchanged. Capability-reach enumeration + source/sink expansion
  land in #148b.

## [0.4.19] - 2026-07-22

### Added

- **Within-repo invariant mining (#149a).** First slice of signature-free
  outlier detection (epic #150) — deterministic, no LLM. A new pass in the
  anomaly detector cohorts handlers not by route-path prefix but by the
  *dangerous sink kind they reach* (from the taint pass). When a strong
  majority of those handlers apply an auth/validation guard **before** the sink,
  that pattern is mined as an implicit invariant and every cohort member that
  reaches the same sink kind with no preceding guard is flagged — a new
  `invariant_violation` anomaly whose evidence cites the mined rule (e.g. "9 of
  10 handlers that reach a database (SQL execute) sink apply an auth/validation
  guard before it"). Signature-free: it measures the code against its own norm,
  so it can surface a forgotten guard on a sink pattern no rule anticipates.
  Precision guardrails: a minimum cohort size, a strong-majority split test
  (violators must be a small strict minority), and sanitized chains (#137) are
  excluded so only genuinely undefended flows form the cohort. Confidence scales
  with the size of the agreeing peer group.

## [0.4.18] - 2026-07-21

### Added

- **Loop-until-dry hunting + completeness critic + budget caps (#147c).** Third
  slice of the hunt harness (epic #150). `--hunt-rounds N` loops the generation
  stage for up to N rounds: each round is told what earlier rounds already found
  (so it only emits genuinely new leads), its output is deduped and accumulated,
  and a **completeness critic** pass names untried failure-mode classes / unread
  surfaces / unchecked assumptions to seed the next round. The loop **stops early
  once a round adds nothing new** (loop-until-dry), at the round cap, or when
  `--hunt-budget T` output tokens are spent — whichever comes first. Combines
  with `--hunt-lenses` (each round can fan out per lens) and the #147a
  majority-vote verifier that adjudicates the accumulated set. Token usage across
  every generation/critic/skeptic call is aggregated; the meta records
  `rounds_run`. All opt-in; default `--hunt-rounds 1` is unchanged behavior.

## [0.4.17] - 2026-07-21

### Added

- **Multi-lens hunt generation + cross-pass dedupe (#147b).** Second slice of the
  hunt harness (epic #150). `--hunt-lenses N` fans the generation stage out into
  N independent passes, each primed to specialise in one failure mode
  (auth-bypass, TOCTOU/race, business-logic/IDOR, deserialization,
  SSRF-to-internal, secret-misuse), then **dedupes leads across the passes**
  before the #147a majority-vote verifier runs — surfacing more *unique* novel
  leads than a single generalist pass. Restatements of the same lead collapse
  (title similarity, with shared cited-evidence ids lowering the bar) into one
  freshly re-numbered entry that unions their evidence and lens tags; the dedupe
  (`dedupe_hypotheses`) is pure and deterministic. Opt-in and bounded by the lens
  count (default 1 = single pass); each extra lens costs one generation call.
  `--hunt-lenses N` engages the harness even at `--verify-votes 1`.

## [0.4.16] - 2026-07-21

### Added

- **N-skeptic majority-vote hunt verification (#147a).** First slice of the
  multi-pass hunt harness (epic #150). `--hunt --verify` can now run **N
  independent skeptic passes** (`--verify-votes`, default 3) that each adjudicate
  the *same* fixed, id-keyed hypothesis list (with its cited evidence ids)
  against the real source. A lead is **CONFIRMED only on a strict majority**
  (NEEDS_REVIEW only when a majority flags the evidence insufficient); ties and
  uncertainty are **REFUTED** — so a lead only a single skeptic would confirm is
  dropped, measurably lowering false positives vs. single-vote verify. Token
  usage is aggregated across all jury calls. New
  `hunt_harness.py` (pure, unit-tested `combine_verdicts` + hypothesis/verdict
  parsers + orchestration), a `hunt_generate` pass that emits a machine-readable
  `=== HYPOTHESES ===` list, and a `hunt_skeptic` mode. `--verify-votes 1`
  reproduces the classic single-pass verify. The consensus report groups
  hypotheses by verdict with per-lead vote tallies.
- **Unknown-bug epic plan** documented in `docs/unknown-bug-epic.md` (verifier-
  gated build order across #146–#149).

## [0.4.15] - 2026-07-21

### Added

- **`--triage` LLM mode (#145).** A prioritization pass over the *existing*
  heuristic findings (complementing `--hunt`, which discovers new leads). It has
  the LLM cluster findings by root cause, de-duplicate them, and rank them into a
  shortlist that cites real `finding_id`s — organization, not discovery, under
  the same grounding contract as `--llm`/`--hunt` (it may not invent findings).
  Output is written to `triage.md`. When no LLM backend is available it degrades
  to a **deterministic** score-ordered, root-cause-clustered shortlist (new
  `triage.py`) rather than erroring — the ordering is a pure function of the
  findings (severity → exploitability → score → title), so runs are reproducible
  and diff cleanly. The evidence pack now also carries each finding's stable
  `finding_id`, `score`, and `exploitability`.

## [0.4.14] - 2026-07-21

### Added

- **Query-parameter, RPC-method & GraphQL authorization scoping (#139).** BOLA/
  IDOR detection previously only saw resource ids in the URL path. It now also
  flags object references arriving as an **id-bearing query parameter** (an
  id-shaped query access in the handler body — `req.query.userId`,
  `request.args.get('id')`, `docId: str = Query(...)`), an **RPC method** (AT
  Protocol XRPC `/xrpc/…getRecord`, tRPC `user.byId` — id-fetching object
  operations), and a **GraphQL field** (`user(id: ID!)`, scanning `.graphql`/
  `.gql` files and inline SDL, including custom `schema { query: RootQuery }`
  roots; test/fixture and vendored paths are excluded). RPC/GraphQL object-access
  operations satisfy the datastore-reachability condition intrinsically.
  Authorization is suppressed by the existing ownership markers, and for GraphQL
  by either a `@auth`/`@hasRole`/`@authenticated` schema directive on the field
  or an ownership check in the field's resolver. `BolaCandidate` gains a
  `surface` field (`path_param` / `query_param` / `rpc_method` / `graphql_field`),
  and GraphQL mutations are treated as HIGH (write) findings in both the finding
  and the attack-path narrative.

## [0.4.13] - 2026-07-21

### Added

- **Lockfile version resolution (#143).** A new `lockfiles.py` parses the common
  lockfiles for *exact* resolved versions and the full **transitive** dependency
  tree — `package-lock.json` (v1/v2/v3) and `pnpm-lock.yaml` (npm), `poetry.lock`
  and `uv.lock` (PyPI), and `Cargo.lock` (Cargo). Resolved `DependencyHint`s set
  `resolved=True`, flag `direct` vs transitive, and carry a `via` resolution path
  (`express > body-parser > qs`) reconstructed by a BFS over the dependency
  graph. Multiple installed versions of one package are all preserved, and the
  project's own workspace/local package is excluded from the inventory. A
  lockfile supersedes the range-only manifest in its **own directory** (monorepo
  services don't shadow each other). Go is resolved directly from `go.mod`
  (already exact, `// indirect` flagged); `go.sum` is a checksum history, not the
  build list, so it is not used.
- The CVE scan now queries lockfile-resolved dependencies (direct **and**
  transitive) at their pinned versions instead of guessing a lower bound, and a
  vulnerable transitive dependency is reported with its resolution path
  (`Vulnerability.direct` / `Vulnerability.resolution_path`, surfaced in the
  finding evidence). Resolved versions are queried verbatim, so exact PEP 440
  pins (`1.0.post1`, `1!2.3.0`) aren't normalized away. The existing offline OSV
  cache is unchanged.

## [0.4.12] - 2026-07-21

### Changed

- **Call-graph-aware taint edges (#138).** The import-graph taint walk now prunes
  edges that aren't backed by a real use of the imported symbol: for Python and
  JS/TS, an import edge is kept only when at least one of the names it binds is
  actually referenced/called in the importing file. A dead import (imported but
  never called) no longer fans a route out to that module's sinks — reducing the
  "imported-but-uncalled sink" over-linking called out in the README. The plain
  import-graph remains the fallback for namespace/star/side-effect/dynamic
  imports (no resolvable binding) and for Go/PHP, so recall is preserved.
  Same-file (hop-0) sinks are unaffected — a locally-called sink is still linked
  without any top-level import. On the real-world corpus (OWASP Juice Shop) the
  emitted chain set is unchanged (no regression, no new hangs).

## [0.4.11] - 2026-07-21

### Added

- **Typed provider-signature secret detection (#141).** Added high-confidence
  typed detectors for **OpenAI** (`sk-…`, `sk-proj-…`, `sk-svcacct-…`),
  **GitLab** (`glpat-…`), and **npm** (`npm_…`) key formats, joining the
  existing AWS / GitHub / Slack / Stripe / SendGrid / Mailgun / Twilio / Google /
  Anthropic / PEM / JWT detectors. Each fires at confidence `1.0` with a
  provider-specific `kind`, and the raw value is redacted before it reaches any
  report — including inside the evidence snippet (`evidence_text`), so the full
  credential never survives into `attackmap-report.json`. OpenAI keys are split
  by documented shape (`sk-proj-`, `sk-svcacct-`, and the 48-char alphanumeric
  legacy form), which keeps hyphenated placeholders from being misclassified and
  keeps Anthropic's `sk-ant-…` keys on their own more-specific `kind`.

### Changed

- **Entropy fallback calibration (#141).** The generic high-entropy secret
  detector now suppresses two more well-known non-secret high-entropy shapes,
  extending the #96 charset guard: Subresource-Integrity / lockfile integrity
  digests (`sha256-…`, `sha384-…`, `sha512-…`) and canonical UUIDs. Integrity
  digests are validated as correct-length base64 (not just prefix-matched), so a
  genuine secret that merely starts with `sha256-` is still reported. Typed
  provider matches continue to take precedence over the entropy hit for the same
  span, so a recognized key is never also reported as a bare high-entropy blob.

## [0.4.10] - 2026-07-13

### Added

- **Unauthenticated state-changing route synthesis (#140).** A fusion pass turns
  noisy raw `auth_hints` into a *conclusion*: one precise finding listing the
  public, state-changing (`POST/PUT/PATCH/DELETE`) `public_api` routes that have
  **no authentication/authorization control on their own chain**. Unlike the
  file-windowed `auth_signals` heuristic (which lets a route inherit a
  neighbor's auth code), this resolves the control per route:
  - **Express/Koa/Fastify** — an auth middleware in the route's argument list or
    a global `app.use(...)`/`router.use(...)`.
  - **FastAPI/Flask** — an auth decorator (`@login_required`, `@jwt_required`, …),
    a `dependencies=[Depends(...)]` on the route, `Depends(<auth>)`/`Security(...)`
    in the handler signature, or a router-level dependency.
  - **Spring** — `@PreAuthorize`/`@PostAuthorize`/`@Secured`/`@RolesAllowed` on the
    method or controller class, or a global security policy requiring auth.

  Each evidence line names the route and the resolved chain outcome. Routes
  behind a control produce nothing; the sensitive categories (webhook/admin/
  upload/auth) keep their own dedicated findings, so there's no double-reporting.
  `auth_hints` emission is unchanged. Adds `T1190` mapping.

## [0.4.9] - 2026-07-12

### Changed

- **Taint: sanitizer / validator awareness (#137).** The taint walk now
  recognizes sink-appropriate neutralizers in the sink file — `shlex.quote` /
  `escapeshellarg` (shell), `secure_filename` / path allow-listers (`open`),
  `is_safe_url` (open redirect), `markupsafe.escape` (SSTI), driver escapers
  (SQL), mongo-sanitize (NoSQL). When one is present, the chain is marked
  `sanitized`, its confidence is downgraded below the finding threshold, and the
  neutralizer is recorded in the new `TaintChain.sanitizer_evidence` field.
  Sanitized chains are retained in `scan.taint_chains` for audit but no longer
  raise a HIGH taint finding or earn an exploitability score — cutting a class
  of false positives where input is escaped/validated/bound before the sink.
  Detection is file-granular (matching the import-walk); the table is easy to
  extend via `_SANITIZER_PATTERNS` in `taint.py` (see README).

## [0.4.8] - 2026-07-12

### Added

- **GitHub Actions / CI workflow security scanner (#142).** A new built-in pass
  parses `.github/workflows/*.yml` — a real, previously-unanalyzed attack
  surface — and emits findings for:
  - **script injection** — an attacker-controlled context
    (`github.event.*.{title,body,message,…}`, `github.head_ref`) interpolated
    into a `run:` step, so a crafted issue/PR title runs arbitrary shell (high);
  - **`pull_request_target` + PR-head checkout** — building untrusted fork code
    with the base repo's secrets in scope (high);
  - **unpinned actions** — `uses: org/action@tag|branch` instead of a pinned
    commit SHA (branch/`latest` = medium, semver tag = low);
  - **secret in `run:`** — `${{ secrets.* }}` expanded into a shell step instead
    of passed via `env:` (medium);
  - **over-broad permissions** — `permissions: write-all` at the workflow or job
    level (medium);
  - **self-hosted runner on a PR trigger** — exposing the runner to fork code
    (high under `pull_request_target`, else medium).

  Findings aggregate per issue kind (severity = the max over that kind), carry
  the workflow/job/step context as evidence plus remediation and an ATT&CK
  mapping, and flow through SARIF, the diff gate, and suppression like any other
  finding. A hardened workflow (SHA-pinned actions, scoped permissions, secrets
  via `env:`, no untrusted-context interpolation) produces nothing.

## [0.4.7] - 2026-07-12

### Added

- **Finding suppression (#144).** Silence residual false positives without going
  blind to new signal — the noise-in-CI adoption blocker. Two mechanisms, both
  applied as a post-pass over the assembled findings:
  - **Repo-level baseline** `.attackmap-suppress.yaml` at the repo root, with
    entries keyed by `id` (the stable 16-hex finding id), `rule` (a slug of the
    finding title — the same string as the SARIF `ruleId`), and/or `path`/`paths`
    globs, each carrying a mandatory `reason`. A `path` selector matches a finding
    only when **every** file its evidence cites falls under the glob, so a finding
    that also touches live code is never silently hidden.
  - **Inline directives** `# attackmap:ignore[rule-id] reason` (any comment
    leader — `#`, `//`, `/* */`, …). A directive in a file suppresses findings
    whose cited evidence is covered by it.
  - Suppressed findings are **retained, not dropped**: excluded from
    `--fail-on-new-high` and the console summary, but emitted to
    `attackmap-report.json` under `suppressed_findings` (with reasons) and marked
    with a SARIF `suppressions` array so GitHub Code Scanning shows them as
    suppressed. Suppression counts are printed in the run summary.
  - New flags: `--no-suppress` (ignore all suppressions for a full audit) and
    `--suppress-file PATH` (override baseline auto-discovery).
- **PyYAML** is now a runtime dependency (parses the suppression baseline).

## [0.4.6] - 2026-07-11

### Fixed

- **`--llm-backend auto` now falls back to the subscription CLI when the API SDK
  isn't installed.** Previously, if an API key was set but the `anthropic` /
  `openai` SDK wasn't importable (e.g. a Homebrew install, which doesn't vendor
  `attackmap[llm]`), `auto` chose the API backend and errored instead of using
  the `claude` / `codex` CLI. It now prefers the API backend only when the SDK is
  importable, otherwise uses the CLI (subscription auth) — so `--llm` / `--hunt`
  / `--remediate` work out of the box on brew installs.

## [0.4.5] - 2026-07-11

### Fixed

- **Scan hang on large/generated files (config scanner).** `_extract_*` called
  `_line_of` — which counts newlines from the start on every match — once per
  match, so a large file yielded O(n²) work and effectively hung the scan. Most
  visibly, re-scanning a repo the macOS GUI had scanned before choked on
  AttackMap's own multi-MB JSON reports under `.attackmap-gui/`. Fixed with a
  precomputed line index (O(log n) lookups), a 5 MB config-file size cap, and by
  adding `.attackmap-gui` / `.attackmap` to the skipped directories.

## [0.4.4] - 2026-07-11

Analyzer selection for tool front-ends (the macOS GUI's Analyzers picker).

### Added

- **`attackmap modules --json`.** Emits the installed analyzer modules as a JSON
  array (`name`/`display_name`/`description`/`scope`/`ecosystems`/
  `enabled_by_default`). Network-free (skips the remote module-repository lookup
  the human-readable listing does) so tool / GUI front-ends can offer analyzer
  selection without a GitHub round-trip. Backs the macOS GUI's Analyzers picker.

## [0.4.3] - 2026-07-11

Choose your LLM: model/reasoning/speed selection, plus an OpenAI/Codex provider
alongside Claude. Motivated by the macOS GUI's provider + model pickers.

### Added

- **OpenAI / Codex provider (`--llm-provider {claude,openai}`).** `--llm`,
  `--hunt`, and `--remediate` can now run on OpenAI as well as Claude. Mirroring
  the Claude api/cli split, the OpenAI provider has two backends: `api` (the
  OpenAI SDK's Responses API, using `OPENAI_API_KEY`) and `cli` (`codex exec`,
  using your `codex login` subscription — no API key needed). `--llm-backend
  auto` tries `OPENAI_API_KEY` then the `codex` CLI. The default model is
  `gpt-5-codex`; `--llm-model` passes any model ID through verbatim (e.g.
  `gpt-5.5`, `gpt-5.4`, `gpt-5.4-mini`). `--llm-effort` maps onto the Responses
  API's reasoning effort (xhigh/max clamp to high); `--llm-speed fast` is
  Claude-only and ignored for OpenAI. Install with `pip install attackmap[llm]`
  (now pulls in `openai`) or just have the `codex` CLI on PATH.
- **`--llm-speed {standard,fast}`.** Fast mode (~2.5× output speed, premium
  price) for the LLM phases, applied only on Opus 4.8/4.7 via the API backend
  (other models/backends fall back to standard). Surfaced in the macOS GUI as a
  per-scan Fast toggle alongside model + reasoning pickers.

### Changed

- **`--llm-model` default bumped `claude-opus-4-7` → `claude-opus-4-8`** (current
  Opus tier). Help text now lists the verified selectable models
  (opus-4-8 / fable-5 / sonnet-5 / opus-4-7 / opus-4-6 / sonnet-4-6). `--llm-effort`
  (low→max) is unchanged; the GUI now exposes model + reasoning as pickers.

## [0.4.2] - 2026-07-10

Progress/status polish so no phase runs silently — motivated by the macOS GUI.

### Changed

- **Anomaly / outlier pass now reports determinate progress (#127).** The slow
  tail on large route surfaces drove only an indeterminate spinner; it now
  advances a real bar over the route cohorts (TTY bar + ETA, and determinate
  progress on the `--progress-format json` stream).
- **Live status for the CVE lookup and all LLM phases (#128).** `--cve` and
  every LLM mode (`--llm` / `--hunt` / `--hunt --verify` / `--remediate`)
  previously blocked silently — an LLM call can run for minutes. Each now shows
  an animated spinner + elapsed timer on the TTY (e.g. "Claude is writing the
  defensive review… 0:42") and emits a phase `stage` event the GUI renders with
  a live timer.

## [0.4.1] - 2026-07-08

Patch release enabling the macOS GUI front-end.

### Added

- `--progress-format {auto,json,none}` on `analyze`. `json` emits versioned
  newline-delimited JSON progress events (`begin`/`advance`/`stage`/`done`) to
  stderr for non-TTY front-ends — the foundation for the macOS GUI
  (`mlaify/AttackMap-mac`). `auto` preserves the existing TTY bar; `--no-progress`
  is equivalent to `none`. See `docs/macos-gui-plan.md`.

## [0.4.0] - 2026-07-06

Fourth feature release — **precision, multi-language reach, and workflow**. The
taint engine now spans **Python, JS/TS, Go, and PHP**; the front-end (routes,
auth attribution, SQL) is materially more precise; exploitability fuses known
dependency CVEs; and AttackMap gains a GitHub PR bot, LLM-assisted remediation,
and adjudicated (`--hunt --verify`) hypothesis hunting. Every feature was
validated on real codebases (Bluesky, Juice Shop, Apple OSS, PocketBase,
BookStack).

### Added

- **Agentic hunt verification `--hunt --verify` (#122).** Upgrades `--hunt` to
  adjudicate each hypothesis **CONFIRMED / REFUTED / NEEDS HUMAN REVIEW**
  against the *actual source* at cited locations. Because the LLM backend is
  sandboxed to the AttackMap workspace (can't read the target repo), AttackMap
  extracts the cited route/sink/finding code excerpts (line ± context) and
  feeds them to the verify pass, which is instructed to refute leads the shown
  code contradicts (parameterized query, constant arg, auth present, static-file
  sink) and to say NEEDS-REVIEW when the excerpt is insufficient — rather than
  confirm what it can't see.
- **Crypto-weakness detection for Go and PHP (#120).** The insecure-crypto pass
  now covers Go (`md5.New`/`md5.Sum` over a security value, `des`/`rc4.NewCipher`
  and `crypto/des`|`rc4` imports, `math/rand`-exclusive RNG for secrets) and PHP
  (`mcrypt_*` / `MCRYPT_DES|RC4|…`, `CURLOPT_SSL_VERIFYPEER => false`, `'verify'
  => false`) — completing the crypto surface for the languages added in
  #102/#103. Ambiguous forms are excluded to avoid false positives (Go
  `rand.Int`/`rand.Read` overlap the secure `crypto/rand`, so only math-only
  funcs are flagged).
- **LLM-assisted remediation `--remediate` (#106).** Proposes concrete,
  review-first fixes per finding — a suggested diff/snippet when the code is in
  evidence, else a precise instruction (file + what to change) — grounded in the
  same evidence contract as `--llm`/`--hunt` (cite ids, no invented code, no
  exploit code, flags where human judgment is needed). Output to
  `remediation.md` under a "suggestions to review, not auto-applied" banner.
- **GitHub PR bot (#105).** A reusable composite Action (`action.yml`) that
  installs AttackMap, scans, uploads SARIF (inline annotations on the PR's
  *Files changed* tab), and renders a Markdown **PR summary comment** — new /
  resolved findings vs. baseline, HIGH-gate status, and the top "most
  exploitable now". New `--pr-comment <path>` CLI flag emits the comment
  (with the diff when `--baseline` is set); a documented workflow posts it via
  `actions/github-script`.
- **PHP language support (#103).** `.php` is a recognized language with route
  extraction for Laravel (`Route::get('/x', …)`, `$router->…`), Slim
  (`$app->get('/x', …)`), and Symfony attributes/annotations (`#[Route('/x')]` /
  `@Route`), leading-slash gated — **and import-graph taint**: `use Ns\Class`
  is resolved via composer.json PSR-4 autoload (plus `require`/`include`), so a
  route reaches sinks in its controllers/models. PHP sinks: `mysqli_query` /
  `pg_query` / PDO `->query|exec` / Laravel `DB::select|raw|…` (with a
  PHP-tailored parameterized-query gate — flags `.`-concatenation, `"…$var…"`
  interpolation, and `sprintf`, not the `+`/comma heuristic that misreads PHP),
  `system`/`shell_exec`/`passthru`/`proc_open`/`popen`, and `unserialize`.
  Validated on BookStack (254 routes; route→controller resolves via PSR-4 across
  337 files; 0 taint chains — it uses parameterized Eloquent throughout,
  correctly not flagged).
- **Go language support (#102).** `.go` is a recognized language with route
  extraction across the common Go web frameworks — net/http
  (`mux.HandleFunc("/x", h)`), gin/echo (`r.GET("/x", h)`), chi/fiber
  (`r.Get("/x", h)`), leading-slash-gated — **and import-graph taint**: Go
  imports are resolved module-path-relative (via `go.mod`) so a route reaches
  sinks in imported packages, with Go dangerous sinks `db/tx/stmt.Query|Exec`
  (parameterized-query-gated; `fmt.Sprintf`-built SQL still flagged) and
  `exec.Command`. Validated on PocketBase (108 routes; 0 taint chains — it uses
  parameterized `dbx` throughout, correctly not flagged).
- **Generated/declaration files excluded from scanning (#95 follow-up).** `*.d.ts`
  TypeScript declaration stubs join the vendored/minified exclusion, and the
  taint indexer now honors it — removing a class of false sinks (PocketBase's
  19k-line `types.d.ts` had produced 30 spurious `exec` chains).
- **CVE → exploitability fusion (#104).** The exploitability score now folds in
  known-vulnerable dependencies: each route→sink path file's bare imports are
  resolved to package names and matched against the `--cve` advisory set, so a
  public route reaching a sink through a known-vulnerable library version scores
  higher (amplifier by CVE severity: high +15 / medium +8 / low +3, with the
  matched package and advisory ids cited in the factor). Completes the CVE half
  of #79.

### Changed

- **Test/vendored routes excluded from the attack surface (#113).** Route
  extraction now skips test/spec and vendored/minified files by default —
  Laravel/Go/pytest test helpers call `.get('/x')` heavily, inflating the route
  count and attack surface (BookStack went 868 → 254 real routes; test routes
  no longer appear). `ATTACKMAP_INCLUDE_TESTS` / `ATTACKMAP_INCLUDE_VENDORED`
  opt back in.
- **Handler-aware taint seeding for central route registration (#107).** For
  JS/TS apps that register many handlers in one hub file (`server.ts` importing
  ~100 route modules), taint now seeds from the module that *defines* a route's
  handler (`app.get('/profile', getUserProfile())` → `routes/userProfile.ts`)
  instead of walking the hub's entire import set. This connects routes to their
  real code precisely and kills the import-hub fan-out (on OWASP Juice Shop:
  the real `GET /profile → eval` RCE is now found via the correct 0-hop path,
  and total chains are 22 credible flows vs. 856 with a naive visit-cap raise).
  Inline handlers and Python decorators are unaffected (they co-locate handler
  and route, so seeding stays on the route file).

- **Parameterized-query recognition (#101).** The `sql_execute` taint sink no
  longer flags safe parameterized queries — bind-param calls
  (`cursor.execute("… %s", (id,))`, `client.query("… $1", [id])`), builder
  terminals (Kysely `.execute()`), and placeholder-only literals. Raw
  string-built SQL (concatenation, f-strings, template interpolation,
  `.format()`, `%`-format) is still flagged. Cuts SQLi false positives.
- **Framework auth-middleware awareness (#100).** Auth attribution now
  recognizes custom middleware factories (`webhookAuth({secret})`,
  `apiKeyAuth()`, `tenantGuard()` — any CamelCase `*Auth(`/`*Guard(` call),
  global installs (`app.use(requireAuth)`), and guards passed as a route
  argument (`router.get('/x', requireAuth, handler)`). Previously these
  authenticated routes were reported as "no auth" (the Bluesky KWS-webhook
  false positive), skewing the BOLA, anomaly, and exploitability passes.

### Fixed

- **Route extraction no longer mistakes method calls for routes (#99).**
  Express-style `x.<verb>("s")` extraction is now gated on an app/router-like
  receiver or a URL-shaped path (leading `/` or `*`), so `headers.delete
  ("content-type")`, `params.get("request_uri")`, and config lookups like
  `settings.get("application.favicon")` are no longer emitted as HTTP routes.
  On real repos this cut route noise substantially (juice-shop 455 → 273 real
  routes; a client-only UI 36 → 0). First of the Theme A precision fixes.

## [0.3.2] - 2026-07-05

Patch release — precision fixes surfaced by real-world testing against Apple's
`apple-oss-distributions` (WebInspectorUI).

### Fixed

- **Weakness/secret precision fixes from real-world testing (#94, #95, #96).**
  Surfaced scanning Apple's `apple-oss-distributions` (WebInspectorUI):
  - `prototype_pollution` no longer fires on prototype-chain *reads*
    (`x.prototype.__proto__.constructor`) or on `__proto__` inside `//`
    comments — it now requires an assignment (write) context. (#94)
  - Per-file weakness passes and the taint indexer now skip vendored/minified
    third-party code (`node_modules`, `vendor`, `third_party`, `External/`,
    `*.min.js`, …) via `srcpaths.is_vendored_file`; `ATTACKMAP_INCLUDE_VENDORED`
    opts back in. (#95)
  - The high-entropy secret heuristic no longer flags well-known charset
    constants (base64/base32/hex alphabets, e.g. a source-map `base64Digits`
    string). (#96)

  On WebInspectorUI this cut the noise from 5 weaknesses + 1 "secret" (all false
  positives or vendored) to 1 genuine finding, with no loss on juice-shop.

## [0.3.1] - 2026-07-05

Patch release — a precision fix surfaced by real-world testing against OWASP
Juice Shop.

### Fixed

- **Taint: deserialization/eval/exec sinks no longer over-fire on static/local
  arguments (#91).** The "dangerous-regardless" sink families are now suppressed
  when the call argument is provably static — a string literal or a literal-path
  file read (e.g. `yaml.load(fs.readFileSync('./swagger.yml'))`) — rather than
  attacker-influenced. Found via OWASP Juice Shop, where one benign startup
  `yaml.load` in a hub module fanned out to 113 of 123 taint chains (all scored
  CRITICAL); this cuts it to 10 while preserving the real `eval()` RCE and the
  variable-path `yaml.load('./data/'+key)` chains. Same class as #85.

## [0.3.0] - 2026-07-05

Third feature release — the vulnerability-hunting arc. Adds injection-sink and
novel vuln-class detection, insecure-crypto and web-hardening checks, BOLA/IDOR,
within-repo anomaly/outlier detection, a deterministic exploitability score, an
LLM vulnerability-hypothesis mode (`--hunt`), and a live scan progress bar —
while tightening precision (test/spec and infra/static-route exclusion) and
holding the precision-first line on every detector.

### Added

- **Injection sink detection (#68).** The taint engine gained four new
  dangerous-sink families, each producing a dedicated ATT&CK-mapped finding
  when reachable from a route: `unsafe_deserialization` (pickle, yaml.load
  without SafeLoader, marshal, node-serialize), `ssti` (server-side template
  injection), `ssrf` (request-derived outbound HTTP), and `nosql_injection`
  (request object as a Mongo filter, or `$where`). Args-gated sinks require a
  member access / subscript on a request container (`req.query.url`) rather than
  a bare identifier — validated against a real repo, this cut 607 false SSRF
  hits to 0 while preserving genuine detection.
- **Broken object-level authorization (BOLA/IDOR) detection (#69).** Flags
  routes that take a resource id in the path, reach a datastore, and have no
  ownership/authorization check nearby. Write methods are HIGH, reads MEDIUM;
  emits a Finding (T1190) and a dedicated attack-path narrative.
- **Insecure cryptography & weak randomness detection (#70).** A per-file pass
  flags weak password hashing, broken ciphers (DES/3DES/RC4/Blowfish), ECB mode,
  static IV/salt literals, insecure RNG for secrets, and insecure TLS
  (`verify=False`, `rejectUnauthorized:false`, …), each an ATT&CK-mapped finding
  under `scan.crypto_weaknesses`. Noisy families are context-gated and cipher
  tokens matched case-sensitively (so the French "des" isn't a hit).
- **Web-hardening detection (#71).** Flags positively-present misconfigurations —
  wildcard CORS *with* credentials, disabled CSRF, insecure cookie flags,
  `unsafe-inline`/`unsafe-eval` CSP, and shipped debug mode — under
  `scan.web_hardening_issues`.
- **Novel vulnerability-class detectors (#77).** A per-file `weaknesses` pass for
  bug classes beyond the taint/crypto/web families, under `scan.code_weaknesses`:
  prototype pollution, mass assignment, JWT weakness (alg=none / unverified),
  XXE, ReDoS (regex-context-gated so arithmetic isn't flagged), insecure upload
  (client-controlled filename/path), and GraphQL introspection/playground
  exposure. Plus `open_redirect` as a taint sink.
- **Anomaly / outlier detection (#78).** Surfaces the odd-one-out among sibling
  routes — an `auth_outlier` / `validation_outlier` / `method_outlier` that
  breaks the norm its resource cohort establishes — under `scan.anomalies`.
  Confidence scales with cohort consistency; only strict-minority deviations in
  structurally-real cohorts are flagged.
- **Exploitability fusion (#79).** Fuses sink danger, exposure, entry-route auth,
  reachability (hops), and data sensitivity at the sink into a deterministic,
  fully-explainable 0–100 "exploitable now" score per route→sink path. Scores
  attach to taint findings (`exploitability` + `exploitability_tier`) and rank a
  new `attackmap-exploitability.md` / `exploitability` JSON section; the console
  summary leads with the most exploitable. Conventional infra/static routes
  (robots.txt, `.well-known`, health) are excluded from the ranking so a
  mis-linked chain doesn't cry wolf.
- **LLM vulnerability-hypothesis mode `--hunt` (#80).** Has Claude reason over
  the full evidence pack (surfaces, assets, controls, taint chains,
  exploitability scores, anomalies) as a red-team analyst and propose ranked,
  human-verifiable exploit-chain **hypotheses** to `vulnerability-hypotheses.md`.
  Framed as leads not detections (unmissable banner), same evidence-citation
  grounding as `--llm`, with honesty guardrails: no CVE assignment, no exploit
  code, confidence-tiered, and each lead states what a human must verify. Shares
  `--llm`'s auth/backend resolution.

- **Live scan progress + ETA (#36).** `attackmap analyze` now shows a
  self-updating progress bar with percentage, file count, and estimated time
  remaining during the per-file pass, plus an animated spinner with elapsed time
  for the indeterminate tail analyzers (taint, SBOM, authorization, anomalies) —
  so a multi-minute monorepo scan visibly makes progress instead of looking
  hung. TTY-aware (silent when stderr isn't a terminal); `--no-progress` forces
  it off. Zero new dependencies.

### Changed

- **Test/spec files excluded from heuristic passes by default (#67).** The
  crypto, web-hardening, novel-vuln, and anomaly passes skip `tests/`,
  `__tests__/`, `*.test.*`, `test_*.py`, and similar, since dangerous-looking
  patterns in test scaffolding are rarely real exposure. `ATTACKMAP_INCLUDE_TESTS=1`
  opts back in.

## [0.2.0] - 2026-07-05

Second feature release. Turns AttackMap from an architecture/asset modeler into
a tool that also traces data flow, checks authorization, and inventories
dependency risk — while adding CI-grade output formats.

### Added

- **Data-flow / taint analysis (#45).** A lightweight import-graph walk (Python
  + JS/TS) traces request-to-sink reachability up to two hops from each route,
  emitting `TaintChain` signals for SQL execute, subprocess/shell, eval, exec,
  and dynamic file-open sinks, and folding them into attack-path narratives.
- **SBOM inventory (#48).** Parses direct dependencies from `pyproject.toml`,
  `requirements.txt`, `package.json`, `go.mod`, `Cargo.toml`, and
  `composer.json` into `DependencyHint` signals across five ecosystems.
- **CVE cross-reference (`--cve`, #60).** Opt-in OSV.dev lookup for every SBOM
  entry, with an on-disk cache (`~/.attackmap/cache/osv/`, 24h TTL) and
  offline-tolerant fallback. Emits one finding per vulnerable dependency,
  CVSS-mapped to severity.
- **`attackmap suggest` (#46).** Recommends the analyzer plugins a repository
  actually needs (by manifests, extensions, and framework markers), with an
  optional `--install`.
- **Watch / diff mode (#47).** `--baseline`, `--diff-output`, and
  `--fail-on-new-high` produce a New/Persisted/Resolved diff against a prior
  report and can gate a PR on newly-introduced HIGH findings. Findings now carry
  a stable id in `attackmap-report.json`.
- **SARIF 2.1.0 output (#42).** Every scan writes `attackmap-report.sarif` for
  GitHub Code Scanning, VS Code, and other SARIF consumers.
- **Mermaid + Graphviz export (#49).** Attack paths and service topology render
  as `attackmap-paths.md` / `attackmap-topology.md` (Mermaid) and `.dot`
  (Graphviz).
- **Hard-coded secret detection (#39)** in source and config, with
  `<first-4>…<last-4>` redaction and entropy heuristics.
- **Config-file analyzer (#43).** Extracts DB connection strings, service URLs,
  and secret-shaped literals from YAML / TOML / JSON / INI / `.env`.
- **`attackmap-analyzer-iac` (#40).** New official plugin: Dockerfile hardening,
  docker-compose service graphs, GitHub Actions workflows, `.env` templates, and
  shell installers. Now bundled in the `[all]` extra (14 plugins total).
- **Route-scoped auth attribution (#41).** Auth signals are attributed per-route
  instead of via a global fallback, sharpening BOLA and missing-auth findings.
- **Eval rubric v2 (#44).** Keyword-group + pattern-based scoring with per-repo
  fixture splits (Bluesky atproto / PDS / social-app).

### Changed

- The `[all]` extra now installs 14 analyzer plugins (adds `attackmap-analyzer-iac`).
- `claude` CLI backend errors now surface the real message (e.g. "Not logged in
  · Please run /login") plus a hint, instead of the misleading `subtype`
  ("success") field.

### Fixed

- Container image and Homebrew publishing pipelines: the GHCR build now waits for
  PyPI before building and tags images from the resolved version; the Homebrew
  formula drops the `anthropic`/`jiter` tree (unbuildable in Homebrew's sandbox),
  depends on `rust` for `pydantic-core`, and passes `brew audit`/`brew style`.

## [0.1.1] - 2026-06-25

### Changed

- **`[all]` extra now pins each analyzer to a minimum version.** All
  bundled plugins carry `>=0.1.0`; `attackmap-analyzer-node-service` is
  bumped to `>=0.2.0` to guarantee users installing `attackmap[all]`
  pick up the deepened TS/Node service coverage (NestJS decorators,
  NextJS routes, tRPC, XRPC handlers, workspaces, BullMQ/Kafka workers,
  `EXPO_PUBLIC_*` client-bundled secret rule).

No core code changes. Users who `pip install --upgrade attackmap[all]`
are now guaranteed the newer analyzer bundle.

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

[Unreleased]: https://github.com/mlaify/AttackMap/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/mlaify/AttackMap/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/mlaify/AttackMap/releases/tag/v0.1.1
[0.1.0]: https://github.com/mlaify/AttackMap/releases/tag/v0.1.0
