# Changelog

All notable changes to AttackMap will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
