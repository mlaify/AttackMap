# AttackMap

**AI-assisted defensive security analysis for codebases.** AttackMap reads your
repository, models its assets and defensive controls, traces request-to-sink
data flow, inventories dependencies and their known CVEs, and produces an
evidence-grounded security review with MITRE ATT&CK mappings and
detection-engineering hints — finding the cross-cutting weaknesses that
single-file scanners miss.

Built for AppSec engineers, SOC and detection-engineering teams, and engineering
managers who need to triage an unfamiliar codebase.

> Story over checklist. Asset-aware. Control-absence-aware. Evidence-grounded.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![PyPI](https://img.shields.io/pypi/v/attackmap.svg)](https://pypi.org/project/attackmap/)

> **Status: beta (v0.4.18).** Core engine and 14 analyzer plugins are published
> to PyPI, Homebrew, and GHCR and validated against real-world codebases.
> AttackMap is heuristic by design — findings are confidence-tiered evidence,
> not proof. See [Project status](#project-status) for what's solid and what's
> still maturing.

### The macOS app

Prefer a GUI? AttackMap ships a native macOS front-end that drives this CLI and
renders every result view — install with `brew install --cask mlaify/tap/attackmap-app`
(the cask depends on the `attackmap` formula, so this pulls the CLI too).

| Overview | Exploitability |
|---|---|
| [![AttackMap macOS app — overview](https://raw.githubusercontent.com/mlaify/AttackMap/main/docs/screenshots/04-overview.png)](https://docs.matthewd.xyz/gui/) | [![AttackMap macOS app — exploitability](https://raw.githubusercontent.com/mlaify/AttackMap/main/docs/screenshots/06-exploitability-ranked.png)](https://docs.matthewd.xyz/gui/) |

*Scanning OWASP Juice Shop. Full walkthrough in the [macOS app docs](https://docs.matthewd.xyz/gui/); source at [mlaify/AttackMap-mac](https://github.com/mlaify/AttackMap-mac).*

---

## Quickstart

Install with all bundled analyzers:

```bash
pip install "attackmap[all]"
```

Run a review on a repository:

```bash
attackmap analyze /path/to/repo --output reports
```

Optional: add an AI-narrated review using Claude. Either set an
`ANTHROPIC_API_KEY`, or log in once with the [Claude Code CLI](https://docs.claude.com/claude-code)
to use your existing Pro/Max subscription:

```bash
attackmap analyze /path/to/repo --output reports --llm
```

Prefer OpenAI? Add `--llm-provider openai` to run the same review/hunt/remediate
phases on OpenAI. Set `OPENAI_API_KEY` for the Responses API, or log in once with
the [`codex` CLI](https://developers.openai.com/codex) to use your subscription
(`--llm-backend cli`). Default model is `gpt-5-codex`; `--llm-model` accepts any
model ID verbatim.

Read `reports/defensive-review.md` (heuristic) and `reports/defensive-review-llm.md`
(LLM-narrated) side by side.

**Multi-repo (fleet) scan.** Pass two or more repositories to scan a whole fleet
in one run:

```bash
attackmap analyze ./service-a ./service-b ./gateway --output reports
```

Each repo is scanned independently into its own `reports/<repo>/` directory, and
a `reports/fleet-summary.md` (+ `.json`) indexes the run with per-repo severity
counts and top findings. Single-repo behavior is unchanged. This is the
foundation for cross-repo seam analysis — contract linking, cross-boundary
taint, and trust-gap detection — which builds on the fleet view (epic #150).

---

## Install

### From PyPI

```bash
pip install attackmap                  # core only
pip install "attackmap[llm]"           # add LLM narrative support
pip install "attackmap[all]"           # core + LLM + all 14 analyzer plugins
```

You can also install individual analyzer plugins on demand:

```bash
pip install attackmap-analyzer-python attackmap-analyzer-go
```

Not sure which plugins your repo needs? Let AttackMap tell you:

```bash
attackmap suggest ./path/to/repo          # print ranked pip lines
attackmap suggest ./path/to/repo --install # and install them (prompts once)
```

`suggest` inspects the repo's manifest files, extensions, and directory layout
and recommends only the plugins that would give it deeper signal — useful
when you want a smaller install footprint than `[all]`.

### With Docker

```bash
docker run --rm -v "$PWD:/src" ghcr.io/mlaify/attackmap:latest analyze /src --output /src/reports
```

### With Homebrew (macOS)

```bash
brew install mlaify/tap/attackmap
```

### From source

```bash
git clone https://github.com/mlaify/AttackMap.git
cd AttackMap
pip install -e ".[llm]"
```

---

## What you get

Every `attackmap analyze` run writes:

| File | What it is |
|---|---|
| `architecture.md` | High-level summary of the repository |
| `attack-surface.md` | Surfaces classified by category, exposure, and risk |
| `defensive-review.md` | Notable Observations, Asset Inventory, Defensive Controls, Strengths, Weaknesses, Detection Opportunities, Recommendations |
| `defensive-review.json` | Structured equivalent (schema v1.2.0) |
| `review-context-pack.json` | Structured evidence pack consumed by the LLM stage |
| `attackmap-report.json` | Everything bundled |
| `attackmap-report.sarif` | SARIF 2.1.0 log — ingestable by GitHub Code Scanning, VS Code, and other SARIF consumers |
| `attackmap-paths.md` | Mermaid flowcharts of each attack path — renders inline on GitHub |
| `attackmap-topology.md` | Mermaid graph of the service topology, with edge kinds styled per relationship type |
| `attackmap-paths.dot` / `attackmap-topology.dot` | Graphviz DOT versions of the two diagrams — feed into `dot -Tsvg` for slide-quality graphics |
| `attackmap-exploitability.md` | "Most exploitable now" — route→sink paths ranked by fused 0–100 score, each with its factors |
| `defensive-review-llm.md` *(with `--llm`)* | Claude-narrated review |
| `defensive-review-llm.meta.json` *(with `--llm`)* | Backend, model, token usage |
| `vulnerability-hypotheses.md` *(with `--hunt`)* | LLM-generated, evidence-cited exploit-chain **hypotheses** to confirm (leads, not detections) |
| `triage.md` *(with `--triage`)* | Clustered, de-duplicated, ranked shortlist of the existing findings (LLM-backed; deterministic fallback) |

### GitHub Code Scanning integration

Drop this into `.github/workflows/attackmap.yml` to get AttackMap findings inline on every PR:

```yaml
name: AttackMap
on: [pull_request, push]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install "attackmap[all]"
      - run: attackmap analyze . --output reports
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: reports/attackmap-report.sarif
          category: attackmap
```

### PR bot (reusable Action + summary comment)

AttackMap ships a composite **GitHub Action** (`action.yml`) that installs it,
scans, uploads SARIF (for inline annotations on the PR's *Files changed* tab),
and renders a Markdown **PR summary comment** (new/resolved findings, gate
status, and the top "most exploitable now"). Wire it up to post the comment on
each PR:

```yaml
name: AttackMap PR review
on: pull_request
permissions:
  contents: read
  security-events: write   # SARIF upload
  pull-requests: write     # summary comment
jobs:
  attackmap:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - id: scan
        uses: mlaify/AttackMap@v1
        with:
          path: .
          fail-on-new-high: "true"   # optional gate (needs a baseline)
      - uses: actions/github-script@v7
        if: always()
        with:
          script: |
            const fs = require('fs');
            const body = fs.readFileSync('${{ steps.scan.outputs.pr-comment-file }}', 'utf8');
            await github.rest.issues.createComment({
              owner: context.repo.owner, repo: context.repo.repo,
              issue_number: context.issue.number, body,
            });
```

The comment renderer is also available standalone: `attackmap analyze .
--pr-comment pr.md` (add `--baseline prev.json` to include the diff).

### Diff mode (PR gating)

For a lighter CI integration than Code Scanning — a bot comment, a JSON delta,
or a hard fail on newly-introduced HIGH findings — point `--baseline` at a
prior report and AttackMap will emit a Markdown diff alongside the fresh
report:

```bash
attackmap analyze . --output reports \
  --baseline path/to/previous/attackmap-report.json \
  --diff-output reports/attackmap-diff.md \
  --fail-on-new-high        # exit non-zero if the PR introduces any HIGH finding
```

Findings get a stable id (hash of the finding title) that survives line drift
on unrelated commits, so a finding that persists across scans has the same id
in both. The diff has three sections — **New**, **Persisted**, **Resolved** —
which drop cleanly into a PR comment.

### Suppressing findings

Silence a residual false positive without going blind to new signal. Two
mechanisms, both honored across every pass:

**Repo-level baseline** — `.attackmap-suppress.yaml` at the repo root:

```yaml
version: 1
suppress:
  # by stable finding id (the 16-hex id in attackmap-report.json)
  - id: 1a2b3c4d5e6f7a8b
    reason: accepted risk, tracked in JIRA-1234

  # by rule (a slug of the finding title — same string as the SARIF ruleId),
  # optionally scoped to paths
  - rule: hard-coded-secret-literals-were-found-in-source-or-config
    reason: example keys in docs, never shipped
    paths: ["docs/**", "examples/**"]

  # by path only — any finding whose evidence is *entirely* within these globs
  - path: "vendor/**"
    reason: third-party code, out of scope
```

A `path` selector matches a finding only when **every** file its evidence cites
falls under the glob, so a finding that also touches live code is never hidden.
`*` spans path separators (`vendor/*` covers the whole subtree).

**Inline directives** — a comment on the flagged line, in any language:

```python
API_KEY = "AKIA…"  # attackmap:ignore[hard-coded-secret-literals-were-found-in-source-or-config] staging only
```

Suppressed findings are **not dropped**: they're excluded from
`--fail-on-new-high` and the console summary, but retained in
`attackmap-report.json` under `suppressed_findings` (with reasons) and marked
with a SARIF `suppressions` array so GitHub Code Scanning shows them as
suppressed. Suppression counts print in the run summary. Use `--no-suppress`
for a full unfiltered audit, or `--suppress-file PATH` to point elsewhere.

### Data-flow / injection detection

A lightweight taint pass (Python + JS/TS) walks the import graph up to two hops
from each route handler and flags dangerous sinks reachable from an entry point.
Each sink kind that a route can reach produces a dedicated finding with an
ATT&CK mapping:

| Sink kind | What it catches | Severity |
|---|---|---|
| `eval` / `exec` | Request-reachable code execution | HIGH |
| `subprocess_shell` | OS command execution (`shell=True`, `child_process.exec`) | HIGH |
| `unsafe_deserialization` | `pickle.loads`, `yaml.load` (no SafeLoader), `marshal`, `node-serialize` | HIGH |
| `ssti` | Server-side template injection (`render_template_string`, `Template(req…)`) | HIGH |
| `ssrf` | Request-derived URL into `requests`/`httpx`/`urlopen`/`axios`/`fetch` | MEDIUM |
| `nosql_injection` | Request object as a Mongo filter, or `$where` | MEDIUM |
| `sql_execute` | Cursor/session `.execute`/`.query` reachable from a route | (feeds attack paths) |
| `dynamic_open` | `open()` with request-shaped path | (feeds attack paths) |

| `open_redirect` | Request-derived URL into `redirect()`/`res.redirect()` | MEDIUM |

Beyond the taint sinks, a per-file pass flags additional undisclosed-vuln
classes (`scan.code_weaknesses`): **prototype pollution** (`__proto__` writes,
deep-merge of a request object), **mass assignment** (a whole request body bound
to a model), **JWT weaknesses** (`alg=none`, signature verification off), **XXE**
(XML parsers with external entities enabled), **ReDoS** (regexes with
catastrophic backtracking), **insecure upload** (a file saved under a
client-controlled name/path), and **GraphQL exposure** (introspection/playground
left on).

Sinks that are only dangerous with attacker-controlled input (SSRF, SSTI, NoSQL,
open redirect, `open`) are gated on a request-shaped identifier in the call — a constant URL or
template is not flagged. The walk is **call-graph-aware** (#138): for Python and
JS/TS an import edge is kept only when the imported symbol is actually used in
the file, so a dead import no longer fans a route out to that module's sinks
(the plain import-graph remains the fallback for namespace/star/side-effect
imports and for Go/PHP). It's still a heuristic (use ≉ proven call), so findings
are evidence, not proof; confidence tapers with hop distance. Chains appear in
`attackmap-report.json` under `scan.taint_chains`.

**Sanitizer awareness.** When a sink-appropriate neutralizer is present in the
sink file — `shlex.quote` / `escapeshellarg` (shell), `secure_filename` / path
allow-listers (`open`), `is_safe_url` (redirect), `markupsafe.escape` (SSTI),
driver escapers (SQL), mongo-sanitize (NoSQL) — the chain is marked
`sanitized`, its confidence is downgraded well below the finding threshold, and
the neutralizer is recorded in `sanitizer_evidence`. Sanitized chains stay in
`scan.taint_chains` for audit but don't raise a HIGH finding or earn an
exploitability score. Detection is file-granular (matching the import-walk's
granularity), so it trades a little recall for precision. To extend the table,
add a high-signal, sink-appropriate `(label, regex)` entry to
`_SANITIZER_PATTERNS` in [`taint.py`](src/attackmap/taint.py) — keep it specific
(a vague `validate(` would hide real bugs).

Test and spec files (`tests/`, `__tests__/`, `*.test.*`, `test_*.py`, …) are
excluded from all the heuristic passes above by default, since dangerous
patterns in test scaffolding are rarely real exposure. Set
`ATTACKMAP_INCLUDE_TESTS=1` to scan them too (e.g. for test-quality reviews).

**Recall mode (`--recall`).** Aggressiveness is only useful *behind* a verifier —
so `--recall` widens taint discovery and marks the extra reach **speculative**
instead of asserting it. It:

- raises the max import-hop depth (2 → 4) and per-route visit budget;
- surfaces reaches the default pass conservatively hides, like a
  static-literal-looking `eval`/`exec`/deserialize argument;
- **enumerates capability-reach**: every reach to a powerful capability —
  network (`requests`/`httpx`/`axios`/`fetch`/`urlopen`), template
  (`render_template_string`/`Template`), filesystem (`open`), redirect
  (`redirect`/`res.redirect`) — even with **no known-bad pattern**, i.e. the
  bare call without a request-derived argument (a genuine request-derived sink
  still fires once, as a confirmed finding, not a duplicate).

Speculative chains carry downgraded confidence, get their own LOW-severity
finding (`SPECULATIVE (recall mode)…`), are excluded from every asserted
downstream pass (exploitability, BOLA, attack paths), and are kept **out of
`--fail-on-new-high`** — they are leads for `--hunt --verify` / `--triage` to
adjudicate, not detections. Default behavior is unchanged; pair `--recall` with
`--hunt --verify` to widen the net and then adjudicate what it catches.

### Web hardening gaps

Route- and config-level checks for common web misconfigurations, each an
ATT&CK-mapped finding:

| Kind | Catches | Severity |
|---|---|---|
| `cors_wildcard_credentials` | wildcard/reflected CORS origin **with** credentials | HIGH |
| `csrf_disabled` | CSRF explicitly disabled / exempted | MEDIUM |
| `insecure_cookie` | `httpOnly:false`, `secure:false`, `SameSite=None` without `Secure` | MEDIUM |
| `weak_csp` | CSP allowing `'unsafe-inline'` / `'unsafe-eval'` | MEDIUM |
| `debug_enabled` | debug mode / actuator wildcard exposure shipped on | MEDIUM |

These detect *positively-present* misconfigurations rather than hard-to-judge
absences (a wildcard CORS origin alone is fine — it's the pairing with
credentials that's flagged). Results appear under `scan.web_hardening_issues`.

### Insecure cryptography & weak randomness

A cheap per-file pass flags crypto misuse, each as a finding with an ATT&CK
mapping:

| Kind | Catches | Severity |
|---|---|---|
| `weak_password_hash` | MD5/SHA-1 over a password-shaped value | HIGH |
| `weak_cipher` | DES / 3DES / RC4 / Blowfish | HIGH |
| `ecb_mode` | ECB block-cipher mode (incl. Java's `Cipher.getInstance("AES")` default) | MEDIUM |
| `static_iv_salt` | hard-coded IV or salt literal | MEDIUM |
| `insecure_random` | `Math.random`/`random`/`rand`/`mt_rand` for a token/key/salt/nonce | MEDIUM |
| `insecure_tls` | `verify=False`, `rejectUnauthorized:false`, `InsecureSkipVerify:true`, deprecated TLS | HIGH |

The noisy families (weak hash, insecure RNG) are gated on a security-context
identifier; cipher/ECB tokens are matched case-sensitively so algorithm names
aren't confused with prose (e.g. the French word "des"). Results appear under
`scan.crypto_weaknesses`.

### Hard-coded secret detection

Two layers, precision-first. **Typed provider-signature detectors** recognize the
distinctive shapes of leaked keys and fire at high confidence with a
provider-specific `kind`:

| Provider | Prefix / shape |
|---|---|
| AWS | `AKIA…` / `ASIA…` |
| GitHub | `ghp_` / `gho_` / `ghu_` / `ghs_` / `ghr_` |
| OpenAI | `sk-…` / `sk-proj-…` / `sk-svcacct-…` |
| Anthropic | `sk-ant-…` |
| GitLab / npm | `glpat-…` / `npm_…` |
| Stripe / Slack / Google | `sk_live_…` / `xox[bpsare]-…` / `AIza…` |
| SendGrid / Mailgun / Twilio | `SG.…` / `key-…` / `AC…` SID |
| PEM / JWT | `-----BEGIN … PRIVATE KEY-----` / `eyJ….eyJ….…` (header verified) |

Below the typed layer, a **Shannon-entropy fallback** catches high-entropy
literals that don't match a known provider. It is calibrated to stay quiet:
pure-hex hashes, URLs, version/number strings, base64/base32 alphabet constants
(#96), Subresource-Integrity / lockfile digests (`sha384-…`), and UUIDs are
suppressed, and a typed match always takes precedence over the entropy hit for
the same span. Values are redacted (`ghp_…6789`) before they reach any report —
the raw secret never appears. No liveness verification is performed. Results
appear as `scan.secret_hints`.

### GitHub Actions / CI workflow security

CI config is a real attack surface. AttackMap parses `.github/workflows/*.yml`
and flags supply-chain and code-execution risks, each a finding with an ATT&CK
mapping:

| Kind | Catches | Severity |
|---|---|---|
| `script_injection` | attacker-controlled context (`github.event.*.{title,body,message,…}`, `github.head_ref`) interpolated into a `run:` step | HIGH |
| `pr_target_checkout` | `pull_request_target` + checkout of the PR head ref (untrusted code with secrets in scope) | HIGH |
| `unpinned_action` | `uses: org/action@tag\|branch` instead of a pinned commit SHA | branch = MEDIUM, semver tag = LOW |
| `secret_in_run` | `${{ secrets.* }}` expanded into a shell step (pass via `env:` instead) | MEDIUM |
| `broad_permissions` | `permissions: write-all` at workflow or job level | MEDIUM |
| `self_hosted_pr` | self-hosted runner on a `pull_request`/`pull_request_target` trigger | HIGH / MEDIUM |

A hardened workflow — SHA-pinned actions, scoped `permissions:`, secrets via
`env:`, no untrusted-context interpolation — produces nothing. Results appear
under `scan.workflow_issues`.

### Unauthenticated state-changing routes

Raw `auth_hints` are signals, not conclusions — a monorepo emits hundreds. A
fusion pass turns them into one precise finding: the public, state-changing
(`POST/PUT/PATCH/DELETE`) routes with **no auth control on their own chain**. It
resolves the control *per route* rather than by file proximity:

- **Express/Koa/Fastify** — auth middleware in the route's arguments, or a global `app.use(...)` / `router.use(...)`.
- **FastAPI/Flask** — an auth decorator, `dependencies=[Depends(...)]`, `Depends(<auth>)` / `Security(...)` in the signature, or a router-level dependency.
- **Spring** — `@PreAuthorize` / `@Secured` / `@RolesAllowed` on the method or controller, or a global "authenticated" policy.

Routes behind a control produce nothing, and the sensitive categories
(webhook/admin/upload/auth) keep their own dedicated findings — so this only
adds the general mutating-endpoint case, with the resolved chain as evidence.

### Broken object-level authorization (BOLA / IDOR)

OWASP API Security #1. AttackMap flags a route as a BOLA/IDOR candidate when it
composes three signals it already has:

1. the route takes a **resource id** — via a **path** template (`/users/{id}`,
   `/orders/:orderId`), an id-bearing **query parameter** (`?orderId=`), an
   **RPC method** (XRPC `/xrpc/…getRecord`, tRPC `user.byId`), or a **GraphQL
   field** (`user(id: ID!)`) — and
2. it **reaches a datastore** — a DB hint in the same file/module, a taint chain
   from the route to a SQL execute sink, or (for RPC/GraphQL) an object-access
   operation, and
3. **no ownership/authorization check** is visible near the handler
   (`current_user`, `request.user`, `authorize`, a policy/guard, a
   `filter_by(user_id=…)`-style scoped query, or a GraphQL `@auth`/`@hasRole`
   schema directive on the field).

Write operations (POST/PUT/PATCH/DELETE, GraphQL mutations) are HIGH, reads
MEDIUM. Candidates appear under `scan.authz_candidates` (each carrying its
`surface`); the ownership-marker scan is the main false-positive reducer, so a
well-scoped handler or an `@auth`-guarded field is not flagged.

### Anomaly / outlier detection

The closest honest thing to "surface the unknown": instead of matching a
known-bad signature, AttackMap flags a route that deviates from the norm its own
siblings establish. Routes are bucketed into resource cohorts by path prefix
(`/api/users`, `/api/users/{id}` and `/api/users/export` all share `api/users`;
`api`/version scaffolding is stripped so versioned resources still separate), and
within each cohort the odd-one-out is reported:

| Kind | Catches | Severity |
|---|---|---|
| `auth_outlier` | siblings carry an auth/authorization signal near the handler; this route doesn't | HIGH |
| `validation_outlier` | among a cohort's state-changing handlers, peers validate input and this one shows no validation marker | LOW |
| `method_outlier` | a lone state-changing method in an otherwise read-only cohort | MEDIUM |
| `invariant_violation` | a mined-invariant outlier: among handlers that reach the same dangerous sink kind, the majority guard the request *before* the sink and this one doesn't — evidence cites the mined rule | HIGH |

The `invariant_violation` kind is the **mined-invariant** pass (#149a): its
cohort is not a route-path prefix but the set of handlers that reach the same
dangerous sink (from the taint pass). When a strong majority guard the request
before the sink, that pattern is mined as an implicit invariant and the handler
that reaches the same sink kind with no preceding guard is flagged, citing the
mined rule (e.g. "9 of 10 handlers that reach a database (SQL execute) sink
apply an auth/validation guard before it"). It reasons only about **same-file**
flows, where guard-before-sink ordering is actually verifiable (a cross-file
sink could be called before an `authorize(...)` that textually follows it), and
counts one handler per declaration regardless of how many verbs it exposes.
Sanitized chains are excluded so only genuinely undefended flows form the cohort
— it measures the code against its own norm and needs no signature.

Everything is peer-relative and **confidence scales with how consistent the
cohort is** — a lone deviation among many agreeing siblings is likelier a mistake
than the same deviation in a split group. Outliers are only flagged when they're a
strict minority (a genuinely 50/50 surface isn't nagged), the cohort must have
real route structure (distinct paths with parameters/sub-paths, not repeated
method-call strings), and per-route signal detection is scoped to each handler's
own span so a sibling's guard is never miscredited. Results appear under
`scan.anomalies`, each finding naming the peer group and the deviation. This is
the scan-level, route-cohort counterpart to the layered engine's
`asymmetric_protection` insight.

### Exploitability fusion ("Most exploitable now")

Every signal AttackMap has about a route→sink path is fused into a single
**0–100 exploitability score** so the highest-risk *combinations* rise to the
top — the public, unauthenticated route whose request reaches a SQL sink next to
a secret is a different animal from an internal, authed route that reaches the
same sink two hops away. The score is:

- **Deterministic** — the same scan always yields the same number; no
  randomness, no clock.
- **Explainable** — the score is the clamped sum of named factors, and every one
  is shown. Contributing factors: sink danger (SQLi/RCE/deserialization highest),
  exposure (public/internal/unknown), auth at the entry route, reachability
  (fewer hops = higher), and data sensitivity at the sink (a co-located secret or
  datastore), plus insecure-crypto / web-hardening gaps and **known-vulnerable
  dependencies imported on the path** (from `--cve`, amplified by CVE severity)
  as amplifiers.

Scores land on the relevant taint findings (`exploitability` + `exploitability_tier`)
and in a ranked **`attackmap-exploitability.md`** report plus the `exploitability`
array in `attackmap-report.json`; the console summary leads with the top few. For
example, `public + no-auth + taint-to-eval (0 hops)` scores 90/100 (CRITICAL), and
a route reaching a sink through a known-vulnerable library version scores higher
still.

### SBOM inventory

Every scan also produces a lightweight SBOM by parsing direct dependencies out
of the common manifest files:

| Ecosystem | Files parsed |
|---|---|
| PyPI (Python) | `pyproject.toml` (PEP 621 + Poetry), `requirements.txt` |
| npm (Node.js) | `package.json` (dependencies + devDependencies + peer/optional) |
| Go | `go.mod` (single-line + block-form `require`, `// indirect` flagged) |
| Cargo (Rust) | `Cargo.toml` (dependencies + dev-dependencies + build-dependencies) |
| Composer (PHP) | `composer.json` (require + require-dev; platform reqs skipped) |

Each entry appears in `attackmap-report.json` under `scan.dependencies` with
`{name, version, ecosystem, file, dev, resolved, direct, via}`. Manifest ranges
are kept verbatim (`^4.16.0`, `>=2,<3`, `latest`).

**Lockfile resolution (#143).** When a lockfile is present it is parsed for
*exact* resolved versions and the full **transitive** tree — where most
known-vulnerable dependencies actually live. Resolved entries set
`resolved=true`, mark `direct`/transitive, and carry a `via` resolution path
(`express > body-parser > qs`). A lockfile supersedes the range-only manifest
in its **own directory** (so a monorepo's per-service lockfiles don't shadow
each other).

| Lockfile | Ecosystem |
|---|---|
| `package-lock.json` (v1/v2/v3), `pnpm-lock.yaml` | npm |
| `poetry.lock`, `uv.lock` | PyPI |
| `Cargo.lock` | Cargo |

Go needs no lockfile pass: `go.mod` already pins exact versions and flags
`// indirect` (transitive) deps, so it's treated as resolved directly.
(`go.sum` is a checksum history, not the build list, so it is not used for
inventory.)

### CVE cross-reference (opt-in)

`attackmap analyze --cve` cross-references every SBOM entry against
[OSV.dev](https://osv.dev) and emits one finding per vulnerable dependency
(all known advisories aggregated in the evidence list). CVSS scores map into
low/medium/high — anything ≥ 7.0 is HIGH.

```bash
attackmap analyze . --cve
```

- **Off by default.** The flag exists precisely because CVE lookup does
  network I/O; regular scans stay offline.
- **Cached** under `~/.attackmap/cache/osv/` keyed by
  `sha256(ecosystem+name+version)`. TTL is 24h by default, overridable via
  `ATTACKMAP_OSV_CACHE_TTL_HOURS`. Repeat scans of the same repo don't hit
  the network.
- **Offline-tolerant.** If the network's unavailable but the cache is warm,
  cached results still surface; only fresh queries are skipped.
- **Exact when a lockfile exists.** Lockfile-resolved dependencies (direct and
  transitive) are queried at their pinned version, and a vulnerable transitive
  dep is reported with its resolution path. For range-only manifests with no
  lockfile, version resolution is best-effort — ranges (`^4.16.0`, `>=2.28,<3`)
  resolve to a queryable lower-bound and OSV does the range math; unpinned specs
  (`*`, `latest`) are skipped.

The structured vulnerability list is available under
`scan.vulnerabilities` in `attackmap-report.json` with
`{id, aliases, summary, severity, cvss_score, references, affected_range,
package_name, package_version, ecosystem}`.

---

## How it works

AttackMap is built as four layers, each grounded in the layer below.

**1. Heuristic scanner + analyzer plugins.** Language-aware extraction of routes,
databases, external calls, auth signals, secrets, frameworks, and entrypoints.
Every signal carries a `file:line` citation, an evidence-text snippet, and a
confidence score. Plugins are auto-discovered through the `attackmap.analyzers`
entry-point group. Alongside recon, three cross-file passes run in core: a
**taint / data-flow** walk (request-to-sink reachability across imports), a
**BOLA/IDOR** authorization check, and an **SBOM** dependency inventory
(optionally cross-referenced against OSV.dev with `--cve`).

**2. Asset and control overlay.** Identifies *what's at risk* (credentials,
sessions, PII, payment records, internal secrets — with criticality tiers) and
*what protects it* (authentication, authorization, input validation, rate
limiting, CSRF, encryption, audit logging, RBAC, MFA), including detection of
*absent* expected controls.

**3. Cross-cutting insight engine.** Connects findings into narratives —
sensitive-asset reachability, shared-secret blast radius, defense gaps in attack
chains, control-strength mismatches, asymmetric protection, audit gaps,
trust-boundary violations, and more.

**4. LLM narrative review.** With `--llm`, Claude Opus generates a final review
from the structured evidence pack. The model is forced to cite real
surface/asset/control IDs, so it can't invent findings. Add `--llm-provider
openai` to run the same phase on OpenAI/Codex instead (`gpt-5-codex` by default,
via `OPENAI_API_KEY` or the `codex` CLI) — the grounding contract is identical.

**5. Vulnerability-hypothesis hunting (`--hunt`).** The honest core of the
"find the unknown" ask. `attackmap analyze . --hunt` has Claude reason over the
full evidence pack (surfaces, assets, controls, taint chains, exploitability
scores, anomalies) as a red-team analyst and propose **ranked, human-verifiable
exploit-chain hypotheses** — candidate weaknesses a static rule wouldn't catch,
especially novel cross-signal combinations. Output goes to
`vulnerability-hypotheses.md` under an unmissable banner: **these are hypotheses
to confirm, not detections.** The same grounding contract as the review applies
(every hypothesis cites real evidence IDs), plus honesty guardrails: no CVE
assignment, no exploit code, confidence-tiered, and each lead lists exactly what
a human must verify. Uses the same auth/backend resolution as `--llm`.

With `--verify`, each hypothesis is adjudicated against the actual source at its
cited locations. **`--verify-votes N`** (default 3) turns that into a jury: **N
independent skeptics** each adjudicate the same fixed hypothesis list. A lead is
**CONFIRMED only on a strict majority** (NEEDS_REVIEW only when a majority flags
the evidence as insufficient); ties and uncertainty are **REFUTED** — so a lead
only one skeptic would confirm is dropped. **`--hunt-lenses N`** additionally
fans generation out into N independent passes, each specialised in one failure
mode (auth-bypass, TOCTOU/race, IDOR, deserialization, SSRF-to-internal,
secret-misuse), and dedupes the leads across passes before verifying — more
unique novel leads than a single generalist pass. **`--hunt-rounds N`** loops
generation for up to N rounds, accumulating new (deduped) leads while a
completeness critic seeds each next round with untried angles, and stops early
once a round finds nothing new; **`--hunt-budget T`** caps the multi-round output
tokens.
This is the verifier the unknown-bug initiative
([`docs/unknown-bug-epic.md`](docs/unknown-bug-epic.md)) is built on;
`--verify-votes 1` is the classic single pass.

Layered on top: **MITRE ATT&CK technique mappings** on every insight and
**detection opportunities** (Sigma/KQL/Splunk-style hints) for each weakness.

**6. Triage (`--triage`).** Where `--hunt` finds *new* leads, `--triage`
distills the *existing* heuristic findings: `attackmap analyze . --triage` has
the LLM cluster them by root cause, de-duplicate, and rank into a prioritized
shortlist that cites real finding IDs (it organizes, it never invents). Output
goes to `triage.md`. When no LLM backend is available it degrades to a
**deterministic**, score-ordered, clustered shortlist — reproducible enough to
diff across runs — rather than erroring.

---

## Supported ecosystems

Fourteen official analyzer plugins, each distributable as a separate package:

| Plugin | Coverage |
|---|---|
| `attackmap-analyzer-python` | Django, Starlette, AIOHTTP, Sanic, Litestar, DRF; SQLAlchemy/asyncpg/motor; passlib/PyJWT/authlib; httpx/aiohttp |
| `attackmap-analyzer-rust` | axum, actix-web, rocket; sqlx, diesel, sea-orm; jsonwebtoken, argon2; reqwest |
| `attackmap-analyzer-go` | net/http, chi, gin, echo, fiber, gorilla/mux; database/sql, gorm, pgx; golang-jwt; resty |
| `attackmap-analyzer-java-spring` | Java/Kotlin Spring Boot, JAX-RS, Ktor; Spring Data; Spring Security; jjwt |
| `attackmap-analyzer-dotnet` | ASP.NET Core minimal APIs and attribute routing, EF Core, Identity, JwtBearer |
| `attackmap-analyzer-terraform` | AWS, Azure, GCP resources; IAM wildcards; open SGs; secrets |
| `attackmap-analyzer-iac` | Dockerfile hardening, docker-compose service graphs, GitHub Actions workflows, `.env` templates, shell installers |
| `attackmap-analyzer-c` | libmicrohttpd, civetweb, mongoose; libcurl; OpenSSL/libsodium; sqlite3/libpq/mysql |
| `attackmap-analyzer-cpp` | Crow, Pistache, Drogon, cpprestsdk; libcurl/cpr; OpenSSL/Botan/libsodium; libpqxx/mongocxx |
| `attackmap-analyzer-node-service` | Node.js / TypeScript service ecosystems |
| `attackmap-analyzer-atproto` | AT Protocol (Bluesky) services |
| `attackmap-analyzer-php-web` / `-php-laminas` / `-omeka-s` | Generic PHP web, Laminas/Zend MVC, Omeka-S |

`pip install "attackmap[all]"` installs every official plugin. Not sure which
you need? `attackmap suggest ./repo` recommends the right set for a repo's shape.

### Building your own analyzer

The plugin contract is documented in code at
[`attackmap.sdk`](src/attackmap/sdk/__init__.py); the developer cookbook with
scaffolding, testing, and publishing instructions is in
[`docs/external-analyzers.md`](docs/external-analyzers.md).

---

## CLI reference

```bash
attackmap analyze <path>                 # run a review on a repository
attackmap analyze <path> --output dir    # write outputs to `dir/`
attackmap analyze <path> --format json   # json | markdown | all (default)
attackmap analyze <path> --module python --module rust   # only these analyzers
attackmap analyze <path> --cve           # cross-reference SBOM against OSV.dev
attackmap analyze <path> --llm           # add LLM narrative (auto-resolve auth)
attackmap analyze <path> --llm --llm-backend cli         # force Claude CLI
attackmap analyze <path> --llm --llm-provider openai     # use OpenAI/Codex (OPENAI_API_KEY or `codex` CLI)
attackmap analyze <path> --llm --llm-provider openai --llm-model gpt-5.5   # any OpenAI model ID, passed through
attackmap analyze <path> --hunt          # LLM vulnerability-hypothesis hunt (leads to confirm)
attackmap analyze <path> --hunt --verify # adjudicate each lead vs. source (confirmed/refuted/review)
attackmap analyze <path> --hunt --verify --verify-votes 3   # majority vote of N independent skeptics (default 3; 1 = single pass)
attackmap analyze <path> --hunt --verify --hunt-lenses 4     # N lens-specialised generation passes, deduped, then verified
attackmap analyze <path> --hunt --verify --hunt-rounds 4     # loop-until-dry generation (completeness critic seeds each round)
attackmap analyze <path> --remediate     # LLM review-first fix suggestions (remediation.md)
attackmap analyze <path> --triage        # cluster/dedupe/rank existing findings (triage.md; deterministic fallback)
attackmap analyze <path> --pr-comment pr.md   # Markdown PR summary comment for CI

# CI / PR diff gating
attackmap analyze <path> --baseline prev/attackmap-report.json \
  --diff-output reports/attackmap-diff.md --fail-on-new-high

# Suppression (.attackmap-suppress.yaml + inline `attackmap:ignore` directives)
attackmap analyze <path> --no-suppress          # full audit, ignore all suppressions
attackmap analyze <path> --suppress-file cfg.yaml   # override baseline location

# Plugin discovery
attackmap suggest ./repo                 # recommend plugins for a repo shape
attackmap suggest ./repo --install       # and pip-install the missing ones
attackmap modules                        # list installed analyzers
```

`--module` is repeatable. Missing requested external analyzers can be
auto-installed (when possible) from the `mlaify` GitHub organization. `--cve`
does network I/O (cached under `~/.attackmap/cache/osv/`, 24h TTL);
`--fail-on-new-high` requires `--baseline` and exits non-zero when the diff
introduces a new HIGH finding.

---

## What AttackMap is *not*

- **A runtime detector.** AttackMap is static. The detection opportunities it
  emits are *hints* for your SIEM team — they are not deployable rules.
- **A replacement for dedicated SCA.** AttackMap does inventory dependencies and
  cross-reference OSV.dev with `--cve`, but tools like Trivy, Grype, and
  Dependabot go deeper on transitive resolution and lockfiles. AttackMap's
  value is folding the CVE signal into an architecture-aware narrative
  ("this public route reaches this vulnerable ORM").
- **A true taint engine.** The data-flow pass is a heuristic call-graph-refined
  import-graph walk (edges pruned to used symbols, but symbol *use* ≉ a proven
  data-carrying call), not sound interprocedural taint analysis. It favors
  precision over recall; findings are evidence, not proof.
- **Exhaustive.** AttackMap is heuristic by design. Findings are confidence-tiered
  with explicit guardrails for stale signals.

---

## Project status

AttackMap is **beta** (v0.4.18) — published and validated on real codebases, but
pre-1.0 and heuristic.

**Solid today:**

- Modular analyzer execution with entry-point discovery; 14 official plugins on PyPI.
- Framework-aware route extraction (FastAPI/Flask/Express/Spring/axum/chi/…).
- Asset + control modeling, cross-cutting insight engine, chain-aware threat model.
- **Multi-language import-graph taint** — **Python, JS/TS, Go (module-path
  resolution), and PHP (PSR-4 autoload)** — for injection sinks: SSRF, SSTI,
  NoSQL, unsafe deserialization, eval/exec/shell, SQL (parameterized-query-gated),
  dynamic file open, open redirect. Handler-aware seeding connects a route to
  the module that defines its handler (no import-hub fan-out).
- Novel vuln-class detectors: prototype pollution, mass assignment, JWT weakness,
  XXE, ReDoS, insecure upload, GraphQL exposure.
- BOLA/IDOR authorization detection (with custom-middleware / guard-arg awareness).
- Insecure-crypto / weak-randomness (Python/JS/Go/PHP) and web-hardening
  (CORS/CSRF/cookies/CSP/debug) detection.
- Anomaly / outlier detection and **exploitability fusion** — a deterministic,
  explainable 0–100 "exploitable now" score that ranks route→sink combinations
  and folds in known-vulnerable dependencies on the path.
- **`--hunt`** (LLM exploit-chain hypotheses) with **`--verify`** (adjudicate
  each lead CONFIRMED/REFUTED/NEEDS-REVIEW against the actual source),
  **`--remediate`** (review-first fix suggestions), and **`--triage`**
  (cluster/dedupe/rank existing findings, with a deterministic fallback).
- SBOM inventory (5 ecosystems) + OSV.dev CVE cross-reference (`--cve`).
- Output: Markdown + JSON + **SARIF 2.1.0** + **Mermaid / Graphviz** diagrams;
  **diff/baseline** PR gating; a reusable **GitHub Action + PR bot**; optional
  LLM narrative.
- Live scan progress bar + ETA; test/spec/vendored/generated files excluded from
  heuristic passes.
- Distribution: `pip install attackmap[all]`, `brew install mlaify/tap/attackmap`,
  `docker pull ghcr.io/mlaify/attackmap`.

**Still maturing:**

- BOLA/IDOR authorization now covers path templates, query parameters, RPC
  methods (XRPC/tRPC), and GraphQL fields; deeper resolver-level GraphQL
  ownership analysis and more languages are planned.
- The taint walk is call-graph-aware for Python/JS/TS (import edges are pruned to
  symbols actually used in the file) but still approximates: symbol *use* is not a
  proven data-carrying call, and Go/PHP keep the plain import-graph. Precision
  over recall; findings are evidence, not proof.
- CVE lookup uses exact lockfile-resolved versions (direct + transitive) when a
  lockfile is present; range-only manifests without a lockfile still fall back to
  a best-effort concrete version.
- Anomaly / exploitability reasoning is route-cohort and taint-chain scoped.

---

## Documentation

- [`CHANGELOG.md`](CHANGELOG.md) — release notes
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — development setup and PR process
- [`SECURITY.md`](SECURITY.md) — vulnerability disclosure
- [`AGENTS.md`](AGENTS.md) — agent-facing repo guide
- [`VISION.md`](VISION.md) — project direction
- [GitHub wiki](https://github.com/mlaify/AttackMap/wiki) — deeper architecture
  and analyzer-contract references

---

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md)
for setup, testing, and submission guidelines. By contributing you agree that
your contributions will be MIT-licensed.

## License

[MIT](LICENSE). Copyright (c) 2026 Matthew Davis and AttackMap Contributors.
