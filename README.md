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

> **Status: beta (v0.2.0).** Core engine and 14 analyzer plugins are published
> to PyPI, Homebrew, and GHCR and validated against real-world codebases.
> AttackMap is heuristic by design — findings are confidence-tiered evidence,
> not proof. See [Project status](#project-status) for what's solid and what's
> still maturing.

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

Read `reports/defensive-review.md` (heuristic) and `reports/defensive-review-llm.md`
(LLM-narrated) side by side.

---

## Install

### From PyPI

```bash
pip install attackmap                  # core only
pip install "attackmap[llm]"           # add LLM narrative support
pip install "attackmap[all]"           # core + LLM + all 13 analyzer plugins
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
| `defensive-review-llm.md` *(with `--llm`)* | Claude-narrated review |
| `defensive-review-llm.meta.json` *(with `--llm`)* | Backend, model, token usage |

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

Sinks that are only dangerous with attacker-controlled input (SSRF, SSTI, NoSQL,
`open`) are gated on a request-shaped identifier in the call — a constant URL or
template is not flagged. It's a heuristic (import-edge ≠ call-edge), so findings
are evidence, not proof; confidence tapers with hop distance. Chains appear in
`attackmap-report.json` under `scan.taint_chains`.

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

### Broken object-level authorization (BOLA / IDOR)

OWASP API Security #1. AttackMap flags a route as a BOLA/IDOR candidate when it
composes three signals it already has:

1. the route takes a **resource id** in the path (`/users/{id}`,
   `/orders/:orderId`, `/docs/<int:doc_id>`), and
2. it **reaches a datastore** — a DB hint in the same file/module, or a taint
   chain from the route to a SQL execute sink, and
3. **no ownership/authorization check** is visible near the handler
   (`current_user`, `request.user`, `authorize`, a policy/guard, or a
   `filter_by(user_id=…)`-style scoped query).

Write routes (POST/PUT/PATCH/DELETE) are HIGH, reads MEDIUM. Candidates appear
under `scan.authz_candidates`; the ownership-marker scan is the main
false-positive reducer, so a well-scoped handler is not flagged. Path-template
routes today; query-parameter and RPC-method ids are future work.

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
`{name, version, ecosystem, file, dev}`. Version ranges are kept verbatim
(`^4.16.0`, `>=2,<3`, `latest`) — this slice does not resolve lockfiles.

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
- **Version resolution is best-effort.** Manifest ranges (`^4.16.0`,
  `>=2.28,<3`) resolve to a queryable lower-bound; OSV does the range math.
  Unpinned specs (`*`, `latest`) are skipped.

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
surface/asset/control IDs, so it can't invent findings.

Layered on top: **MITRE ATT&CK technique mappings** on every insight and
**detection opportunities** (Sigma/KQL/Splunk-style hints) for each weakness.

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

# CI / PR diff gating
attackmap analyze <path> --baseline prev/attackmap-report.json \
  --diff-output reports/attackmap-diff.md --fail-on-new-high

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
- **A true taint engine.** The data-flow pass is a heuristic import-graph walk
  (import-edge ≈ call-edge), not sound interprocedural taint analysis. It
  favors precision over recall; findings are evidence, not proof.
- **Exhaustive.** AttackMap is heuristic by design. Findings are confidence-tiered
  with explicit guardrails for stale signals.

---

## Project status

AttackMap is **beta** (v0.2.0) — published and validated on real codebases, but
pre-1.0 and heuristic.

**Solid today:**

- Modular analyzer execution with entry-point discovery; 14 official plugins on PyPI.
- Framework-aware route extraction (FastAPI/Flask/Express/Spring/axum/chi/…).
- Asset + control modeling, cross-cutting insight engine, chain-aware threat model.
- Injection / data-flow detection: SSRF, SSTI, NoSQL, unsafe deserialization,
  eval/exec/shell, SQL, dynamic file open — request-container-gated for precision.
- BOLA/IDOR authorization detection on path-template routes.
- SBOM inventory (5 ecosystems) + OSV.dev CVE cross-reference (`--cve`).
- Output: Markdown + JSON + **SARIF 2.1.0** (GitHub Code Scanning) + **Mermaid /
  Graphviz** diagrams; **diff/baseline** mode for PR gating; optional LLM narrative.
- Distribution: `pip install attackmap[all]`, `brew install mlaify/tap/attackmap`,
  `docker pull ghcr.io/mlaify/attackmap`.

**Still maturing:**

- Taint + BOLA are Python + JS/TS and path-template scoped; query-param / RPC-method
  authorization and more languages are planned.
- CVE lookup resolves a best-effort concrete version, not full lockfile ranges.
- Test-file exclusion for the taint pass is in progress ([#67](https://github.com/mlaify/AttackMap/issues/67)).
- Insecure-crypto and web-hardening detection are in flight ([#70](https://github.com/mlaify/AttackMap/issues/70), [#71](https://github.com/mlaify/AttackMap/issues/71)).

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
