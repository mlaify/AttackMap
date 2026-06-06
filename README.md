# AttackMap

**AI-assisted defensive security analysis for codebases.** AttackMap reads your
repository, models its assets and defensive controls, finds cross-cutting
weaknesses that single-file scanners miss, and produces an evidence-grounded
security review with MITRE ATT&CK mappings and detection-engineering hints.

Built for AppSec engineers, SOC and detection-engineering teams, and engineering
managers who need to triage an unfamiliar codebase.

> Story over checklist. Asset-aware. Control-absence-aware. Evidence-grounded.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)

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
pip install "attackmap[all]"           # core + LLM + all 11 analyzer plugins
```

You can also install individual analyzer plugins on demand:

```bash
pip install attackmap-analyzer-python attackmap-analyzer-go
```

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
| `defensive-review-llm.md` *(with `--llm`)* | Claude-narrated review |
| `defensive-review-llm.meta.json` *(with `--llm`)* | Backend, model, token usage |

---

## How it works

AttackMap is built as four layers, each grounded in the layer below.

**1. Heuristic scanner + analyzer plugins.** Language-aware extraction of routes,
databases, external calls, auth signals, secrets, frameworks, and entrypoints.
Every signal carries a `file:line` citation, an evidence-text snippet, and a
confidence score. Plugins are auto-discovered through the `attackmap.analyzers`
entry-point group.

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

Eleven official analyzer plugins, each distributable as a separate package:

| Plugin | Coverage |
|---|---|
| `attackmap-analyzer-python` | Django, Starlette, AIOHTTP, Sanic, Litestar, DRF; SQLAlchemy/asyncpg/motor; passlib/PyJWT/authlib; httpx/aiohttp |
| `attackmap-analyzer-rust` | axum, actix-web, rocket; sqlx, diesel, sea-orm; jsonwebtoken, argon2; reqwest |
| `attackmap-analyzer-go` | net/http, chi, gin, echo, fiber, gorilla/mux; database/sql, gorm, pgx; golang-jwt; resty |
| `attackmap-analyzer-java-spring` | Java/Kotlin Spring Boot, JAX-RS, Ktor; Spring Data; Spring Security; jjwt |
| `attackmap-analyzer-dotnet` | ASP.NET Core minimal APIs and attribute routing, EF Core, Identity, JwtBearer |
| `attackmap-analyzer-terraform` | AWS, Azure, GCP resources; IAM wildcards; open SGs; secrets |
| `attackmap-analyzer-c` | libmicrohttpd, civetweb, mongoose; libcurl; OpenSSL/libsodium; sqlite3/libpq/mysql |
| `attackmap-analyzer-cpp` | Crow, Pistache, Drogon, cpprestsdk; libcurl/cpr; OpenSSL/Botan/libsodium; libpqxx/mongocxx |
| `attackmap-analyzer-node-service` | Node.js / TypeScript service ecosystems |
| `attackmap-analyzer-atproto` | AT Protocol (Bluesky) services |
| `attackmap-analyzer-php-web` / `-php-laminas` / `-omeka-s` | Generic PHP web, Laminas/Zend MVC, Omeka-S |

`pip install "attackmap[all]"` installs every official plugin.

---

## CLI reference

```bash
attackmap analyze <path>                 # run a review on a repository
attackmap analyze <path> --output dir    # write outputs to `dir/`
attackmap analyze <path> --module python --module rust   # only these analyzers
attackmap analyze <path> --llm           # add LLM narrative (auto-resolve auth)
attackmap analyze <path> --llm --llm-backend cli         # force Claude CLI
attackmap modules                        # list installed analyzers
```

`--module` is repeatable. Missing requested external analyzers can be
auto-installed (when possible) from the `mlaify` GitHub organization.

---

## What AttackMap is *not*

- **A runtime detector.** AttackMap is static. The detection opportunities it
  emits are *hints* for your SIEM team — they are not deployable rules.
- **A vulnerability scanner.** AttackMap models architecture, assets, and
  controls. It does not match known-CVE patterns.
- **Exhaustive.** AttackMap is heuristic by design. Findings are confidence-tiered
  with explicit guardrails for stale signals.

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
