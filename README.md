# AttackMap

> [!IMPORTANT]
> **Active development, slow pace.** AttackMap is under active development, but
> progress may be slow until more contributors or co-maintainers join. Help is
> very welcome with the core engine, an analyzer, the macOS app, or the docs —
> see [CONTRIBUTING.md](CONTRIBUTING.md) or open an issue on
> [mlaify/AttackMap](https://github.com/mlaify/AttackMap/issues) to say hello.
> Security reports are still welcome at [security@mlaify.io](mailto:security@mlaify.io).

**Local-first, AI-assisted defensive security analysis for codebases.** AttackMap
reads a repository (or a whole fleet of them), reconstructs the attack surface —
routes, data stores, external calls, auth signals, trust boundaries — traces
request-to-sink data flow, and produces an evidence-grounded, prioritized security
review. It finds the cross-cutting weaknesses single-file scanners miss, and never
sends your code anywhere.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)

> **Status: beta (v0.5.0).** Core engine + 15 analyzer plugins, installed straight
> from GitHub and validated on real codebases. AttackMap is heuristic by
> design — findings are confidence-tiered evidence, not proof. Roadmap to 1.0:
> [issue #209](https://github.com/mlaify/AttackMap/issues/209).

Full documentation: **[docs.mlaify.io](https://docs.mlaify.io)** ·
architecture & internals: **[wiki](https://github.com/mlaify/AttackMap/wiki)**.

### The macOS app

Prefer a GUI? A native macOS front-end drives this CLI and renders every result
view. Install it with Homebrew (this also installs the CLI), or build it from
source at [mlaify/AttackMap-mac](https://github.com/mlaify/AttackMap-mac):

```bash
brew install --cask mlaify/tap/attackmap-app
```

| Overview | Exploitability |
|---|---|
| [![AttackMap macOS app — overview](https://raw.githubusercontent.com/mlaify/AttackMap/main/docs/screenshots/04-overview.png)](https://docs.mlaify.io/gui/) | [![AttackMap macOS app — exploitability](https://raw.githubusercontent.com/mlaify/AttackMap/main/docs/screenshots/06-exploitability-ranked.png)](https://docs.mlaify.io/gui/) |

*Scanning OWASP Juice Shop. Walkthrough in the [macOS app docs](https://docs.mlaify.io/gui/); source at [mlaify/AttackMap-mac](https://github.com/mlaify/AttackMap-mac).*

## Quickstart

```bash
brew install mlaify/tap/attackmap         # Homebrew: CLI + all 15 analyzer plugins
# or: pip install "attackmap[all] @ git+https://github.com/mlaify/AttackMap.git"
attackmap analyze /path/to/repo           # heuristic review → reports/
attackmap analyze /path/to/repo --llm     # + AI-narrated review (Claude or OpenAI)
attackmap analyze ./svc-a ./svc-b ./gw    # cross-repo / fleet scan
```

Read `reports/defensive-review.md` for the heuristic review, and (with `--llm`)
`reports/defensive-review-llm.md` for the AI narration. `--llm` resolves auth
automatically (`ANTHROPIC_API_KEY`, or your Claude/`codex` CLI subscription); add
`--llm-provider openai` for OpenAI/Codex.

Other install paths: `pip install git+https://github.com/mlaify/AttackMap.git` (core
only), or the `[llm]` extra for AI narration. Not sure
which analyzer plugins a repo needs? `attackmap suggest ./repo`. Full install and
CI setup: **[install guide](https://docs.mlaify.io/install/)**.

## What it finds

- **Attack-surface recon** — routes, data stores, external calls, auth signals,
  secrets, frameworks, entrypoints; every signal carries a `file:line` citation,
  evidence snippet, and confidence.
- **Data-flow / injection taint** (Python, JS/TS, Go, PHP, Java) — SSRF, SSTI,
  NoSQL, unsafe deserialization, eval/exec/shell, SQL, path traversal, open
  redirect — traced source → variable → sink inside each handler, with
  flow-bound sanitizers, SARIF `codeFlows`, and a deterministic 0–100
  **exploitability score**.
- **Novel vuln classes** — prototype pollution, mass assignment, JWT, XXE, ReDoS,
  insecure upload, GraphQL exposure; **BOLA/IDOR** authorization; insecure-crypto
  & web-hardening; anomaly/outlier + signature-free **invariant mining**.
- **Dependency CVEs** (`--cve`) — SBOM + lockfile resolution against OSV.dev,
  folded into the exploitability score.
- **Unknown-bug discovery** — `--hunt --verify` (a multi-pass, majority-vote LLM
  jury), verifier-gated `--recall`, and **cross-repo / fleet** analysis:
  confused-deputy flows, trust-assumption gaps, and the sibling service that omits
  a control its peers enforce.
- **Workflow** — `--triage`, `--remediate`, finding suppression, baseline diff
  gating, SARIF + Mermaid/Graphviz output, and a GitHub **Action + PR bot**.

Each run writes Markdown, JSON (`attackmap-report.json`), **SARIF 2.1.0**, and
diagram artifacts; fleet runs add `fleet-summary.{md,json}` + `fleet-graph.md`.
See the [outputs reference](https://docs.mlaify.io/scanning/) for the full list.

## Supported ecosystems

Fourteen analyzer plugins (each installable on its own; `[all]` installs every one):
**Python**, **JavaScript/TypeScript** (Node services), **Go**, **Java/Kotlin**
(Spring), **C#** (ASP.NET Core), **Rust**, **PHP** (web / Laminas / Omeka-S),
**C**, **C++**, **Terraform**, **IaC** (Docker / compose / GitHub Actions),
**AT Protocol**. Specialty and experimental analyzers are opt-in: when one
matches a repo, `analyze` says so, and `-m <name>` runs it (`attackmap modules`
shows which). Details: [analyzers reference](https://docs.mlaify.io/analyzers/).
Write your own against the documented [analyzer SDK](docs/external-analyzers.md).

## CLI cheat-sheet

```bash
attackmap analyze <path>                  # review a repo (--output dir, --format all|json|markdown)
attackmap analyze repoA repoB …           # multi-repo fleet scan
attackmap analyze <path> --cve            # dependency CVEs (OSV.dev)
attackmap analyze <path> --recall         # widen taint discovery (extra reach = SPECULATIVE)
attackmap analyze <path> --llm            # AI narrative (--llm-provider claude|openai)
attackmap analyze <path> --hunt --verify  # LLM exploit-hypothesis hunt, adjudicated vs. source
attackmap analyze <path> --triage         # cluster/dedupe/rank existing findings
attackmap analyze <path> --remediate      # review-first fix suggestions
attackmap analyze <path> --baseline prev.json --fail-on-new-high   # PR gate
attackmap suggest ./repo                  # recommend analyzer plugins    · attackmap modules  # list installed
```

Verify-jury knobs (`--verify-votes` / `--hunt-lenses` / `--hunt-rounds` /
`--hunt-budget`) and suppression (`--no-suppress` / `--suppress-file`) are
documented in the [CLI reference](https://docs.mlaify.io/cli/).

## What AttackMap is *not*

- **Not a runtime detector.** It's static; its detection hints are leads for your
  SIEM team, not deployable rules.
- **Not a replacement for dedicated SCA.** `--cve` folds CVE signal into an
  architecture-aware narrative; Trivy/Grype/Dependabot go deeper on resolution.
- **Not a sound taint engine.** Taint follows local assignments *within* one
  function (intra-procedural def-use) and a call-graph-refined import walk
  *across* files; it does not follow a value into a helper it is passed to, and
  branches are not distinguished. Precision over recall; findings are evidence,
  not proof. See the limits in `src/attackmap/taint_flow.py`.
- **Not exhaustive.** Heuristic by design, with explicit confidence tiers and
  guardrails for stale signals.

## Documentation & links

- **[docs.mlaify.io](https://docs.mlaify.io)** — user guide, install, CLI,
  analyzers, SDK
- **[Wiki](https://github.com/mlaify/AttackMap/wiki)** — architecture, roadmap,
  contributor references
- **[Roadmap / Bug Triage / Kanban](https://github.com/orgs/mlaify/projects)** —
  project boards · [Road to 1.0](https://github.com/mlaify/AttackMap/issues/209)
- [`CHANGELOG.md`](CHANGELOG.md) · [`CONTRIBUTING.md`](CONTRIBUTING.md) ·
  [`SECURITY.md`](SECURITY.md) · [`VISION.md`](VISION.md)

## Special thanks

AttackMap is built by its contributors.

<a href="https://github.com/mlaify/AttackMap/graphs/contributors"><img src="https://contrib.rocks/image?repo=mlaify/AttackMap" alt="AttackMap contributors" /></a>

## Contributing

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). By contributing
you agree your contributions will be MIT-licensed.

## License

[MIT](LICENSE). Copyright (c) 2026 Matthew Davis and AttackMap Contributors.
