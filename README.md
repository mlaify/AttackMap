# AttackMap

**Local-first, AI-assisted defensive security analysis for codebases.** AttackMap
reads a repository (or a whole fleet of them), reconstructs the attack surface —
routes, data stores, external calls, auth signals, trust boundaries — traces
request-to-sink data flow, and produces an evidence-grounded, prioritized security
review. It finds the cross-cutting weaknesses single-file scanners miss, and never
sends your code anywhere.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/attackmap.svg)](https://pypi.org/project/attackmap/)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)

> **Status: beta (v0.4.27).** Core engine + 14 analyzer plugins published to PyPI,
> Homebrew, and GHCR, validated on real codebases. AttackMap is heuristic by
> design — findings are confidence-tiered evidence, not proof. Roadmap to 1.0:
> [issue #209](https://github.com/mlaify/AttackMap/issues/209).

Full documentation: **[docs.matthewd.xyz](https://docs.matthewd.xyz)** ·
architecture & internals: **[wiki](https://github.com/mlaify/AttackMap/wiki)**.

### The macOS app

Prefer a GUI? A native macOS front-end drives this CLI and renders every result
view — `brew install --cask mlaify/tap/attackmap-app` (pulls the CLI too).

| Overview | Exploitability |
|---|---|
| [![AttackMap macOS app — overview](https://raw.githubusercontent.com/mlaify/AttackMap/main/docs/screenshots/04-overview.png)](https://docs.matthewd.xyz/gui/) | [![AttackMap macOS app — exploitability](https://raw.githubusercontent.com/mlaify/AttackMap/main/docs/screenshots/06-exploitability-ranked.png)](https://docs.matthewd.xyz/gui/) |

*Scanning OWASP Juice Shop. Walkthrough in the [macOS app docs](https://docs.matthewd.xyz/gui/); source at [mlaify/AttackMap-mac](https://github.com/mlaify/AttackMap-mac).*

## Quickstart

```bash
pip install "attackmap[all]"              # or: brew install mlaify/tap/attackmap
attackmap analyze /path/to/repo           # heuristic review → reports/
attackmap analyze /path/to/repo --llm     # + AI-narrated review (Claude or OpenAI)
attackmap analyze ./svc-a ./svc-b ./gw    # cross-repo / fleet scan
```

Read `reports/defensive-review.md` for the heuristic review, and (with `--llm`)
`reports/defensive-review-llm.md` for the AI narration. `--llm` resolves auth
automatically (`ANTHROPIC_API_KEY`, or your Claude/`codex` CLI subscription); add
`--llm-provider openai` for OpenAI/Codex.

Other install paths: `pip install attackmap` (core only) or `"attackmap[llm]"`;
`docker run --rm -v "$PWD:/src" ghcr.io/mlaify/attackmap analyze /src`. Not sure
which analyzer plugins a repo needs? `attackmap suggest ./repo`. Full install and
CI setup: **[docs.matthewd.xyz/install](https://docs.matthewd.xyz/install/)**.

## What it finds

- **Attack-surface recon** — routes, data stores, external calls, auth signals,
  secrets, frameworks, entrypoints; every signal carries a `file:line` citation,
  evidence snippet, and confidence.
- **Data-flow / injection taint** (Python, JS/TS, Go, PHP) — SSRF, SSTI, NoSQL,
  unsafe deserialization, eval/exec/shell, SQL, open redirect — sanitizer-aware,
  with a deterministic 0–100 **exploitability score**.
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
See the [outputs reference](https://docs.matthewd.xyz/scanning/) for the full list.

## Supported ecosystems

Fourteen analyzer plugins (each installable on its own; `[all]` installs every one):
**Python**, **JavaScript/TypeScript** (Node services), **Go**, **Java/Kotlin**
(Spring), **C#** (ASP.NET Core), **Rust**, **PHP** (web / Laminas / Omeka-S),
**C**, **C++**, **Terraform**, **IaC** (Docker / compose / GitHub Actions),
**AT Protocol**. Details: [analyzers reference](https://docs.matthewd.xyz/analyzers/).
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
documented in the [CLI reference](https://docs.matthewd.xyz/cli/).

## What AttackMap is *not*

- **Not a runtime detector.** It's static; its detection hints are leads for your
  SIEM team, not deployable rules.
- **Not a replacement for dedicated SCA.** `--cve` folds CVE signal into an
  architecture-aware narrative; Trivy/Grype/Dependabot go deeper on resolution.
- **Not a sound taint engine.** The data-flow pass is a call-graph-refined
  import-graph walk — precision over recall; findings are evidence, not proof.
- **Not exhaustive.** Heuristic by design, with explicit confidence tiers and
  guardrails for stale signals.

## Documentation & links

- **[docs.matthewd.xyz](https://docs.matthewd.xyz)** — user guide, install, CLI,
  analyzers, SDK
- **[Wiki](https://github.com/mlaify/AttackMap/wiki)** — architecture, roadmap,
  contributor references
- **[Roadmap / Bug Triage / Kanban](https://github.com/orgs/mlaify/projects)** —
  project boards · [Road to 1.0](https://github.com/mlaify/AttackMap/issues/209)
- [`CHANGELOG.md`](CHANGELOG.md) · [`CONTRIBUTING.md`](CONTRIBUTING.md) ·
  [`SECURITY.md`](SECURITY.md) · [`VISION.md`](VISION.md)

## Contributing

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). By contributing
you agree your contributions will be MIT-licensed.

## License

[MIT](LICENSE). Copyright (c) 2026 Matthew Davis and AttackMap Contributors.
