# AttackMap

**Understand your system. Map your attack surface.**

AttackMap analyzes a codebase, infers a lightweight architecture model, highlights likely attack surfaces, and generates an initial threat model with concrete mitigations.

## Why AttackMap?

Most tools focus on isolated findings. AttackMap is designed to answer a more useful question:

> If I were attacking this system, where would I start, what could I reach, and what should the team fix first?

## Current MVP features

- Detects common web routes in Python and JavaScript projects
- Flags likely databases, external HTTP calls, auth hints, and secrets-like environment variables
- Builds a simple system graph
- Generates:
  - architecture summary
  - attack surface summary
  - findings
  - attack paths
  - mitigations
- Writes both Markdown and JSON reports

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Usage

```bash
attackmap analyze .
attackmap analyze . --output reports
attackmap analyze . --format json
```

## Example output files

- `architecture.md`
- `attack-surface.md`
- `attackmap-report.json`

## Roadmap

- Tree-sitter based parsing
- Terraform / Docker / Kubernetes support
- GitLab MR diff-aware attack surface analysis
- LLM provider abstraction
- Confidence scoring per finding

## GitLab

This project is structured to be GitLab-friendly out of the box with a simple CI pipeline in `.gitlab-ci.yml`.

## License

MIT
