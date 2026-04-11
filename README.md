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

## Analyzer Architecture

AttackMap is the core engine. It remains responsible for:

- CLI orchestration
- running registered analyzers
- merging analyzer output
- graph construction
- findings and attack path generation
- report rendering

Analyzers are responsible for inspecting a repository and emitting structured data. For the first migration step, the analyzer contract reuses the existing `ScanResult` model so the rest of core can stay stable.

### Built-in analyzer

The current heuristic scanner behavior is now split across:

- `python-web` as the first specialized built-in analyzer
- `default` as the fallback analyzer for the rest of the current built-in scanner coverage

CLI behavior stays the same, but core now has a clearer seam for future installed analyzers with narrower responsibilities.

Each analyzer now exposes lightweight metadata:

- `name`
- `description`
- `scope`
- supported `ecosystems`

### What an external analyzer would implement

An external repository such as `attackmap-analyzer-php-laminas` in `matthewd.xyzAI/attackmap-analyzers` only needs to implement the analyzer contract and return structured data:

```python
from pathlib import Path

from attackmap.analyzers import Analyzer, AnalyzerResult
from attackmap.models import Route


class PhpLaminasAnalyzer(Analyzer):
    metadata = AnalyzerMetadata(
        name="php-laminas",
        description="Analyzer for Laminas MVC route and controller configuration.",
        scope="PHP Laminas and Omeka-style application structure.",
        ecosystems=("php", "laminas", "omeka-s"),
    )

    @property
    def name(self) -> str:
        return self.metadata.name

    def analyze(self, root: str | Path) -> AnalyzerResult:
        result = AnalyzerResult(root=str(Path(root).resolve()))
        result.languages.append("php")
        result.routes.append(Route(path="/admin", method="GET", file="module/Application/config/module.config.php"))
        return result
```

### Follow-up work for external analyzers

- Add installed-package discovery for analyzers published under `matthewd.xyzAI/attackmap-analyzers`
- Define analyzer metadata such as supported ecosystems and confidence
- Evolve `ScanResult` into a richer analyzer result model when framework-specific analyzers need more structure

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
