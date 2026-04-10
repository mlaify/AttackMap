# AGENTS.md

## Project
AttackMap is an open source security analysis tool that explains a codebase from an attacker’s perspective.

Its purpose is to:
- infer architecture from code and config
- identify attack surface
- generate initial threat findings
- map plausible attack paths
- produce useful reports for engineers and security reviewers

## Product framing
AttackMap is not a generic AI code explainer and not a classic static analyzer.
Its unique value is system-level security reasoning:
- entry points
- trust boundaries
- data flows
- reachable attack paths
- practical mitigations

When making suggestions, preserve this framing.

## Current stack
- Python 3.11+
- Typer CLI
- Pydantic
- NetworkX
- pytest
- GitLab-first workflow

## Repo layout
- `src/attackmap/cli.py` - CLI entrypoint
- `src/attackmap/scanner.py` - heuristic repo scanning
- `src/attackmap/graph.py` - graph construction
- `src/attackmap/analyzer.py` - architecture and attack surface summaries
- `src/attackmap/threat_model.py` - findings and attack path generation
- `src/attackmap/report.py` - markdown/json report writing
- `src/attackmap/models.py` - Pydantic models
- `tests/` - test suite
- `examples/` - demo apps for local testing

## How to work
Prefer small, reviewable changes.
Before editing code:
1. understand the current implementation
2. explain your plan briefly
3. make minimal changes
4. run tests if available
5. summarize exactly what changed

## Commands
Install:
`pip install -e .`

Run tests:
`pytest`

Run CLI:
`attackmap analyze .`
`attackmap analyze examples/vulnerable-demo-app --output reports`

## Engineering preferences
- keep functions focused and readable
- prefer explicit data models
- avoid adding heavy dependencies without strong justification
- write or update tests with behavior changes
- keep security language concrete, not hypey
- document assumptions and heuristic limitations

## MVP priorities
Highest priority:
1. better framework detection for FastAPI, Flask, and Express
2. better route extraction
3. datastore detection improvements
4. attack surface and attack path quality
5. cleaner report structure
6. example projects and demo output

Lower priority:
- full LLM integration
- UI
- distributed analysis
- large refactors

## Output expectations
Good output should help answer:
- what is exposed?
- what can talk to what?
- where are trust boundaries?
- how might an attacker chain weaknesses together?
- what should be fixed first?

## Definition of done
A task is done when:
- code is correct and focused
- tests pass or are updated appropriately
- CLI behavior is preserved unless intentionally changed
- output is more useful to a security-minded engineer
- assumptions and limitations are documented
