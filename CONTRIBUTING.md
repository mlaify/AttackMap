# Contributing to AttackMap

Thanks for your interest in improving AttackMap. This document describes how to
set up a development environment, run the tests, and submit changes.

## Code of Conduct

This project adheres to the [Code of Conduct](CODE_OF_CONDUCT.md). By
participating, you agree to uphold it. Report unacceptable behavior to
[matthewd@matthewd.xyz](mailto:matthewd@matthewd.xyz).

## Getting started

AttackMap is a Python package. Development requires Python 3.11+.

```bash
git clone https://github.com/mlaify/AttackMap.git
cd AttackMap
python -m venv .venv
source .venv/bin/activate
pip install -e ".[llm]"
```

To run the analyzer plugins locally, install each one editable from its sibling
repo:

```bash
pip install -e ../attackmap-analyzer-python
pip install -e ../attackmap-analyzer-rust
# ...and so on for the analyzers you want to develop against
```

## Running the tests

```bash
pytest
```

The full core suite runs in under a second. Analyzer plugins each carry their
own `pytest` suite in their respective repos.

## Eval harness

To grade a generated review against a golden fixture:

```bash
python -m attackmap.review_eval \
  --fixture evals/fixtures/bluesky-atproto-review-v1.json \
  --review evals/samples/bluesky-atproto-good-review.md
```

Suite mode:

```bash
python -m attackmap.review_eval \
  --fixtures-dir evals/fixtures \
  --reviews-dir evals/samples
```

## How to contribute

### Reporting bugs

Open a [bug report](https://github.com/mlaify/AttackMap/issues/new?template=bug_report.md)
using the issue template. Please include:

- AttackMap version (`attackmap --version` once available, otherwise commit SHA)
- Python version and OS
- Reproduction steps
- Expected vs. actual behavior

### Suggesting enhancements

Open a [feature request](https://github.com/mlaify/AttackMap/issues/new?template=feature_request.md).
For larger design changes, please open an issue *before* writing code so we can
align on direction.

### Submitting changes

1. Fork the repository.
2. Create a topic branch from `main`.
3. Make your change, including tests.
4. Run `pytest` and confirm everything is green.
5. Add a CHANGELOG.md entry under `[Unreleased]` for any user-facing change.
6. Open a pull request using the [PR template](.github/PULL_REQUEST_TEMPLATE.md).

### Code style

- Match the surrounding style; the project does not currently enforce a single
  formatter, but new code should be type-annotated and pass `python -m compileall`.
- Keep changes focused. Smaller, scoped PRs review faster.
- Every signal-emitting code path should carry a `file:line` citation, an
  evidence-text snippet, and a confidence score. See `src/attackmap/sdk/` for
  the analyzer SDK contract.

### Adding a new analyzer plugin

Each language ecosystem lives in its own repo, named
`attackmap-analyzer-<ecosystem>`. To add a new one:

1. Use one of the existing plugin repos as a template (Python or Go are good
   starting points — both are comprehensive).
2. Register your analyzer under the `attackmap.analyzers` entry-point group in
   your plugin's `pyproject.toml`.
3. Emit Signal-v2 records (line numbers, evidence text, confidence).
4. Add tests covering your framework and database/auth/HTTP-client detections.

## Reporting security issues

Please do **not** open public issues for security vulnerabilities. Email
[matthewd@matthewd.xyz](mailto:matthewd@matthewd.xyz) — see
[SECURITY.md](SECURITY.md) for the full disclosure policy.

## License

By contributing to AttackMap, you agree that your contributions will be licensed
under the [MIT License](LICENSE).
