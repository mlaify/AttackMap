# Contributing to AttackMap

Thanks for your interest in improving AttackMap. This document describes how to
set up a development environment, run the tests, and submit changes.

## Code of Conduct

This project adheres to the [Code of Conduct](CODE_OF_CONDUCT.md). By
participating, you agree to uphold it. Report unacceptable behavior privately with GitHub's
**Report content** option (choose **Report to repository admins**).

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

### Adding a new detector rule

Every rule id that `attackmap rules` lists needs a taxonomy entry: at least
one CWE and one OWASP category (Top 10 2021 or API Security Top 10 2023), plus
optional ASVS 4.0.3 and ATT&CK ids. Add one line to `RULE_TAXONOMY` in
[`src/attackmap/taxonomy.py`](src/attackmap/taxonomy.py); the module docstring
explains the fields. `tests/test_taxonomy.py` fails for any unregistered rule.
Look the ids up at cwe.mitre.org, owasp.org and attack.mitre.org rather than
from memory, and add any new CWE or technique to the catalogs in that file.

### Adding a new analyzer plugin

The full developer cookbook — scaffolding, the contract, testing, and
releasing — is in [`docs/external-analyzers.md`](docs/external-analyzers.md).
Use one of the existing plugin repos (Python or Go are the most thorough) as
a working template.

## Releasing core

Maintainers cut a core release in this order:

1. **Analyzers first**, if any changed. Release each plugin from its own repo (a version-bump PR, then a signed
   `v*` tag). Then run `python scripts/update_plugin_lock.py`, which pins the released versions in the `[all]`
   extra and their commits in `src/attackmap/plugins_lock.py`. Merge that only once every pinned version is on PyPI.
2. **Green gates on `main`**:
   - the `pytest` matrix and `ruff`;
   - the **`plugin-matrix`** job: all 15 official analyzers' tests against this core;
   - the real-world benchmark against its baseline (`attackmap bench --benchmark evals/realworld/benchmark.json
     --baseline evals/realworld/baseline.json`, or `gh workflow run realworld-bench.yml`);
   - the scan-time budget (`scripts/perf_budget.py`).
3. **Version-bump PR**: date the `[Unreleased]` section of `CHANGELOG.md` and add its compare link; bump
   `__version__` in `src/attackmap/__init__.py` and the README status line. If the report schema changed, freeze
   the new version (`python scripts/schemas.py freeze`, see [`docs/schemas.md`](docs/schemas.md)).
4. **Tag**: `git tag -s vX.Y.Z -m "AttackMap X.Y.Z"` on the merged commit, and push it.
5. **Approve**: `release.yml` waits on the `release` and `pypi` environments. The required reviewer runs
   `scripts/pypi/approve-releases.sh`; it checks the tag's signature, commit and version before approving.
6. **After**: the Homebrew formula bumps itself once PyPI's one-day cooldown has passed.

## Reporting security issues

Please do **not** open public issues for security vulnerabilities. Use this
repository's **Security** tab and select **Report a vulnerability** — see
[SECURITY.md](SECURITY.md) for the full disclosure policy.

## License

By contributing to AttackMap, you agree that your contributions will be licensed
under the [MIT License](LICENSE).
