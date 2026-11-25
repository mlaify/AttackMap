# Versioning and compatibility

AttackMap follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
From 1.0.0, a minor or patch release never breaks the interfaces listed below.
Only a new major version can, and it removes nothing without a deprecation
period first.

## What the version covers

| Interface | Stable within a major version | Enforced by |
|---|---|---|
| **CLI** | Commands, options and their values, defaults, and exit codes. New commands and options may appear in any minor release. | `attackmap capabilities` lists what a given CLI supports; the docs site's CLI reference is tested against `--help`. |
| **Report files** | `attackmap-report.json`, `defensive-review.json` and `review-context-pack.json` each carry their own `schema_version` with its own semver: minor versions only add. See [schemas.md](schemas.md). | `tests/test_schema_contract.py` and the frozen snapshots in `schemas/frozen/`. |
| **SARIF** | SARIF 2.1.0. `ruleId` values are the stable rule ids. | `tests/test_rule_ids.py` |
| **Rule ids** | A rule id, once released, keeps its meaning. It is used in suppressions (`rule:`, `attackmap:ignore[...]`) and listed by `attackmap rules`. A rule may be retired, but its id is never reused for something else. | `tests/test_rule_ids.py` |
| **Analyzer SDK** | Every name in `attackmap.sdk.__all__` keeps working for all of SDK 1.x (`attackmap.sdk.SDK_VERSION`). The SDK version is independent of the package version. | `attackmap.sdk.testing.assert_conforms`; the `plugin-matrix` CI job runs all 15 official analyzers against every core change. |

## What it doesn't cover

- **Findings.** Detection improves in every release, so the same repository can
  produce different findings, scores and confidence values after an upgrade.
  That isn't a breaking change. To gate CI on findings, use `--baseline` with
  `--fail-on-new-high` rather than an exact finding count.
- **Python internals.** Modules outside `attackmap.sdk` (for example
  `attackmap.taint`) are implementation details and can change in any release.
- **Markdown reports and console output**, which are for people to read, not for
  parsing. Parse the JSON reports instead.
- **Supported Python versions.** Dropping a Python version that is past its
  upstream end of life happens in a minor release, and the changelog says so.

## Deprecation

Removing or renaming any of the covered interfaces works like this:

1. A minor release keeps the old form working, warns when it is used, and names
   the replacement in the warning and the changelog.
2. The old form goes away only in the next major release.

For example, the old title-slug suppression selectors kept working, with a
warning that names the new rule id.

## Analyzers

Each `attackmap-analyzer-*` plugin has its own version. Its
`metadata.requires_core` (for example `>=0.8,<2`) states which core releases it
supports, and core skips an analyzer whose range doesn't match, with an upgrade
hint. `attackmap[all]` pins the official analyzers that were tested with that
core release.
