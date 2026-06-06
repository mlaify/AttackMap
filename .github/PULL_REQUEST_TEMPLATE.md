<!--
Thanks for opening a pull request! A few things to check before submitting:
1. Tests run cleanly: `pytest`
2. CHANGELOG.md has an entry under [Unreleased] for any user-facing change
3. New signals carry file:line citation + evidence text + confidence
-->

## Summary

<!-- One or two sentences describing the change. -->

## Motivation

<!-- Why is this change needed? Link to any related issue. -->

Fixes # <!-- (issue number if applicable) -->

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing behavior to change)
- [ ] New analyzer plugin
- [ ] Documentation update
- [ ] CI / tooling / hygiene

## Testing

<!-- What did you do to verify this change? -->

- [ ] `pytest` passes locally
- [ ] Added or updated tests covering the change
- [ ] Ran `attackmap analyze` on a sample repo (for pipeline-affecting changes)

## CHANGELOG

- [ ] Added an entry to `CHANGELOG.md` under `[Unreleased]`

## Checklist

- [ ] My code follows the existing style in the repo
- [ ] I have performed a self-review of my own code
- [ ] New signals carry `file:line`, evidence text, and confidence (where applicable)
- [ ] No secrets, API keys, or PII included in this diff
