# Finding confidence

Every finding carries `confidence` on one scale, whichever detector made it:

| Level | Means | Examples |
|---|---|---|
| `high` | The evidence shows the weakness itself. | A traced request-to-sink flow; a literal insecure setting (`privileged: true`, `http_tokens = "optional"`); a verified JWT pattern. |
| `medium` | A strong signal with one link unverified. | A sink reached with no traced source; a structural match whose surrounding context wasn't read. |
| `low` | A lead for a human to confirm. | Speculative recall reach (`--recall`); business-logic heuristics (`race-check-then-act`, `idempotency-gap`); a documented insecure default inferred rather than read; weak signals. |

Rules core enforces for every detector (`attackmap.confidence`):

- Findings tagged `speculative`, `needs-review` or `weak-signal` are `low`.
- Confidence is separate from severity: severity is the impact if the
  finding is real, and confidence is how sure the evidence makes it. A finding's
  triage `score` combines the two.

`attackmap analyze --min-confidence medium` (or `high`) hides findings below
the threshold in every output (Markdown, JSON, SARIF, the baseline diff and
gates). `attackmap-report.json` then records
`"confidence_filter": {"min_confidence": "medium", "filtered": N}`, so a report
never silently omits findings.
