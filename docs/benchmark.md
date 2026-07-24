# Detection benchmark (`attackmap bench`)

The **1.0 precision gate** ([#197](https://github.com/mlaify/AttackMap/issues/197)).
Where `review_eval` grades LLM *review text*, this scores AttackMap's *findings*
against a hand-labeled corpus of ground-truth vulnerabilities and reports
**precision / recall / F1 per detector class**. Every future detector change
should report its delta here.

## Running it

```bash
attackmap bench                         # prints the per-class table
attackmap bench --output reports        # + benchmark-results.{md,json}
attackmap bench --fail-under 0.9        # CI gate: exit non-zero if any scored class drops below 0.9
```

Run from a repo checkout — the manifest ships in `evals/`, not the installed
wheel. Point `--benchmark` at a different manifest to score your own corpus.

## Methodology

- **Ground truth is labeled independently of the tool.** Each case in
  [`evals/benchmark/benchmark.json`](../evals/benchmark/benchmark.json) lists the
  genuine, exploitable weaknesses in a repo — read from the source, not derived
  from what AttackMap emits — so the score is not circular.
- **Only precise detector classes are scored.** `injection`, `bola`,
  `unauth_state_change`, `webhook_exposure`, `crypto`. Architectural / advisory
  findings (e.g. "public routes sit near sensitive data", secret-env
  *references*, admin-route groupings) make no precise claim and are **out of
  scope** — they never count as false positives. (`cve` is not scored by the
  default runner: it is offline+deterministic and does not query OSV, so a CVE
  label would only ever record a false negative — CVE benchmarking needs a
  recorded-OSV fixture, tracked as future work.)
- **Matching.** A finding is mapped to a canonical class from its tags/title, and
  matched to a label when the class agrees and its evidence cites the same
  **repository-relative** file, confirmed by an **exact route + method** match
  (`/orders` never matches `/orders/search`) or — when the finding cites no
  route — a line within a small window.
- **Metrics.** *Recall* = labels matched by ≥1 finding ÷ total labels; *precision*
  = scored findings that matched ≥1 label ÷ all scored findings. A grouped finding
  that legitimately cites several true routes helps recall without a precision
  penalty.

## Baseline (v0.4.28, example-app corpus)

| Detector class | Precision | Recall | Notes |
|---|---|---|---|
| `webhook_exposure` | 100% | 100% | Public unverified webhook detected. |
| `unauth_state_change` | 100% | 40% | Per-route detection is solid; **recall gap** — admin/internal-prefixed state-changing routes are absorbed by the admin-route grouping and not flagged individually. |
| `bola` | 100% | 50% | **Recall gap** — misses an id-addressed Flask read route. |
| `injection` | — | 0% | **Recall gap** — same-file f-string / concatenated SQL in `orders-api-demo` is not yet caught by the taint pass. |

**Precision is 100% across every scored class** — AttackMap's precise findings on
this corpus are all true positives. The value of the baseline is the honest
**recall gaps**, which are exactly the targets the [road to 1.0](https://github.com/mlaify/AttackMap/issues/209)
epics attack: injection depth, unauthenticated admin/internal routes, and broader
BOLA coverage. The corpus grows as new labeled cases (known-vuln and known-clean)
are added; the standing invariant enforced by tests is **precision = 100%** on the
curated set — a regression that introduces a false positive fails CI.
