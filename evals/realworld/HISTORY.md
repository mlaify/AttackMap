# Real-world benchmark history

Per-finding precision/recall per scored class on `evals/realworld/benchmark.json`
(pinned public repos, labels from each project's own vulnerability documentation,
checked against the code). `baseline.json` is the gate: `attackmap bench --baseline` fails if a class
drops more than 5 points below it.
Each detection PR records its delta here.

## Baseline — core 0.7.0, node-service 0.3.1 (2026-11-24)

Corpus: OWASP Juice Shop v20.4.0 (`266448a`), 18 labels.

| Detector class | Precision | Recall | TP / FP / expected |
|---|---|---|---|
| `injection` | 80% | 42% | 4 / 1 / 12 |
| `token_auth` | 100% | 100% | 3 / 0 / 2 |
| `bola` | 0% | 0% | 0 / 2 / 2 |
| `crypto` | 0% | 0% | 0 / 1 / 1 |
| `unauth_state_change` | 0% | 0% | 0 / 1 / 1 |

Per-finding scoring counts an aggregated finding once; the per-location false
positives behind these numbers are filed as #441 (i18n prose as secrets, 647
locations), #442 (`sequelize.query` SQLi missed), #443 (BOLA from snippet
files; basket IDOR missed), #444 (injection FPs), #445 (injection recall) and
#446 (crypto recall).
