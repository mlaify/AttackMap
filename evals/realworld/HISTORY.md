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

## #441, #442, #443 (2026-11-24)

Labels: +4 BOLA on Juice Shop (checkout, coupon, BasketItems, Recycles), found by
#443's handler resolution and confirmed against the code. 22 labels.

| Detector class | Precision | Recall | TP / FP / expected |
|---|---|---|---|
| `injection` | 80% → 83% | 42% → 58% | 5 / 1 / 12 |
| `bola` | 0% → 100% | 0% → 83% | 2 / 0 / 6 |
| `token_auth` | 100% | 100% | 3 / 0 / 2 |
| `crypto` | 0% | 0% | 0 / 1 / 1 |
| `unauth_state_change` | 0% | 0% | 0 / 1 / 1 |

- #442: both SQL injections found (`sequelize.query`, TS-annotated declarations).
- #443: BOLA follows the imported handler; 77 snippet-file locations gone. Per
  location 5 of 9 candidates are real. Public catalog lookups (deliveries, product
  reviews, order tracking) remain false positives.
- #441: `hardcoded-secret` 686 → 38 locations (advisory, unscored).

## #453 — PHP script entry points; DVWA case (2026-11-24)

Corpus: + DVWA 2.5 (`a96943d`), 21 labels (low/medium/high are vulnerable by
design, `impossible.php` is the clean twin). 43 labels in total.

| Detector class | Precision | Recall | TP / FP / expected |
|---|---|---|---|
| `injection` | 83% → 90% | 58% → 68% | 9 / 1 / 28 |
| `bola` | 100% | 83% | 2 / 0 / 6 |
| `token_auth` | 100% | 100% | 3 / 0 / 2 |
| `crypto` | 0% → 50% | 0% → 50% | 2 / 2 / 6 |
| `unauth_state_change` | 0% | 0% | 0 / 1 / 1 |

DVWA injection 100% P / 75% R per finding. Before #453 DVWA had no injection
finding. Misses: escaped-but-unquoted numeric SQL (medium), the session-stored
id (high, second order), `fi/index.php` include (source in another file).
Per-location false positives inside matched findings are filed: #455
(`exec/impossible.php`), #456 (`header()` Location reported as header
injection), #457 (crypto matches in comments/HTML).
