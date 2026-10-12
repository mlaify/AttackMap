# Benchmark history

Before/after `attackmap bench` results for detector changes, newest first.
Each row is scored against the corpus in `benchmark.json` as of that change, so
"before" and "after" use the same labels.

## #243 (part 1): JWT verification checks (v0.6.0)

Corpus change: new scored class `token_auth` (findings tagged `token-auth`)
and case `express-jwt-demo` with 4 labels: a short hard-coded HMAC secret
(`session.js:5`), `verify` with a public key and no `algorithms`
(`partner.js:8`), identity read from `jwt.decode` (`profile.js:5`) and a key
file path built from the header `kid` (`keys.js:5`). `admin.js` (decode for
the header, then a pinned verify) and `adminKey` (a fixed key map) are the
clean twins and must stay unflagged.

| Detector class | Precision before | Precision after | Recall before | Recall after | TP / FP / expected after |
|---|---|---|---|---|---|
| `token_auth` | — | 100% | 0% | 100% | 4 / 0 / 4 |
| `injection` | 100% | 100% | 100% | 100% | 3 / 0 / 5 |
| `bola` | 100% | 100% | 100% | 100% | 2 / 0 / 2 |
| `unauth_state_change` | 100% | 100% | 100% | 100% | 3 / 0 / 5 |
| `webhook_exposure` | 100% | 100% | 100% | 100% | 1 / 0 / 1 |

Before: `main` 81f8988 scored against the same corpus. `jwt-weakness` findings
carried no `token-auth` tag and were unscored, so the class had no matches.

## #239 — intra-procedural def-use taint propagation (v0.6.0)

Corpus change: added `express-docs-demo` (2 injection labels: `GET /docs/raw`
path traversal, `GET /preview` SSRF; its clean twins `GET /docs/view` and
`GET /status/:service` carry no label and must stay unflagged).

| Detector class | Precision before | Precision after | Recall before | Recall after | TP / FP / expected after |
|---|---|---|---|---|---|
| `injection` | — | 100% | 0% | 100% | 3 / 0 / 5 |
| `bola` | 100% | 100% | 50% | 50% | 1 / 0 / 2 |
| `unauth_state_change` | 100% | 100% | 40% | 40% | 2 / 0 / 5 |
| `webhook_exposure` | 100% | 100% | 100% | 100% | 1 / 0 / 1 |

Injection recall gaps closed: `orders-api-demo` `POST /orders:24`,
`GET /orders/search:40`, `POST /internal/reindex:50` (one SQL-injection finding
citing each traced route), and `express-docs-demo` `GET /docs/raw:12`,
`GET /preview:26`. On the original v0.5.0 corpus alone: injection 0% → 100%
recall (3/3) at 100% precision.
