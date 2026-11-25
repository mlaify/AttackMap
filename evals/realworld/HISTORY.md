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

## #455, #456, #457, #446 (2026-11-24)

| Detector class | Precision | Recall | TP / FP / expected |
|---|---|---|---|
| `injection` | 90% | 68% | 9 / 1 / 28 |
| `bola` | 100% | 83% | 2 / 0 / 6 |
| `token_auth` | 100% | 100% | 3 / 0 / 2 |
| `crypto` | 80% | 83% | 4 / 1 / 6 |
| `unauth_state_change` | 0% | 0% | 0 / 1 / 1 |

Crypto 50% / 50% → 80% / 83%: comments, prints and prose no longer match (#457), and an MD5 wrapper called with a password is found (#446). #455 and #456 change per-location results inside matched findings (DVWA `exec/impossible.php` is sanitized; `header()` Location is an open redirect).

## PyGoat case and its fixes (2026-11-24)

Corpus: + OWASP PyGoat v3.0.0 (`e5808dd`), 15 labels. 59 labels in total.

| Detector class | Precision | Recall | TP / FP / expected |
|---|---|---|---|
| `injection` | 94% | 72% | 16 / 1 / 39 |
| `bola` | 100% | 83% | 2 / 0 / 6 |
| `token_auth` | 100% | 100% | 3 / 0 / 2 |
| `session_auth` | 100% | 100% | 1 / 0 / 1 |
| `crypto` | 86% | 89% | 6 / 1 / 9 |
| `unauth_state_change` | 0% | 0% | 0 / 2 / 1 |

Fixes found on PyGoat: `c`/`cur` cursors are SQL sinks (`sql_injection_lab` was missed); `yaml.load(Loader=yaml.Loader|UnsafeLoader|FullLoader)` is unsafe; a filename allow-list is no guard for deserialized content; SAX `setFeature(feature_external_ges, True)` is XXE; `redirect(request.referrer)` is not an open redirect. Still missed: Pillow `ImageMath.eval` (CVE-2023-50447) and the stored SSTI (template written to a file, then rendered).

## WebGoat case and its fixes (2026-11-24)

Corpus: + OWASP WebGoat v2026.5 (`7e198f3`), 21 labels (lessons under `src/main/java/org/owasp/webgoat/lessons`). 80 labels in total.

| Detector class | Precision | Recall | TP / FP / expected |
|---|---|---|---|
| `injection` | 95% | 75% | 20 / 1 / 56 |
| `bola` | 100% | 83% | 2 / 0 / 6 |
| `token_auth` | 100% | 40% | 3 / 0 / 5 |
| `session_auth` | 100% | 100% | 1 / 0 / 1 |
| `crypto` | 88% | 90% | 7 / 1 / 10 |
| `unauth_state_change` | 0% | 0% | 0 / 3 / 1 |

WebGoat injection went from 67% / 19% to 100% / 82%. Fixes: request input passed to a same-file helper is now traced up to two calls deep (WebGoat's SQL lessons call `injectableQuery(query)`); Spring `"redirect:" + url` views, `RedirectView` and `sendRedirect` are open-redirect sinks; Java `String.matches("…")` counts as a full-match guard (SSRF task 2 only fetches one exact URL); core's crypto rules now run on `.java`/`.kt` files (before this, `MessageDigest.getInstance("MD5")` was never checked in a real scan), and the Java MD5/SHA-1 rule needs a secret passed to `update`/`digest`. token_auth recall is down only because the new labels are Java JWT cases, and core has no Java JWT checks yet (#472). Still missed: helpers in another class (`CommandExecutionService`, `CommentsCache.parseXml`, `ProfileUploadBase.execute`).

## #472 Java JWT (2026-11-24)

token_auth 100% / 40% → 100% / 100% (5 / 0 / 5); no other class changes. Core now checks jjwt and auth0 java-jwt in Java/Kotlin: `Jwts.parser()…parse(token)` accepts unsigned tokens, short hard-coded HMAC keys are reported at the literal or its constant, and `Algorithm.none()` and `JWT.decode` without `JWT.require` are flagged. On WebGoat this reports 7 locations, all in the JWT lessons.
