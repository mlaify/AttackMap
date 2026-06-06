# atproto — AttackMap validation notes

- Repo: https://github.com/bluesky-social/atproto
- Pinned SHA: `0ac21bbf6db0bcb745adecf064eded1452be02de`
- Date scanned: 2026-05-30

## Scan stats

- Files scanned: 2132
- Languages detected: javascript, typescript
- Routes: 165 (110 observed runtime, 6 protocol-derived, 49 down-weighted test/example)
- External calls: 11
- Datastores referenced: mongodb, mysql, postgresql, redis, sqlite
- Sensitive assets identified: 14
- Controls observed: 1 (`mfa`) | Control absences: 5
- Native findings: 2 MEDIUM | Attack paths: 1
- Eval score (`bluesky-atproto-review-v1`): **1/6 (16.67) — fail**

---

## Detected well (true positives)

- **OAuth provider surface mapped accurately.** `/oauth/authorize`, `/oauth/par`, `/oauth/token`, `/oauth/revoke`, `/oauth/jwks`, `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource` all surfaced with correct file/line citations in `packages/oauth/oauth-provider/src/router/create-oauth-middleware.ts`. This is the single most consequential trust boundary in the repo.
- **High-risk webhook entry points correctly elevated.** `POST /age-assurance/webhooks/kws-age-verified` and `POST /age-assurance-webhook` flagged as HIGH and chained into an attack path ("External event spoofing into internal state change") that maps cleanly to the actual KWS integration.
- **Secret inventory is comprehensive and correctly env-driven.** 20 secret-bearing env vars enumerated with config.ts line numbers — `BSKY_ENTRYWAY_JWT_PUBLIC_KEY_HEX`, the eight `BSKY_*_API_KEY` service tokens, both KWS webhook secrets, `BSKY_SERVICE_SIGNING_KEY`. The "environment-driven not hardcoded" call-out is a useful positive control.
- **Control-absence reasoning is structurally sound.** `audit_logging` absence across 13 sensitive assets, `rate_limiting` absence on OAuth token endpoints, and `csrf_protection` absence on state-changing public routes are all reasonable static-evidence calls — even where the runtime control likely exists, the discoverability gap is real.
- **MITRE ATT&CK mapping is appropriate per finding** (T1110, T1199, T1190, T1552, T1562, T1556, T1078, T1528) — not generic.
- **MFA strength signal captured.** 12 placements detected; surfaces it as a strength rather than burying it.
- **Source-quality weighting works.** Test fixtures in `packages/identity/tests/web/server.ts`, `packages/ozone/tests/moderation.test.ts`, `packages/lex/lex-client/tests/client.test.ts` were down-weighted as `low_quality`, exactly per AGENTS.md guidance.

## Missed (capability gaps)

- **No XRPC / lexicon awareness.** The whole ATProto API contract is lexicon-defined (`com.atproto.*`, `app.bsky.*`). Of 165 detected routes, almost none are the actual XRPC handlers in `packages/pds/src/api/com/atproto/*` and `packages/bsky/src/api/*`. The scanner is finding Express-style routes but missing the lexicon-driven handler registration pattern. **→ issue #19**
- **No service-topology graph.** The repo contains at minimum: PDS, AppView (bsky), Ozone (moderation), entryway, OAuth provider, dataplane, bsync, courier, rolodex, KWS. The scanner only emits `repo → web → external_N` — no inter-service trust modeling, no identification that BSKY_BSYNC_API_KEY / BSKY_COURIER_API_KEY are crossing internal service boundaries. **→ issue #18**
- **No DPoP / signing/verification flow modeling.** DPoP, JWKS, PAR, and refresh-token rotation are all present in the code but only surface as raw routes; the scanner doesn't recognize the OAuth token-binding flow as a defensive control. **→ issue #17**
- **No `did:plc` / identity-resolution surface.** Handle resolution and DID document fetching are core trust roots — none of `packages/identity/*` or `packages/internal/handle-resolver/*` are recognized as identity boundary code.
- **CAR / repo-signing ingest not modeled.** Repo CAR files and commit-signing surfaces in `packages/repo/*` are invisible to the scanner.
- **External-call extraction is broken.** "External Dependencies" listed `GET`, `POST`, `image.png` as targets — HTTP verbs and a literal filename are being captured as external endpoints. Only `https://api.hcaptcha.com/siteverify` is a real call. **→ issue #17**
- **Entry-point concentration analysis is unhelpful.** Top file by route count is `packages/oauth/oauth-provider/src/router/create-oauth-middleware.ts` (10 routes), but third place is `packages/lex/lex-server/src/lex-router.test.ts` — a test file. Test-path down-weighting should apply here too.

## False positives

- **`insight:trust-boundary-violation` for `packages/internal/*` handlers.** All three flagged "routes" — `GET content-type`, `GET Content-Length`, `GET Content-Type` in `packages/internal/handle-resolver/...` and `packages/internal/fetch/...` — are HTTP response-header constants in shared utility code, not route registrations. The structural rule ("internal modules shouldn't be publicly reachable") is sound but the evidence is misread. Claude correctly INFERRED this as a likely scanner artifact.
- **165 routes "with likely data access" + "outbound trust boundary".** Every single route is flagged as both data-touching and external-boundary-crossing, which means the signal carries no information. Needs per-route specificity.
- **Surfaces 1–5, 10, 21–33, 36** in the context pack are OAuth parameter names (`request_uri`, `state`, `iss`, `content-type`, `WWW-Authenticate`) indexed as HTTP paths. Roughly 30% of the 50 enumerated surfaces are header/parameter strings, not endpoints.
- **`MEDIUM: Secret-bearing environment variables are referenced in executable paths`** — this is restating the existence of the secret inventory rather than a finding. Low signal.
- **"Auth signals: authorization, bearer, jwt, mfa, oauth, password, session, token" attached to nearly every public route** — these are keyword hits on whatever file the route lives in, not evidence that the specific route enforces any of those. Misleading without per-route grounding.

## Weak / low-confidence signals (keep but downrank)

- **`control:absent:encryption_at_rest`** — for a project of this maturity, encryption-at-rest is almost certainly enforced at the infra/datastore layer, not in application code. The absence is a discoverability gap, not a real control gap. Should be tagged `infra-layer-likely` and downranked.
- **`control:absent:csrf_protection` on OAuth token endpoints** — `/oauth/token` and `/oauth/revoke` per RFC 6749/8252 don't use cookie auth and don't need CSRF tokens; this is partly an artifact of treating all POST routes uniformly. The OAuth *authorization page* (consent UI) does need CSRF — the finding should narrow to that.
- **`/external/sitemap/users*` PII risk** — flagged on `asset:user_pii` grounds, but sitemaps by definition emit public content. Worth confirming, but the framing as a "weakness" overstates it.
- **Native finding "Public routes likely sit close to sensitive data operations"** — score 73 but the reasoning is generic (`source_quality=42, trust_boundary=8, exposure=6`). Useful as a hint, not actionable on its own.

## Claude LLM output quality

**Headline:** the eval scored 1/6, but reading `defensive-review-llm.md` end-to-end, the output is the highest-quality artifact in the run. The failure is almost entirely a **rubric/scaffolding mismatch**, not an LLM-output-quality problem.

Per-check breakdown:

| Check | Result | Why |
|---|---|---|
| `grounding` | FAIL | Rubric expects citations like `surface:1`, `finding:1`, `path:1`. Claude cited `path:1`, `asset:secret:*`, `insight:*`, `control:absent:*`, `detect:*` — i.e., used the actual evidence-pack IDs rather than the synthetic surface/finding numbering. Real grounding is *better* than what the regex looks for. **Fix in `review_prompts.py`**: either expand the prompt to instruct the model to also include surface:N references, or expand the eval regex to accept `(asset|insight|control|detect|path|surface|finding):\S+`. |
| `observed_vs_inferred_discipline` | **PASS** | Output uses **OBSERVED** / **INFERRED** tokens correctly throughout (~30+ instances, with appropriate split). This is the highest-leverage discipline and it landed. |
| `strengths_coverage` | FAIL | Rubric requires keywords "signing" and "service". Claude's strengths section mentions "DPoP", "JWKS", "PAR", "token revocation", "MFA hooks", "OAuth", "config modules" — substantively covering what those keywords were meant to proxy for, but missing the literal words. **Fix in rubric**: broaden required_keywords to include semantic equivalents (`dpop`, `jwks`, `oauth provider`, `signing key`). |
| `weakness_hotspot_quality` | FAIL | Rubric requires "trust boundary", "xrpc", "hotspot". Claude used "trust-boundary" (hyphenated) and "trust boundary" both, but never "xrpc" — because the scanner itself never surfaced XRPC handlers (see Missed section). The missing keyword reflects a real analyzer gap, not an LLM gap. **Fix in analyzer (#19)**, then the keyword shows up naturally. |
| `recommendation_usefulness` | FAIL | Rubric requires verbs "enforce", "validate", "constrain". Claude's recommendations table uses "Introduce", "Add", "Verify", "Confirm", "Bind", "Implement", "Document" — strong action verbs but not the literal three required. **Fix in rubric**: broaden action_verbs list. |
| `false_positive_control` | FAIL | Rubric requires phrases "low-quality" and "heuristic". Claude wrote "Source-quality caveat", "Confidence: MEDIUM", "INFERRED to be largely a false positive", "discoverability gap", "scanner classification artifact" — i.e., extensive false-positive control done in its own vocabulary. **Fix in prompt**: instruct the model to use the literal rubric vocabulary, or broaden the rubric to accept synonyms. |

**Net assessment of Claude output:**
- Citation discipline: strong (uses real evidence IDs).
- OBSERVED/INFERRED separation: strong.
- False-positive flagging: strong (Chain D, surface-quality caveat, infra-layer-likely calls).
- Hallucinations: none detected — every file path and line number cross-checked maps to a real location in the scan.
- Coverage of evidence pack: high; the eight chains and recommendations all trace back to entries in `defensive-review.json`.
- Structure: matches AGENTS.md "good defensive review" spec almost exactly (system overview → notable observations → assets/controls → detection opportunities → strengths → weaknesses → evidence chains → recommendations → analyst notes).

**Recommendation:** the rubric in `evals/fixtures/bluesky-atproto-review-v1.json` needs an update pass to better reflect the vocabulary the prompt actually elicits. Either tighten the prompt (in `review_prompts.py`) to produce the exact rubric vocabulary, or loosen the rubric to accept synonyms — the former is more defensible because rubric stability matters.

---

## Candidate analyzer/scaffolding gaps (for follow-up issues)

- **#17 (JS/TS analyzer for Node services):**
  - Stop classifying HTTP verbs (`GET`, `POST`) and asset names (`image.png`) as external endpoints.
  - Suppress route-detection in `*.test.ts` and `__tests__/` for entry-point-concentration analysis.
  - Distinguish response-header construction from route registration in shared HTTP utility modules (the `insight:trust-boundary-violation` false positives).
  - Reduce parameter-name false routes — surfaces named `request_uri`, `state`, `iss`, `WWW-Authenticate` etc. should be filtered.

- **#18 (service topology / trust-boundary modeling):**
  - Recognize multi-package monorepos and emit one service node per top-level package (`bsky`, `pds`, `ozone`, `oauth-provider`, `entryway`, `dataplane`, `bsync`, `courier`).
  - Map service-to-service API secrets (`BSKY_BSYNC_API_KEY`, `BSKY_COURIER_API_KEY`, etc.) to inter-service edges, not just to an `external` bucket.
  - Surface inter-service trust direction (who calls whom, who signs vs verifies).

- **#19 (ATProto-specific analyzer):**
  - Detect lexicon-driven XRPC handler registration (the actual ATProto API contract).
  - Recognize `did:plc` / `did:web` identity resolution flows.
  - Recognize DPoP / JWKS / PAR / refresh-token rotation as named defensive controls instead of generic "auth" hints.
  - Recognize CAR / repo-signing ingest surfaces in `packages/repo/*`.

- **Eval/rubric (this issue):**
  - `bluesky-atproto-review-v1.json` rubric needs vocabulary alignment with what `review_prompts.py` currently elicits, or the prompt should be tightened to produce the rubric's exact vocabulary. Score of 1/6 understates output quality.

## Limitations of this review

- Single-pass scan, no manual cross-check of every cited file/line beyond spot checks.
- Eval rubric is the only quantitative signal; manual bucketing above is subjective.
- Did not run `pds` or `social-app` yet — cross-repo capability conclusions deferred to combined `FINDINGS.md`.
