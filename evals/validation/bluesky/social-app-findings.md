# social-app — AttackMap validation notes

- Repo: https://github.com/bluesky-social/social-app
- Pinned SHA: `7f5dd4006970a67f11b85e3941a719cad293b078`
- Date scanned: 2026-05-30


## Important framing

`bluesky-social/social-app` is the **Bluesky client application** (React Native / Expo / web), but the repo is a **mixed monorepo**: alongside the client (`src/`) it contains three small server-side services — `bskylink/` (URL shortener, Express), `bskyogcard/` (Open Graph card / image rendering, Express), and `bskyembed/` (embed renderer) — plus `bskyweb/` (web wrapper). Most of the real server-side HTTP attack surface in this repo is in `bskylink/src/routes/*` and `bskyogcard/src/routes/*`, not in the React client code.

## Scan stats

- Files scanned: 1677
- Languages detected: javascript, typescript
- Routes: 84 (82 observed runtime, 0 protocol-derived, 2 down-weighted test)
- External calls: 2 (`https://go.bsky.app/link`, `https://public.api.bsky.app/xrpc/_health`)
- Datastores referenced: mongodb, postgresql
- Sensitive assets identified: 4
- Controls observed: 1 (`mfa` — suspect, see below) | Control absences: 4
- Native findings: 1 HIGH + 4 MEDIUM + 1 INFORMATIONAL
- Attack paths: 1 ("Public input into sensitive data path")
- Eval score (`bluesky-atproto-review-v1`): **1/6 (16.67) — fail** (identical failure pattern to atproto and pds)

---

## Detected well (true positives)

- **Mixed-monorepo subprojects correctly enumerated.** Claude's overview identifies the five subprojects (`src/`, `bskylink/`, `bskyogcard/`, `bskyembed/`, `bskyweb/`) and pulls the real server-side risk locus into the foreground — `bskylink` Express routes — rather than letting the React client code dominate.
- **Real Express routes in `bskylink` and `bskyogcard` captured with file/line citations.** `GET /`, `POST /link`, `GET /:linkId`, `GET /redirect`, `GET /_health`, `GET /metrics`, `GET /.well-known/apple-app-site-association`, `GET /avatar-bubbles`, `GET /start/:actor/:rkey` — all map to actual files in the repo.
- **`EXPO_PUBLIC_BITDRIFT_API_KEY` flagged as high-criticality and the `EXPO_PUBLIC_` prefix meaning correctly inferred.** This is the standout finding of the scan — the prefix guarantees client-bundle inlining, so any user can extract the key. Claude calls this out explicitly, maps it to T1552 / T1528, and recommends scope audit + rotation. This is exactly the kind of cross-cutting reasoning the tool exists to produce.
- **`SENTRY_AUTH_TOKEN` in `app.config.js` and `webpack.config.js` correctly contextualized as build-time** (less alarming than a runtime client secret), not lumped in with the production-runtime risks.
- **Session subsystem correctly localized.** `src/lib/jwt.ts` and `src/state/session/*` identified as the auth heart and tied to `asset:session` (critical).
- **`INFORMATIONAL` finding "obviously-benign routes carry auth signals" is a real win.** The scanner correctly self-flagged that `/.well-known/apple-app-site-association`, `/_health`, and `/metrics` have file-scope auth signals attached that shouldn't apply to those routes — `insight:stale-signal` is the kind of self-aware false-positive control AGENTS.md asks for.
- **External-call inventory is clean** (only 2 entries, both real URLs) — no `GET`/`POST`/`image.png` artifacts like atproto had.
- **Attack path "Public input into sensitive data path"** correctly identifies the structural concern even though the specific entry it picked is wrong (see false positives).

## Missed (capability gaps)

- **No React Native / Expo / mobile-app awareness.** The analyzer has no concept of:
  - **Client-bundled secrets** (`EXPO_PUBLIC_*` convention was correctly *flagged* by Claude as a one-off, but the scanner itself has no rule that turns `EXPO_PUBLIC_` into a "client-shipped" tag — that semantic was the LLM's, not the analyzer's).
  - **Deep-link / universal-link handlers** (`useIntentHandler.ts` showed up as "routes" but the intent-URL surface is a real risk category that's invisible to the scanner).
  - **`expo-secure-store` / Keychain usage** for client-side secret storage.
  - **`app.config.js` / `eas.json`** as configuration surfaces.
  - **React Navigation route definitions** vs. HTTP routes — the scanner conflates them (see false positives).
- **No XRPC client awareness.** The repo consumes ATProto XRPC heavily via `@atproto/api` (post, like, follow, repo writes, etc.) — none of the XRPC client calls surface as outbound trust-boundary edges.
- **No ATProto authentication-flow recognition.** OAuth client flow (`@atproto/oauth-client-browser`), DPoP token binding, session resumption logic — none surface as defensive controls.
- **No SDK/dependency surface.** `@sentry/react-native`, `@bitdrift/react-native`, `@statsig/*`, push-notification SDKs — all carry trust implications (telemetry/analytics endpoints, server-driven UI, remote config). The scanner has no model for SDK trust edges.
- **Push-notification surface invisible.** APNs/FCM push handling, notification deep-link payloads, and any token registration paths aren't modeled.
- **CI / supply-chain not analyzed.** `.github/workflows/`, Fastlane config, build-signing material — all out of scope of the current analyzer.
- **The `bskyogcard /metrics` "user PII" finding is structurally wrong.** `asset:user_pii` is rooted at `/metrics` only because the asset-classification heuristic matched on `metrics` near other words; this is a misclassification, not a missed surface — but the analyzer has no way to distinguish Prometheus-style ops `/metrics` from a PII-bearing endpoint. **→ feeds into #17.**

## False positives

- **Up to 50 of the 84 "routes" are not HTTP routes at all.** Claude's review pinpoints this: many `public_api` surfaces (surfaces 19–34) are **React state hooks / persisted state keys** — `languagePrefs`, `colorMode`, `disableHaptics`, `feed`, `embed-player.ts:619 GET ww`, `composer/drafts/state/api.ts:388 GET ww`. The scanner appears to be treating client state keys, react-query hooks, or string constants as HTTP routes. **This is the single biggest signal-quality issue in the whole validation pass.**
- **Architecture summary "Entry Point Concentration" top entry — `src/lib/strings/embed-player.ts: 12 routes` — is meaningless.** That file parses embed player URLs (YouTube, Vimeo, etc.); the "12 routes" are URL-parsing patterns, not HTTP route registrations. The "Likely Review Starting Point" recommendation then directs the analyst to a file that is not where the actual server-side risk lives — Claude had to manually correct this by pointing at `bskylink/src/routes/*`.
- **The single attack path `path:1` (`POST http://localhost:1986/` in `__e2e__/setupServer.js`)** is built on a test harness, not production code. The path itself ("Public input into sensitive data path") is a reasonable hypothesis but the entry point cited is wrong; Claude re-anchored it to the real `surface:8` POST `/link` instead.
- **The one "observed" control — `mfa` (strong, 4 placements)** — is evidenced by `MessageInput*.tsx` and `link-meta.ts`, where "mfa" most likely appears as a substring (regex pattern, library symbol, or filename) rather than as an MFA control. Calling this "strong MFA, scope=global" is materially misleading and Claude correctly flagged it for skepticism.
- **Auth signals on every public route ("bearer, jwt, mfa, password, session, token").** These are file-scope keyword hits, not per-route evidence. The same artifact as in atproto.
- **`asset:user_pii` rooted at `bskyogcard /metrics`.** Likely a Prometheus-style ops endpoint; classifying it as user PII drives an entire downstream control-gap chain that probably isn't real.
- **`control:absent:csrf_protection` on `bskylink` POST `/link`.** Possibly real, but if the endpoint is bearer-authenticated (no cookies), CSRF doesn't apply — same caveat as atproto's OAuth token endpoints.

## Weak / low-confidence signals (keep but downrank)

- **`control:absent:encryption_at_rest`** for mongodb/postgresql — almost certainly an infra-layer concern, not a code-layer omission.
- **`control:absent:rate_limiting`** as a global claim — likely enforced at the reverse-proxy / CDN layer for production endpoints, invisible to a code scan.
- **Datastores "mongodb, postgresql"** detected — these are referenced via `bskylink`/`bskyogcard` driver imports, but the scanner doesn't distinguish "imported but not actively used in this repo" from "primary persistence layer." For a client app monorepo, the qualifier matters.

## Claude LLM output quality

**Headline:** third repo, same 1/6 eval score, same five failed checks, same `observed_vs_inferred_discipline` pass. The pattern is now fully confirmed: **the eval rubric in `bluesky-atproto-review-v1.json` is misaligned with what the prompt elicits.** The LLM output is high-quality across all three repos; the score does not reflect that.

| Check | Result | Why |
|---|---|---|
| `grounding` | FAIL | Claude cited `surface:N` ~20 times, plus `finding:1`, `finding:2`, `path:1`, `asset:*`, `insight:*`, `control:*`, `detect:*` — citation discipline is the strongest of the three repos. The regex `(?:surface|finding|path):\d+` *does* match `surface:8`, `surface:36`, `finding:2`, `path:1` etc., so this check likely failed on the `allowed_ids` whitelist constraint (rubric allows only specific IDs like `surface:1`, `surface:2`, `surface:3`). **The rubric is over-restrictive on which IDs count.** |
| `observed_vs_inferred_discipline` | **PASS** | ~30 OBSERVED / INFERRED tokens used correctly. |
| `strengths_coverage` | FAIL | Rubric requires "signing" and "service". Claude's strengths mention "session subsystem", "Apple App Site Association", "health endpoints split out", "external-call surface narrow" — substantive, but missing the literal atproto-rubric vocabulary. |
| `weakness_hotspot_quality` | FAIL | Rubric requires "trust boundary", "xrpc", "hotspot". Claude uses "trust boundary" but never "xrpc" — because the social-app repo *consumes* XRPC but the analyzer doesn't surface XRPC client calls, so the LLM has no evidence to discuss. Same root cause as atproto: rubric requires content the analyzer doesn't expose. |
| `recommendation_usefulness` | FAIL | Rubric requires "enforce", "validate", "constrain". Claude's recommendations: "Audit", "Add", "Emit", "Verify", "Annotate", "Confirm" — strong action verbs, not the literal three required. |
| `false_positive_control` | FAIL | Rubric requires "low-quality" and "heuristic". Claude wrote: "Source-quality caveat", "scanner artifact", "treat with skepticism", "INFERRED", "may be a misclassification" — extensive FP control in its own vocabulary. |

**Per-check notes specific to social-app:**

- **Best LLM run of the three.** Claude detected and explicitly called out *three* distinct scanner artifacts that the user would otherwise have wasted time on: (1) React state hooks classified as routes, (2) test fixtures classified as production surfaces, (3) the `mfa` "control" being substring evidence. This kind of meta-level scanner skepticism is exactly the value-add of having an LLM layer.
- **Bundling inference on `EXPO_PUBLIC_*` is the highest-leverage cross-cutting insight** produced in the entire three-repo run. The scanner just saw a secret; Claude knew the prefix shipped to clients. That's domain knowledge static analysis cannot produce.
- **Citation density is high** (~35 distinct evidence IDs cited across §1–§9).
- **Hallucinations:** none detected on spot check; file/line references verify against the scan.
- **Honest about static-only limits:** every absent-control claim is qualified with "may live at infra/proxy layer not visible to the scanner" — exactly the AGENTS.md "observed vs inferred" discipline.

---

## Candidate analyzer/scaffolding gaps (for follow-up issues)

- **#17 (JS/TS analyzer for Node services):**
  - **Stop classifying React state hooks, `useQuery`/`useMutation` keys, persisted-state keys, and URL-parsing patterns as HTTP routes.** This is the single biggest signal-to-noise problem in this run.
  - **Detect `EXPO_PUBLIC_*` prefix as "client-bundled secret"** and elevate severity automatically — don't rely on the LLM to know the convention.
  - **Detect React Navigation route definitions** (`createNativeStackNavigator`, `createBottomTabNavigator`, `Linking.createURL`) as a separate surface category from HTTP routes.
  - **Distinguish ops `/metrics` (Prometheus-style)** from PII endpoints — heuristic: if a file imports `prom-client`, `prometheus`, `@opentelemetry/exporter-prometheus`, classify `/metrics` as ops, not PII.
  - **Suppress route detection in `__e2e__/`, `tests/`, `__tests__/`, `*.test.ts`, `fixtures/`, `mocks/`** for attack-path entry-point selection — `path:1` should never anchor on a test fixture.
  - **Suppress `mfa` keyword evidence** when the citing file is UI/messaging code (`MessageInput*`, `link-meta`) — require co-occurrence with auth-handler patterns.

- **#18 (service topology / trust-boundary modeling):**
  - **Recognize mixed monorepos:** `src/` is a client, `bskylink/` and `bskyogcard/` are servers, `bskyweb/` is a wrapper. Emit per-subproject service nodes.
  - **Recognize XRPC client calls** (`agent.app.bsky.feed.getTimeline`, etc.) as outbound trust-boundary edges to the AppView.
  - **Recognize SDK trust edges** — Sentry, Bitdrift, Statsig, FCM/APNs — as outbound integrations with their own trust implications.

- **#19 (ATProto-specific analyzer):**
  - **Recognize `@atproto/oauth-client-browser`** as an authentication primitive and surface DPoP / refresh-token rotation as defensive controls.
  - **Recognize XRPC client method calls** and tag them with the lexicon namespace (`app.bsky.*`, `com.atproto.*`) so per-namespace trust boundaries can be reasoned about.
  - **Recognize push-notification token registration paths** (`registerForPushNotificationsAsync`, `expo-notifications`) as identity-bearing surfaces.

- **New analyzer category — mobile app surfaces (worth a separate issue, parallel to #17):**
  - `expo-config` / `app.config.js` analyzer (permissions, deep-link schemes, OAuth redirect URIs).
  - Deep-link / intent-handler analyzer (universal links, custom URL schemes).
  - Client-side secret-storage analyzer (Keychain, `expo-secure-store`, `AsyncStorage` misuse).

- **Eval/rubric (carryover from atproto + pds):**
  - The rubric needs to (a) broaden `allowed_ids` to accept any `(asset|insight|control|detect|surface|finding|path):*` identifier rather than a tiny whitelist, (b) broaden `required_keywords` / `action_verbs` to accept semantic equivalents, and (c) be cloned into per-repo variants where the original list ("xrpc", "signing", "service") doesn't match the target repo's content shape.

## Limitations of this review

- Spot-checked LLM citations against the scan; did not verify every file/line.
- Did not measure how many of the 84 detected "routes" are real HTTP routes vs. React state — Claude estimates "the actual server-side surface is in `bskylink/src/routes/*` and `bskyogcard/src/routes/*`" which spot-checks as ~9–12 real routes total. A precise count would require manual triage of all 84.
- Eval failure modes inferred from rubric definitions, not from running the eval in verbose mode — confidence high but not 100%.
- Cross-repo aggregation deferred to combined `FINDINGS.md`.
