# AttackMap — Bluesky validation findings

Closes / addresses: [issue #16 — Run AttackMap against Bluesky repositories for real-world validation](https://github.com/mlaify/AttackMap/issues/16)

This document captures the results of running AttackMap against the three target
Bluesky repositories called out in the issue, plus a cross-repo capability-gap
analysis and an assessment of the Claude-backed LLM review quality.

Per-repo detailed notes:
- [atproto-findings.md](./atproto-findings.md)
- [pds-findings.md](./pds-findings.md)
- [social-app-findings.md](./social-app-findings.md)

---

## 1. Executive summary

| Repo | SHA | Files scanned | Routes | Assets | Eval score |
|---|---|---:|---:|---:|---|
| [bluesky-social/atproto](https://github.com/bluesky-social/atproto) | `0ac21bbf6db0bcb745adecf064eded1452be02de` | 2132 | 165 | 14 | 1/6 (fail) |
| [bluesky-social/pds](https://github.com/bluesky-social/pds) | `d023aa873c27668f1f22c980505c5de917088386` | 1 | 1 | 0 | 1/6 (fail) |
| [bluesky-social/social-app](https://github.com/bluesky-social/social-app) | `7f5dd4006970a67f11b85e3941a719cad293b078` | 1677 | 84 | 4 | 1/6 (fail) |

**Top-line conclusions:**

1. **The pipeline runs end-to-end on real Bluesky code.** All three repos scanned cleanly, the LLM (Claude Code, Sonnet 4.6) produced a complete narrative review for each, and reports were generated without errors.
2. **The native scanner has strong evidence-handling and weak coverage breadth.** Where it sees a surface, it cites it accurately (file/line, env-var name). Where it doesn't have an analyzer for the file type (Docker, compose, shell, env-template, CI workflow, React Native, lexicon-defined XRPC) it sees nothing — silently.
3. **The Claude-backed LLM review is the highest-quality artifact in every run.** It correctly distinguishes OBSERVED vs INFERRED, flags scanner artifacts as false positives, refuses to hallucinate when evidence is thin (pds), and adds domain knowledge the static scanner cannot (e.g., `EXPO_PUBLIC_*` → client-bundled secret).
4. **The eval rubric is misaligned with what the prompt elicits.** All three runs scored 1/6 with the exact same five failures, despite the LLM output being qualitatively high. This is a rubric/prompt vocabulary mismatch, not an output-quality problem. Fixing it is independent of any analyzer work and should land before more validation is layered on.
5. **`bluesky-social/pds` is a deployment/operations repo, not application code.** The scanner saw 1 of ~20 files because every non-JS file (Dockerfile, compose.yaml, installer.sh, pdsadmin/*.sh, sample.env, GitHub workflow) is outside its current analyzer model. This is the most important coverage finding from the run.

---

## 2. Cross-repo capability gaps

These are the gaps that recur across two or three repos. Per-repo specifics live in the linked notes files.

### Critical (blocks credible coverage of Bluesky)

- **No XRPC / lexicon awareness** — atproto and social-app.
  The ATProto API contract is lexicon-driven. The scanner finds Express-style routes but does not recognize lexicon handler registration (atproto) or XRPC client method calls (social-app). The single largest semantic gap. **→ issue #19.**

- **No service-topology / multi-package monorepo model** — atproto and social-app.
  atproto is at minimum 8 services (PDS, AppView, Ozone, entryway, OAuth provider, dataplane, bsync, courier); social-app is a client + three Express services + a web wrapper. The current graph collapses everything to `repo → web → external_N`. Service-to-service API secrets (`BSKY_BSYNC_API_KEY`, etc.) are not recognized as inter-service trust edges. **→ issue #18.**

- **No analyzers for deployment / operations surfaces** — pds.
  Dockerfile, docker-compose, shell installers, `.env` templates, GitHub Actions workflows, package.json/lockfiles — none have analyzers. For deployment repos this means ~95% blind. Suggests a separate analyzer family beyond #17/#18/#19.

### High (degrades signal-to-noise across all three runs)

- **Stop classifying non-routes as routes** — all three repos.
  Across the runs we observed: HTTP verbs (`GET`, `POST`) and literal filenames (`image.png`) as "external dependencies" (atproto); React state hooks / persisted-state keys / URL-parsing patterns as "routes" (social-app — up to ~50 of 84); OAuth parameter names as paths (atproto — ~30% of surfaces). **→ issue #17.**

- **Per-route auth signals are file-scoped, not route-scoped** — atproto and social-app.
  Every route gets tagged with the union of auth keywords found anywhere in the same file. Result: nearly every public route shows `bearer, jwt, mfa, oauth, password, session, token` regardless of whether the specific handler does any of that. The scanner's own `insight:stale-signal` was the only thing flagging this in social-app — it should be a first-class scanner output, not a post-hoc correction.

- **Test/example down-weighting is partial** — atproto and social-app.
  Test files were correctly down-weighted in atproto's surface inventory, but a test file still made the top-3 "entry point concentration" list (`packages/lex/lex-server/src/lex-router.test.ts`), and in social-app the only generated attack path (`path:1`) anchored on `__e2e__/setupServer.js` — a test harness. Down-weighting needs to propagate into entry-point ranking and attack-path generation, not just surface enumeration.

### Medium (specific to ATProto/Bluesky domain)

- **No DPoP / JWKS / PAR / refresh-token-rotation modeling** as named defensive controls — atproto and social-app. **→ #19.**
- **No `did:plc` / `did:web` identity-resolution surface** — atproto.  **→ #19.**
- **No CAR / repo-signing ingest** — atproto.  **→ #19.**
- **No `EXPO_PUBLIC_*` heuristic** for client-bundled secrets — social-app. Claude caught this; the scanner should.  **→ #17.**
- **No deep-link / universal-link / intent-handler surface** — social-app.  **→ #17 or a new mobile-surface issue.**

### Medium (control-absence reasoning)

- **Many "absent" controls are infra-layer, not code-layer.** `encryption_at_rest`, `rate_limiting`, and (for cookie-less APIs) `csrf_protection` are typically enforced at the proxy/CDN/infra layer and are invisible to a code scan. Across all three runs, these absences dominate the findings list and are correct in narrow technical terms ("no marker visible in code") but easy to misread as real gaps. Recommend a `infra-layer-likely` tag that down-ranks them in the headline findings list and surfaces them as IaC-audit follow-ups instead. The native review's existing "low-quality-evidence" tag does some of this work but does not propagate to severity.

---

## 3. Claude-backed LLM review quality

All three repos were reviewed via `--llm-backend cli` (Claude Code, Sonnet 4.6, Pro plan).

### What Claude did well (consistent across runs)

- **OBSERVED vs INFERRED discipline** — the only eval check that passed in all three runs. ~25–30 instances per review, used correctly.
- **No hallucinations detected** in spot-checks of cited file/line references.
- **False-positive flagging in Claude's own voice.** Examples:
  - atproto: flagged the `insight:trust-boundary-violation` on `packages/internal/*` as likely header-construction code, not real route exposure.
  - pds: explicit "I will not invent observations the pack does not support" when the evidence pack was thin.
  - social-app: flagged the React state hooks classified as routes, the test fixtures classified as production surfaces, and the suspicious `mfa` "control" evidence.
- **Domain knowledge added beyond the scanner.** Best example: `EXPO_PUBLIC_BITDRIFT_API_KEY` — the scanner just saw a secret; Claude knew the Expo prefix convention guarantees client-bundle inlining and elevated the finding accordingly. This is the kind of insight static analysis structurally cannot produce.
- **Honest scaling with evidence-pack size.** Citation density dropped from ~35 IDs (social-app) → ~30 (atproto) → ~10 (pds) — proportional to what was actually in the pack.
- **Structure matches the AGENTS.md "good defensive review" spec** end-to-end: system overview → notable observations → assets/controls → detection opportunities → strengths → weaknesses → evidence chains → recommendations → analyst confidence/limitations.

### Where the eval rubric is wrong

The rubric (`evals/fixtures/bluesky-atproto-review-v1.json`) failed the same five checks in all three runs. Per-check root cause:

| Check | Why it always fails |
|---|---|
| `grounding` | Rubric whitelists a tiny set of IDs (`surface:1..3`, `finding:1..2`, `path:1`). Claude consistently cites the *actual* evidence-pack IDs (`asset:*`, `insight:*`, `control:*`, `detect:*`, plus higher-numbered surfaces/findings). This is *better* grounding than the whitelist anticipates. **Fix:** broaden `allowed_ids` to a pattern, not a whitelist. |
| `strengths_coverage` | Requires literal keywords "signing" and "service". Claude uses semantic equivalents (DPoP, JWKS, MFA, session subsystem, service boundaries). **Fix:** expand the keyword list with synonyms, or instruct the prompt to use the rubric vocabulary. |
| `weakness_hotspot_quality` | Requires "trust boundary", "xrpc", "hotspot". The "xrpc" keyword cannot appear in any review when the analyzer doesn't surface XRPC content — this failure is downstream of the analyzer gap (#19), not a prompt issue. |
| `recommendation_usefulness` | Requires verbs "enforce", "validate", "constrain". Claude uses "Add", "Verify", "Confirm", "Implement", "Audit", "Annotate". Both lists are strong action verbs; only one matches the regex. **Fix:** broaden `action_verbs`. |
| `false_positive_control` | Requires literal phrases "low-quality" and "heuristic". Claude uses "Source-quality caveat", "scanner artifact", "INFERRED", "may be a misclassification". **Fix:** broaden `required_cautions`. |

The cleanest fix is to update both sides: tighten `review_prompts.py` to nudge the model toward the rubric vocabulary, and broaden the rubric to accept semantic equivalents. Either alone is fragile.

There is also a **fixture-scope** issue: the same `bluesky-atproto-review-v1.json` rubric was applied to pds (a deployment repo) and social-app (a mixed client + small servers monorepo). The atproto rubric asks about XRPC and signing keys that don't appear in pds at all. Recommend:

- `bluesky-pds-deployment-review-v1.json` — rubric for deployment repos (Dockerfile hardening, compose service graph, installer.sh integrity, env-template asset inventory).
- `bluesky-social-app-review-v1.json` — rubric for mixed client + Express monorepos (client-bundled secrets, Express route handlers, monorepo subproject enumeration).

---

## 4. Suggested follow-up work

Tagged for the existing sibling issues where they exist:

- **[#17 — JavaScript/TypeScript analyzer for Node service architectures](https://github.com/mlaify/AttackMap/issues/17):**
  - Stop classifying React state hooks, persisted-state keys, URL-parsing patterns, OAuth parameter names, HTTP verbs, and literal filenames as routes/endpoints.
  - Detect `EXPO_PUBLIC_*` prefix as client-bundled secret.
  - Make per-route auth-signal attribution route-scoped, not file-scoped.
  - Distinguish Prometheus-style ops `/metrics` from PII-bearing endpoints.
  - Propagate test/example down-weighting into entry-point ranking and attack-path generation.

- **[#18 — Service topology and trust-boundary modeling](https://github.com/mlaify/AttackMap/issues/18):**
  - Recognize multi-package monorepos and emit per-package service nodes.
  - Map service-to-service API secrets to inter-service trust edges.
  - Parse `compose.yaml` to build a service graph with port/volume/env/auto-update edges.

- **[#19 — Bluesky/ATProto-specific analyzer](https://github.com/mlaify/AttackMap/issues/19):**
  - Detect lexicon-driven XRPC handler registration and XRPC client method calls.
  - Recognize DPoP / JWKS / PAR / refresh-token rotation as named defensive controls.
  - Recognize `did:plc` / `did:web` identity-resolution surfaces.
  - Recognize CAR / repo-signing ingest surfaces.

- **New issues to consider opening:**
  - **Deployment-surface analyzer family** (Dockerfile / docker-compose / shell installer / `.env` template / GitHub Actions workflows / package.json + lockfile). Surfaced strongly by the pds run; would unblock validation of any infra/ops repo.
  - **Mobile-surface analyzer** (deep links / intent handlers / Keychain / `expo-secure-store` / push-notification token registration). Surfaced by the social-app run.
  - **Eval rubric overhaul.** Three concrete changes: (a) broaden `allowed_ids` pattern, (b) broaden keyword/verb lists with semantic equivalents, (c) split rubric per repo class (atproto / pds-deployment / social-app-mixed). Independent of any analyzer work, should land first so future validation pass scores are interpretable.
  - **Make `insight:stale-signal` first-class.** Currently the scanner emits this as an `INFORMATIONAL` note; it should propagate into the per-route auth-signal attribution so downstream findings don't compound the noise.

---

## 5. Reproduction

These results were produced from pinned commit SHAs. Anyone with AttackMap installed and a Claude Code login can regenerate the eight reports per repo by running:

```bash
# atproto
git clone https://github.com/bluesky-social/atproto.git
cd atproto && git checkout 0ac21bbf6db0bcb745adecf064eded1452be02de && cd ..
attackmap analyze ./atproto --output reports-atproto --llm

# pds
git clone https://github.com/bluesky-social/pds.git
cd pds && git checkout d023aa873c27668f1f22c980505c5de917088386 && cd ..
attackmap analyze ./pds --output reports-pds --llm

# social-app
git clone https://github.com/bluesky-social/social-app.git
cd social-app && git checkout 7f5dd4006970a67f11b85e3941a719cad293b078 && cd ..
attackmap analyze ./social-app --output reports-social-app --llm
