# pds — AttackMap validation notes


- Repo: https://github.com/bluesky-social/pds
- Pinned SHA: `d023aa873c27668f1f22c980505c5de917088386`
- Date scanned: 2026-05-30
## Important framing

`bluesky-social/pds` is **not the PDS server source** — that code lives inside `bluesky-social/atproto` under `packages/pds/`. This repo is the **PDS deployment / operations distribution**:

- `Dockerfile` — container build
- `compose.yaml` — service composition (PDS + Caddy reverse proxy + Watchtower)
- `installer.sh` — host setup script (~hundreds of lines, configures TLS, firewall, users, secrets)
- `pdsadmin/*.sh` — admin shell utility (account create/delete, invite codes, crawl requests)
- `service/index.js` — a tiny Node TLS-check shim that fronts the container
- `service/package.json` + `pnpm-lock.yaml`
- `sample.env` — secret template
- `ACCOUNT_MIGRATION.md`, `PUBLISH.md`, `README.md` — operational docs
- `.github/workflows/build-and-push-ghcr.yaml` — CI build

This is a **deployment/operations repo**, not an application source repo. The scan result (1 file, 1 route, no assets) reflects what AttackMap's current analyzer model is built to see (Node web routes), not what's actually in the repo.

## Scan stats

- Files scanned: **1** (only `service/index.js`)
- Languages detected: javascript
- Routes: 1 (`GET /tls-check`)
- External calls: 0
- Datastores: 0
- Sensitive assets identified: 0
- Controls observed: 1 (`encryption_in_transit`) | Control absences: 1 (`rate_limiting`)
- Native findings: 1 LOW (heuristic-scan-coverage warning)
- Attack paths: 0
- Eval score (`bluesky-atproto-review-v1`): **1/6 (16.67) — fail** (same as atproto — see Claude quality section)

---

## Detected well (true positives)

- **The one Node file present was scanned correctly.** `service/index.js` was indexed, the `GET /tls-check` route was extracted with the right file/line, and the TLS control was correctly attached to the route.
- **Honest self-reporting of low confidence.** Both the native review and the LLM review explicitly call out that this is a 1-file scan with low signal — `finding:1` is literally titled "Heuristic scan found only a limited attack surface", and Claude's output opens with the source-quality caveat and refuses to invent observations the pack doesn't support ("The evidence pack contains zero notable_observations… per the operating rules I will not invent cross-cutting insights where none were computed.").
- **TLS control captured as a strength.** Correctly identifies `encryption_in_transit` as observed at `service/index.js:19` with strength `moderate`, and recommends config review (cipher suites, min version, HSTS) as a sensible follow-up.

## Missed (capability gaps — this is the main finding)

The scanner saw 1 of ~20 files in the repo because it has no analyzer for any of the file types that actually carry this repo's security surface:

- **Dockerfile not analyzed.** Base image pinning, root vs non-root user, `COPY`/`ADD` from untrusted contexts, secret leakage via build args, exposed ports — none surfaced. For a deployment repo, the Dockerfile *is* the attack surface.
- **compose.yaml not analyzed.** Service composition (PDS + Caddy + Watchtower), port exposure, volume mounts, environment-variable injection, restart policy, network topology — all invisible. Watchtower in particular auto-pulls images, which is a supply-chain trust decision worth flagging.
- **`installer.sh` not analyzed.** A multi-hundred-line host setup script doing TLS provisioning, firewall config, user creation, secret generation — none of which the analyzer can see. Shell-based installers are a huge category of operational risk (privilege escalation, untrusted downloads, weak randomness, world-readable secrets).
- **`pdsadmin/*.sh` not analyzed.** Admin shell utility with destructive operations (account delete, invite-code creation). These are privileged operational surfaces.
- **`sample.env` not analyzed.** Secret template that enumerates exactly what secrets the deployment needs — would have been a goldmine for asset inventory even without real values.
- **`.github/workflows/build-and-push-ghcr.yaml` not analyzed.** CI pipeline that builds and publishes the container — supply-chain surface (token scoping, image signing, registry auth).
- **`package.json` and `pnpm-lock.yaml` not analyzed.** Dependency surface, lockfile integrity, license posture.
- **Markdown operational docs not analyzed.** `ACCOUNT_MIGRATION.md` describes a privileged cross-PDS migration flow; `README.md` and `PUBLISH.md` document admin procedures. These are useful for understanding intended trust boundaries.

**Net:** AttackMap covered approximately **5% of this repo's actual security-relevant content**. The repo's security story is in Docker, compose, shell, env-template, and CI files — none of which have an analyzer.

## False positives

- **None of consequence.** The few signals that did emerge (`GET /tls-check` public + no auth) are factually correct; the question of whether unauthenticated is *appropriate* for a health-check probe is a manual-validation item, not a false positive.
- **ATT&CK techniques `T1528` (Steal Application Access Token) and `T1552` (Unsecured Credentials) appear in `attack_techniques_observed`** but with no concrete in-code anchor. Claude correctly flagged this as "catalog references, not evidenced exposures" rather than treating them as real findings — good restraint, but it's a noise source the scanner should ideally not emit when no evidence supports them.

## Weak / low-confidence signals (keep but downrank)

- **Native finding "Heuristic scan found only a limited attack surface" (score 1.6).** This is the most honest possible finding for a 1-file scan, but the score and severity (LOW) underplay how structural the issue is — it's not that this repo is *low-risk*, it's that the scanner can't see most of it.
- **TLS strength `moderate`.** Inferred from the route having TLS termination; not a real assessment of cipher suites or HSTS.

## Claude LLM output quality

**Headline:** the eval scored 1/6 again, same as atproto, with the **exact same per-check failure pattern**. This is now a confirmed pattern across two runs, not a one-off — the rubric in `bluesky-atproto-review-v1.json` is misaligned with what the prompt elicits.

| Check | Result | Why |
|---|---|---|
| `grounding` | FAIL | Same as atproto: Claude cites real evidence IDs (`surface:1`, `finding:1`, `control:*`, `detect:*`) — `surface:1` would have matched the regex `(?:surface|finding|path):\d+` but the rubric requires **≥4 citations** and this is a 1-file scan with very few IDs to cite, so even strong citation discipline can't hit the minimum. |
| `observed_vs_inferred_discipline` | **PASS** | Uses OBSERVED / INFERRED consistently, ~25+ instances. This is the discipline-check that the prompt scaffolding gets right. |
| `strengths_coverage` | FAIL | Requires keywords "signing" and "service". On a deployment repo with no signing material, "signing" is not a meaningful concept — but the rubric is atproto-shaped, not pds-shaped. |
| `weakness_hotspot_quality` | FAIL | Requires "trust boundary", "xrpc", "hotspot". Claude uses "trust boundary" but never "xrpc" — there is no XRPC surface in this repo because it's not application code. **The rubric is asking about content that physically isn't in this repo.** |
| `recommendation_usefulness` | FAIL | Requires verbs "enforce", "validate", "constrain". Claude's recommendations use "Add", "Expand", "Confirm", "Implement", "Verify", "Build" — strong action verbs but not the literal three. Same as atproto. |
| `false_positive_control` | FAIL | Requires phrases "low-quality" and "heuristic". Claude says "Source-quality caveat", "weakly grounded", "INFERRED but cheap to validate", "catalog references, not evidenced exposures" — extensive FP control done in its own vocabulary. |

**Per-check notes specific to pds:**

- **Claude correctly refused to hallucinate.** With `notable_observation_count: 0` and `attack_paths: []`, the model could easily have padded the output with invented findings. Instead it opens §2 with "Per the operating rules I will not invent cross-cutting insights where none were computed" — exactly the behavior AGENTS.md asks for.
- **Citation density** dropped from ~30+ in atproto to ~10 in pds, proportional to evidence-pack size. That's correct behavior, not a regression.
- **Hallucinations:** none detected.
- **Adapted to thin evidence well:** restructured the review to lead with the source-quality caveat, marked entire sections "INFERRED extension — not in the pack", and ended with an explicit "What I refused to invent" enumeration.

**Cross-repo observation:** running the *atproto rubric* against the *pds review* is itself a mismatch — the rubric expects content (xrpc, signing, service-mesh) that pds repo doesn't contain. We should either build a `pds-deployment-review-v1.json` fixture, or accept that one repo == one rubric and not score reviews against unrelated rubrics.

---

## Candidate analyzer/scaffolding gaps (for follow-up issues)

- **#17 (JS/TS analyzer):** less relevant for this repo — the issue here is breadth of file types, not depth on JS/TS.

- **#18 (service topology / trust-boundary modeling):**
  - When a repo contains `compose.yaml`, parse it to build a service topology (PDS service, Caddy reverse proxy, Watchtower auto-updater) and inter-service edges (ports, volumes, env).
  - Surface that Watchtower auto-pulls from a registry — a supply-chain trust edge.
  - Recognize `Caddy` as a TLS terminator / reverse proxy and attribute the `encryption_in_transit` control to the right layer.

- **#19 (ATProto-specific analyzer):**
  - Recognize that this repo is the *deployment* of a PDS, not the *implementation*. Could emit a high-confidence inference: "this is a PDS deployment distribution; the application code is at bluesky-social/atproto/packages/pds — consider also scanning that."
  - Recognize `sample.env` as a PDS-specific secret manifest and infer asset inventory from variable names (PDS_ADMIN_PASSWORD, PDS_JWT_SECRET, PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX, etc.).

- **New analyzer category needed — operational/deployment surfaces (worth a separate issue):**
  - **`dockerfile`** analyzer: base image, USER directive, COPY/ADD provenance, EXPOSE ports, build args / secret leakage.
  - **`docker-compose`** analyzer: service graph, port bindings, volume mounts, env injection, image pinning, restart/healthcheck/auto-update behavior.
  - **`shell-installer`** analyzer: `curl | bash` patterns, sudo usage, secret generation entropy, file permission modes, firewall/iptables rules, package source trust.
  - **`env-template`** analyzer: parse `.env` / `sample.env` files into asset inventory (each var becomes a secret asset hint, criticality inferred from name).
  - **`github-workflow`** analyzer: token scopes (`permissions:`), action pinning by SHA vs tag, secrets exposed to forks, registry-push surfaces.
  - **`package.json` / lockfile** analyzer: dependency surface, license posture, lockfile integrity.

- **Eval/rubric:**
  - Don't reuse `bluesky-atproto-review-v1.json` for repos whose content shape it wasn't designed for. Either:
    - Add `bluesky-pds-deployment-review-v1.json` with rubric items appropriate to a deployment repo (Dockerfile hardening, compose service graph, installer.sh integrity, env-template asset inventory), **or**
    - Generalize the rubric to make required keywords conditional on what the evidence pack contains.

## Limitations of this review

- Spot-checked LLM output for hallucinations; did not exhaustively verify every claim.
- Did not separately verify the actual contents of `installer.sh`, the `Dockerfile`, or `compose.yaml` against the analyzer's silence on them — relied on file listings to establish that those files exist and are non-trivial.
- Eval rubric mismatch (atproto rubric vs pds repo) is itself a finding, not a clean LLM-quality signal.
- `social-app` not yet scanned; cross-repo capability conclusions deferred to combined `FINDINGS.md`.
