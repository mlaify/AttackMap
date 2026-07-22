# Unknown-bug discovery (epic [#150](https://github.com/mlaify/AttackMap/issues/150))

Make AttackMap materially better at finding **unknown** (novel, un-signatured)
bugs — not just more matches of known shapes.

## Guiding principle

> **"More aggressive" ≠ "more likely to find unknown bugs."**

Heuristics find known shapes. Novel bugs — business-logic flaws, TOCTOU/races,
trust violations, confused-deputy chains — are found by **reasoning over a
bigger, better-connected surface and verifying hard**. Aggressiveness only pays
off *behind a strong verifier*. Every workstream in this epic is gated on, or
feeds, one asset: **the verifier**.

## Dependency graph

```
                 ┌─────────────────────────────┐
                 │ #147 Multi-pass hunt harness │  ← FOUNDATION
                 │  lenses · loop-until-dry ·   │
                 │  N-skeptic majority verify   │
                 └──────┬───────────────┬───────┘
          verifier gates│               │adjudicates candidates
                        ▼               ▼
         ┌────────────────────┐   ┌──────────────────────────┐
         │ #148 Recall mode    │   │ #146 Cross-repo analysis │  ← biggest build
         │ aggressive knobs +  │   │ fleet graph · contract   │
         │ capability-reach    │   │ linking · x-boundary     │
         └────────────────────┘   │ taint · trust-gap        │
                                   └───────────┬──────────────┘
                                     fleet graph│
                     ┌──────────────────────────▼─────────────┐
                     │ #149 Invariant mining + fleet anomaly   │
                     │  149a within-repo (self-contained)      │
                     │  149b fleet (needs #146 graph)          │
                     └─────────────────────────────────────────┘
```

`#147`'s verifier is what makes `#148` safe and what adjudicates `#146`'s
cross-boundary candidates. `#146`'s fleet graph is what `#149b` needs.

## Build order

| # | Slice | Issue | LLM | Effort | Notes |
|---|-------|-------|-----|--------|-------|
| 1 | **N-skeptic majority-vote verify** | #147a | yes | M | keystone — smallest, immediate FP win, the asset everything leans on |
| 2 | multi-lens passes + dedupe | #147b | yes | M–L | the novelty multiplier |
| 3 | loop-until-dry + completeness critic + budget caps | #147c | yes | M | completes the harness |
| 4 | within-repo invariant mining | #149a | no | M | deterministic, self-contained early win |
| 5 | recall mode (knobs + capability-reach), verifier-gated | #148 | gated | S–M | cheap once #147 exists |
| 6 | cross-repo (phased) | #146 | mixed | XL | highest value; #149b fleet anomaly rides its graph |

## Cross-cutting concerns

- **Opt-in + cost.** Multi-pass (#147) and cross-repo (#146) both multiply LLM
  cost. Everything new is opt-in behind flags, with explicit round/token/budget
  caps.
- **Reproducibility.** LLM passes are non-deterministic; the deterministic
  scaffolding (dedupe keys, ranking, invariant evidence, vote combination) stays
  stable and diffable — same contract as `triage.py`.
- **Precision guardrails.** #149 fires only on strong majorities (configurable
  threshold); #148 output is marked speculative until the verifier adjudicates it.
- **Config surface.** As knobs accumulate, prefer a config-file section over a
  wall of CLI flags.

## Decisions

- **Multi-repo input (#146):** CLI **varargs** — `attackmap analyze repoA repoB …`.
  Single-repo behavior is unchanged; multi-repo is opt-in by passing >1 path.

## Workstream scope

### #147 — Multi-pass hunt harness (foundation)

Today `--hunt` / `--hunt --verify` is a **single** LLM pass (`hunt` / `hunt_verify`
modes in `llm_review.py`); verify is a single adversarial pass that adjudicates
against real `code_excerpts`. Turn it into a discovery *harness*:

- **147a — N-skeptic majority-vote verify.** The hunt pass produces hypotheses;
  they're parsed into a fixed, ID-keyed list; **N independent skeptic passes**
  adjudicate that same list; a pure combiner takes the **majority vote, defaulting
  to REFUTED** on ties / missing / uncertainty. New `hunt_harness.py`
  (Hypothesis/Verdict + pure `combine_verdicts` + parsers), a skeptic prompt, a
  `hunt_skeptic` mode, and a `--verify-votes N` knob (default 3; `1` = today's
  behavior). Report shows the consensus verdict + vote tally.
- **147b — multi-lens passes + dedupe.** N independent hunt passes, each primed
  with a distinct failure-mode lens (auth-bypass, TOCTOU/race, business-logic/
  IDOR, deserialization, SSRF-to-internal, secret-misuse); dedupe across passes.
- **147c — loop-until-dry + completeness critic + budget.** Keep hunting until K
  consecutive rounds find nothing new; a critic names untried modalities /
  unverified claims to seed the next round; round + token-budget caps.

### #148 — Recall mode (verifier-gated)

`--recall` widens discovery — tunable max taint-hop depth, confidence floor,
expanded source/sink lists, speculative call-edges, include test/generated files
— plus **capability-reach enumeration** (every place untrusted data reaches
exec/fs/net/deserialize/template/SQL, pattern or not). All recall output is
routed through the #147 verify + `triage.py` filter so it's ranked/adjudicated
and clearly marked speculative, not raw. Knobs live around `taint.py`
(`_MAX_HOPS`, sink lists) and `scanner.py`.

### #149 — Invariant mining + fleet anomaly

Extends the within-repo odd-one-out pass in `anomalies.py` (already threshold-gated).

- **149a — within-repo invariant mining.** Infer implicit invariants from
  repeated structure ("param `id` is authz-checked before this sink in 9/10
  handlers") and flag the violating site, with the invariant as evidence.
  Deterministic, no LLM — the cleanest standalone slice.
- **149b — fleet anomaly.** The sibling service that omits a control its peers
  enforce. Needs #146's fleet graph.

### #146 — Cross-repo analysis (XL, phased)

The last epic lever. The highest-value *unknown* bugs live at the **seams
between services** — each repo looks locally correct; only a fleet view exposes
them. Today `cli.py` takes a single `path`; `topology.py` builds a single-repo
service graph.

**Architecture reality (mapped 2026-07-22).**
- **Shape = "N per-repo scans → fleet overlay" (Path A).** Lowest blast radius:
  the scanner, `ScanResult`, and every signal model stay untouched. Each repo is
  scanned into its own `ScanResult` (own `root`, own relative paths — no
  collisions), and cross-repo logic runs on the *list* of scans, attributing
  every fleet finding to a repo id. Rejected Path B (one combined `ScanResult`
  with repo-namespaced paths) — it forces a repo field onto every signal model
  and rewrites `scan_repo`'s relativization (`scanner.py:685,697`).
- **Two prerequisite gaps in existing state:** (1) `ExternalCall` drops the HTTP
  method at capture (`scanner.py:707`) and has no structured host/path — only a
  raw `target` string; (2) `topology.py` reduces an outbound URL to a bare
  host-prefix slug (`_service_from_url`, `topology.py:297`), discarding
  path/method/scheme and collapsing localhost to `local-service`. Both must be
  fixed before client↔route linking works.
- **Linking-dimension cost (only HTTP is cheap):** HTTP client↔route — signals
  exist (`Route.path/method` + `ExternalCall.target`), needs method preservation
  + normalization/linking logic, **no new parser**. GraphQL SDL — partially
  reusable (`authz.py:285-410`). Everything else is **new extraction**: RPC
  caller side, OpenAPI/Swagger, protobuf/`.proto`, `.json` AT-proto lexicons,
  queue/topic names, DB table/collection names, token `iss`/`aud`/JWKS.

**Phase plan (sub-issues under #146):**

1. **#146a — Multi-repo input + fleet container + reporting.** `analyze repoA
   repoB …` (CLI varargs). Scan each repo into its own `ScanResult`; wrap in a
   `FleetScan` (list of `(repo_id, ScanResult)`). Write per-repo reports into
   `output/<repo>/` subdirs + a top-level fleet index/summary. **No cross-repo
   logic yet** — pure foundation. Single-repo path (one arg) byte-for-byte
   unchanged. (Touch-points: `cli.py:71` arg → variadic; loop over
   `resolve_run_analyzers`/`analyze_repository`/`collect_suppressions`;
   `report.py` fleet writer.)
2. **#146b — HTTP contract linking + fleet service graph.** Preserve the HTTP
   method + structured host/path on `ExternalCall` (model + `scanner.py`).
   Build a cross-repo linker matching one repo's outbound `(host,path,method)`
   to another repo's `Route` (template-aligned). Extend `topology.py` to a
   **fleet graph** with repo-qualified node keys and cross-repo edges. Stretch:
   GraphQL/RPC and shared-schema linking as additional matchers.
3. **#146c — Cross-boundary taint (confused-deputy).** Over the fleet links,
   propagate: a value leaving repo A (response/event/queue) re-entering repo B
   as a *trusted* input. Verifier-gated (route candidates through #147).
   **→ AC1:** two linked fixture repos (client + server), a value unvalidated in
   the caller and trusted in the callee → one cross-boundary finding citing both
   sides.
4. **#146d — Trust-assumption gap + cross-repo anomaly.** A assumes B enforces
   authz and vice-versa → nobody does (**→ AC2:** trust-gap finding across two
   locally-correct repos). Plus the cross-repo anomaly (the one service skipping
   a sibling-enforced control) — this is **#149b**, which rides this graph.
   Contract drift (producer adds an authz-relevant field the consumer trusts) is
   a stretch item here.

Single-repo behavior unchanged throughout; multi-repo is opt-in. Each phase is
its own PR; #146c/#146d findings are speculative until the #147 verifier
adjudicates them.
