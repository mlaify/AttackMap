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

Today `cli.py` takes a single `path`; `topology.py` builds a single-repo service
graph. Phased:

1. Multi-repo input (CLI varargs).
2. Contract linking across repos — HTTP/RPC client↔server route, shared schemas
   (protobuf / AT-proto lexicon / OpenAPI / GraphQL SDL), queues/topics, shared
   DB tables, token issuer/audience.
3. Unified **fleet service graph** (extend `topology.py`).
4. **Cross-boundary taint** — a value leaving repo A (response/event/queue) that
   re-enters repo B as trusted input (confused-deputy).
5. **Trust-assumption gap** — A assumes B enforces authz and vice-versa.
6. **Contract drift / cross-repo anomaly** — producer adds an authz-relevant
   field the consumer trusts; the one service that skips a sibling-enforced control.

Single-repo behavior unchanged throughout; multi-repo is opt-in.
