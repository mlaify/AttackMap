# Decision: AT Protocol / Bluesky analyzer coverage

**Status:** Decided
**Date:** 2026-06-25
**Closes:** [#19](https://github.com/mlaify/AttackMap/issues/19)

## Context

Real-world validation on the three primary Bluesky repositories
([FINDINGS.md](../../evals/validation/bluesky/FINDINGS.md), landed via PR #20)
identified a set of AT Protocol / Bluesky-specific patterns the analyzer stack
handles poorly out of the box: XRPC handler registration, lexicon-driven NSID
routing, DPoP / JWKS / PAR authentication flows, `did:plc` / `did:web` identity
resolution, and CAR / repo-signing ingest.

#17 (deepen `attackmap-analyzer-node-service`) landed in 0.2.0 and closed the
biggest of these — XRPC handler detection now emits `/xrpc/<nsid>` routes and
`atproto_lexicon:<nsid>` hints. The threat model's `_build_atproto_chains`
already consumes those, `atproto_namespace:*`, `atproto_protocol:xrpc`, and
`atproto_service_note:*` / `atproto_service_edge:*` — producing full "AT
Protocol namespace trust-chain abuse" attack paths.

A dedicated overlay analyzer, `attackmap-analyzer-atproto` (0.1.0), already
exists on PyPI. It's a thin layer over `attackmap-analyzer-node-service` that
adds AT-Protocol-specific hint prefixes on files that look like ATProto
services.

## Decision

**Do not build a new dedicated Bluesky/ATProto analyzer.** Keep the current
split:

- **`attackmap-analyzer-node-service`** — heavy lifting for Node.js/TypeScript
  service topology, including XRPC handler detection (added in 0.2.0 via
  #17).
- **`attackmap-analyzer-atproto`** — light overlay that adds ATProto-specific
  classification (`atproto_service_note:*`, `atproto_service_edge:*`) on top
  of the node-service base.

The alternative — a heavy dedicated analyzer for the full stack — would
duplicate ~80% of what node-service already does and lock ATProto detection
behind a separate PyPI project that most users wouldn't install. The current
split lets any node-service-analyzed repo get partial ATProto benefits when
the overlay is present, and full benefits when both are.

## Rationale

- **The layered plugin design already fits this shape.** Language ↔ framework
  ↔ app-specific was the pattern we chose in [PR #25](https://github.com/mlaify/AttackMap/pull/25);
  ATProto is a natural framework-overlay tier under Node/TS.
- **Every gap the FINDINGS document flagged is either resolved
  (XRPC handlers) or can be resolved incrementally as new overlay hints without
  a new analyzer package.**
- **PyPI slot economics.** Each PyPI project has its own Trusted Publisher
  registration, release workflow, `pip install` line. A new analyzer costs
  more than a hint set added to an existing one.

## Follow-up work

The following ATProto-specific detection gaps remain. Each is a small hint
addition to `attackmap-analyzer-atproto` (or, where the pattern is generic,
to `attackmap-analyzer-node-service`) — not a new analyzer.

Tracked as future issues to file individually:

- **DPoP / PAR / refresh-token rotation** as named defensive controls (not
  generic `auth_hints`). Emit `atproto_control:dpop`, `atproto_control:par`,
  etc. so `_build_atproto_chains` can cite them.
- **`did:plc` / `did:web` identity resolution** surfaces. Emit
  `atproto_identity_resolver:<method>` on files that call handle-resolver
  modules.
- **CAR / repo-signing ingest** surfaces. Emit `atproto_repo_ingest:*` on
  `packages/repo/*` and similar layouts.
- **JWKS endpoint auto-registration** — recognize `.well-known/jwks.json`
  hosting patterns.

None of these blocks the current #19 decision — the analyzer *architecture*
is right; only the pattern coverage is incremental.

## Testing this stays true

Bluesky validation should re-run against the same pinned SHAs
([FINDINGS.md §5](../../evals/validation/bluesky/FINDINGS.md)) after each of
the follow-ups above ships. If a follow-up ends up requiring wholesale changes
that touch more than one hint prefix and cross into framework-graph modeling,
revisit this decision.
