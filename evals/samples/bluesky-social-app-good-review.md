# Defensive Review — bluesky-social/social-app (mixed monorepo)

## Notable Observations

OBSERVED: The repository is a mixed monorepo — a React Native + Expo
client alongside three small Express services (`bskylink/`,
`bskyogcard/`, `bskyembed/`) and a web wrapper (`bskyweb/`). Most of the
real server-side attack surface lives in the workspace subprojects, not
in `src/` where the client lives. See asset:social-app-workspaces.

OBSERVED: Several `process.env.EXPO_PUBLIC_*` secrets appear in the
config module. See surface:expo-public-config.

INFERRED: Because the Expo build system inlines any `EXPO_PUBLIC_`-prefixed
env value into the client bundle at build time, these are effectively
public. Anything named `EXPO_PUBLIC_BITDRIFT_API_KEY` is a
client-bundled secret, not a runtime-protected one. See insight:expo-public-secret.

OBSERVED: Test harnesses in `__e2e__/` and mock utilities under
`src/state/persisted/__mocks__/` were surfaced by the scanner as
runtime routes. See surface:e2e-harness-routes.

## Strengths

- The React Native + Expo build pipeline separates public-safe
  configuration from server-only credentials via the `EXPO_PUBLIC_` prefix
  convention — the convention itself makes the mistake auditable, even
  when a specific value is misclassified.
- The monorepo layout gives each Express subproject (workspace package) its
  own directory boundary, which makes review scoping tractable.

## Weaknesses / Risk Hotspots

- `EXPO_PUBLIC_BITDRIFT_API_KEY` and similar EXPO_PUBLIC vars are
  bundle-inlined at build time. Every prefixed name is a public build
  secret and should be either rotated/removed or explicitly reclassified.
  See finding:expo-public-secrets.
- Express handlers in `bskylink/src/routes/*` and `bskyogcard/src/routes/*`
  are the real server-side surface of this repo; the current scanner
  did not deeply cover them. Any control-absence finding on the React
  client side should not be attributed to those services. See surface:express-service-handlers.
- One generated attack path anchored on a test harness in `__e2e__/setupServer.js`
  is a test fixture, not a production entry point — down-weight so the
  narrative doesn't attribute production risk to test scaffolding.
  See insight:test-harness-downweight.

## Prioritized Recommendations

- Audit every `EXPO_PUBLIC_*` name against actual runtime need. If a
  secret genuinely needs to reach the client, isolate it behind a
  server-side proxy; if not, rotate the credential and remove the
  `EXPO_PUBLIC_` prefix so it stays server-only. See detect:expo-public-audit.
- Verify each Express subproject (`bskylink`, `bskyogcard`, `bskyembed`)
  independently — a monorepo review that averages across all subprojects
  will miss per-package auth gaps. See detect:workspace-scoped-review.
- Annotate test-harness routes so they don't feed into entry-point ranking.
  Confirm the `__e2e__/` prefix propagates into surface classification.
  See detect:test-harness-tagging.

## Analyst Notes

INFERRED to be low-signal: control-absence findings on the React Native
client side (no CSRF, no rate limiting) are typically a scanner artifact
here — the client isn't the state-change enforcer for those controls.
The scanner artifact is not a real gap. Treat those as source-quality
caveat entries in the report, not as work items.
