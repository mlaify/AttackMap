# Defensive Review

## System Overview
- OBSERVED: Public XRPC handlers were detected in service entry files [surface:1] [surface:2].
- INFERRED: Some namespace-derived routes may be protocol-defined rather than directly enumerated runtime handlers [surface:3].
- OBSERVED: Inter-service flow evidence exists from route handling into downstream processing [path:1].

## Strengths
- OBSERVED: Signing and identity checks are referenced near request handling and should support defensive boundary checks when correctly enforced [finding:1].
- OBSERVED: Service segmentation exists, which can reduce blast radius when service auth is strict [surface:2] [path:1].

## Weaknesses / Risk Hotspots
- OBSERVED hotspot: XRPC-exposed handlers near trust boundary transitions increase risk if per-namespace authz is inconsistent [surface:1] [surface:2].
- INFERRED hotspot: Protocol-derived surface area can exceed directly observed runtime routes, so trust boundary assumptions may drift [surface:3].
- OBSERVED weakness: Service-to-service propagation reaches sensitive sinks; this is a trust boundary concern requiring explicit controls [finding:1] [path:1].

## Key Evidence Chains
- OBSERVED chain: request entry reaches service logic and then a downstream boundary [path:1].
- INFERRED chain: namespace-level surface mapping suggests additional route variants that should be validated against runtime policy [surface:3].

## Prioritized Recommendations
- 1. Enforce namespace-specific authorization and service-auth checks at every trust boundary hop [finding:1] [path:1].
- 2. Validate XRPC handler exposure against expected runtime routes and remove unused protocol-derived endpoints [surface:1] [surface:3].
- 3. Constrain downstream service/database permissions to least privilege and log denied cross-service actions [finding:2].

## Analyst Confidence and Limitations
- This review is heuristic and evidence-first; findings are prioritized for defensive triage.
- Low-quality and test-adjacent signals were down-weighted and should not be treated as production exposure without corroboration.
