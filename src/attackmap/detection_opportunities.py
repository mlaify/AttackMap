"""Generate detection-engineering hints from insights and findings.

For each notable observation, suggest a runtime signal a defender could
add to catch the same condition in production. Output is intentionally
generic (rule sketches, not fully-formed Sigma/KQL/Splunk yet) so it
slots into whatever SIEM the user already runs.
"""

from __future__ import annotations

from collections.abc import Callable

from .attack_taxonomy import techniques_for_finding, techniques_for_insight
from .models import (
    AttackTechnique,
    DetectionOpportunity,
    Finding,
    Insight,
    InsightKind,
)


def _opportunity(
    *,
    opportunity_id: str,
    title: str,
    rationale: str,
    signal_kind: str,
    suggested_rule: str,
    related_insight_ids: list[str] | None = None,
    related_finding_titles: list[str] | None = None,
    attack_techniques: list[AttackTechnique] | None = None,
) -> DetectionOpportunity:
    return DetectionOpportunity(
        id=opportunity_id,
        title=title,
        rationale=rationale,
        signal_kind=signal_kind,  # type: ignore[arg-type]
        suggested_rule=suggested_rule,
        related_insight_ids=related_insight_ids or [],
        related_finding_titles=related_finding_titles or [],
        attack_techniques=attack_techniques or [],
    )


# ---------- Per-insight-kind opportunity generators ----------


def _opp_for_shared_secret_blast_radius(insight: Insight) -> DetectionOpportunity:
    return _opportunity(
        opportunity_id=f"detect:{insight.id}",
        title="Detect signing-key drift across services",
        rationale=(
            "Shared signing material across many services means a single rotation should be visible "
            "everywhere; conversely, divergence may indicate a compromised key in use."
        ),
        signal_kind="config_audit",
        suggested_rule=(
            "Periodically hash the secret material referenced by each service and alert when "
            "different services report different hashes for the same secret name (or when one "
            "service uses a key version older than N days). Pair with token-issuer telemetry: "
            "alert on tokens signed by a key version not present in the current authorized set."
        ),
        related_insight_ids=[insight.id],
        attack_techniques=techniques_for_insight(insight),
    )


def _opp_for_sensitive_asset_reachability(insight: Insight) -> DetectionOpportunity:
    routes = ", ".join(f"`{r}`" for r in insight.related_routes[:3]) or "the listed routes"
    return _opportunity(
        opportunity_id=f"detect:{insight.id}",
        title="Alert on unauthenticated access to sensitive-asset routes",
        rationale=(
            "A static-analysis gap on auth at the surface is also a runtime detection opportunity: "
            "any 2xx response for these routes from a request lacking a valid session/JWT is high signal."
        ),
        signal_kind="log",
        suggested_rule=(
            f"On the access log: alert when status_code IN (200,201,204) AND route IN ({routes}) "
            "AND request_headers.authorization IS NULL AND session_cookie IS NULL. "
            "Tighten with a low-volume baseline — this should normally be zero."
        ),
        related_insight_ids=[insight.id],
        attack_techniques=techniques_for_insight(insight),
    )


def _opp_for_admin_action_without_auth(insight: Insight) -> DetectionOpportunity:
    routes = ", ".join(f"`{r}`" for r in insight.related_routes[:3]) or "admin routes"
    return _opportunity(
        opportunity_id=f"detect:{insight.id}",
        title="Alert on any unauthenticated state change to admin/role routes",
        rationale=(
            "Privilege-mutation flows are zero-tolerance for unauthenticated calls. Any successful "
            "mutating verb against them from an unauthenticated session should page on first occurrence."
        ),
        signal_kind="log",
        suggested_rule=(
            f"On the access log: alert when method IN (POST,PUT,PATCH,DELETE) AND route IN ({routes}) "
            "AND auth_subject IS NULL. Severity: page-on-first. Pair with an audit-log assertion that "
            "every successful call to these routes carries an actor + role-change record."
        ),
        related_insight_ids=[insight.id],
        attack_techniques=techniques_for_insight(insight),
    )


def _opp_for_audit_gap(insight: Insight) -> DetectionOpportunity:
    return _opportunity(
        opportunity_id=f"detect:{insight.id}",
        title="Establish baseline audit logs on sensitive-asset access",
        rationale=(
            "Detection is only as good as the telemetry available. The lack of audit-logging signals "
            "in code is a precondition: there is nothing for a SIEM to reason over."
        ),
        signal_kind="log",
        suggested_rule=(
            "Emit a structured audit record `{actor, action, asset_id, outcome, request_id}` from "
            "every handler that touches a sensitive asset. Forward to SIEM. Once the stream exists, "
            "build per-actor anomaly detection (asset access at unusual hours, asset access from new IPs, "
            "asset access volume above the per-actor 95th percentile)."
        ),
        related_insight_ids=[insight.id],
        attack_techniques=techniques_for_insight(insight),
    )


def _opp_for_defense_gap_in_chain(insight: Insight) -> DetectionOpportunity:
    return _opportunity(
        opportunity_id=f"detect:{insight.id}",
        title="Add request-tracing to confirm controls actually run on this chain",
        rationale=(
            "Static analysis can't tell whether a control is invoked at runtime. Trace spans on the "
            "entry and sink confirm whether intermediate auth/validation/rate-limit middleware actually executed."
        ),
        signal_kind="trace",
        suggested_rule=(
            "Instrument the chain's entry handler and its sink (DB call) with OpenTelemetry spans. "
            "Alert when a sink span's parent trace lacks a span tagged `middleware=auth` or "
            "`middleware=ratelimit`. This catches code paths that bypass middleware via direct invocation."
        ),
        related_insight_ids=[insight.id],
        attack_techniques=techniques_for_insight(insight),
    )


def _opp_for_control_strength_mismatch(insight: Insight) -> DetectionOpportunity:
    return _opportunity(
        opportunity_id=f"detect:{insight.id}",
        title="Add config-drift detection for missing controls on critical assets",
        rationale=(
            "When critical assets exist but expected controls aren't observable, drift detection on "
            "the deployed configuration (WAF rules, IAM policies, encryption-at-rest flags) gives "
            "ongoing visibility even before code-level fixes land."
        ),
        signal_kind="config_audit",
        suggested_rule=(
            "Add a daily IaC/config audit step: assert that the modules holding critical assets have "
            "(a) a WAF/auth policy attached, (b) database encryption-at-rest enabled, (c) audit-log "
            "subscriptions configured. Page when any assertion regresses."
        ),
        related_insight_ids=[insight.id],
        attack_techniques=techniques_for_insight(insight),
    )


def _opp_for_asymmetric_protection(insight: Insight) -> DetectionOpportunity:
    return _opportunity(
        opportunity_id=f"detect:{insight.id}",
        title="Compare per-method auth-rejection rates on the same route",
        rationale=(
            "Asymmetric protection often shows up as a spike in unauthenticated traffic to the "
            "unprotected verb of a route whose other verbs require auth — attackers probe for the gap."
        ),
        signal_kind="metric",
        suggested_rule=(
            "Per route, alert when the ratio of (unauthenticated requests on verb X) / "
            "(unauthenticated requests on verb Y) exceeds 10x for routes that share a path. "
            "Suggests probing of asymmetric protection."
        ),
        related_insight_ids=[insight.id],
        attack_techniques=techniques_for_insight(insight),
    )


def _opp_for_single_point_of_failure(insight: Insight) -> DetectionOpportunity:
    return _opportunity(
        opportunity_id=f"detect:{insight.id}",
        title="Track the blast-radius secret's last-rotated timestamp",
        rationale=(
            "A single auth-critical secret with no rotation cadence is a slow-burn risk; detection "
            "starts with tracking how stale it has gotten."
        ),
        signal_kind="config_audit",
        suggested_rule=(
            "Pull the secret's last-modified timestamp from the secret store and emit it as a gauge metric. "
            "Page when last_rotated_age_days > 90 (or your rotation policy). Pair with token-issuance "
            "telemetry: alert if tokens are still being signed by a key version older than the latest."
        ),
        related_insight_ids=[insight.id],
        attack_techniques=techniques_for_insight(insight),
    )


def _opp_for_control_bypass(insight: Insight) -> DetectionOpportunity:
    return _opportunity(
        opportunity_id=f"detect:{insight.id}",
        title="Verify every request hits the global control middleware",
        rationale=(
            "If a control is broadly applied but specific routes bypass it, the runtime detection is "
            "to assert that every request flows through the middleware — catching the bypass without "
            "needing to enumerate the specific routes."
        ),
        signal_kind="trace",
        suggested_rule=(
            "Tag the global middleware with an OTEL span and assert in the request-completion hook "
            "that the request trace contains that span. Alert on missing spans in production. "
            "Effective against intentional bypasses (webhook routes) and accidental ones (new route "
            "added to the wrong router)."
        ),
        related_insight_ids=[insight.id],
        attack_techniques=techniques_for_insight(insight),
    )


def _opp_for_trust_boundary_violation(insight: Insight) -> DetectionOpportunity:
    return _opportunity(
        opportunity_id=f"detect:{insight.id}",
        title="Network-level monitoring for cross-boundary traffic",
        rationale=(
            "An internal-only marker reachable via a public route is a structural problem; runtime "
            "detection focuses on the network boundary itself rather than the application code."
        ),
        signal_kind="network",
        suggested_rule=(
            "On the perimeter (WAF/load balancer): alert on requests whose URL or Host header maps "
            "to internal-only routes/services according to your service inventory. Pair with a VPC flow "
            "log rule: alert on inbound traffic to internal-classified workloads from the internet egress range."
        ),
        related_insight_ids=[insight.id],
        attack_techniques=techniques_for_insight(insight),
    )


def _opp_for_stale_or_contradictory_signal(insight: Insight) -> DetectionOpportunity:
    return _opportunity(
        opportunity_id=f"detect:{insight.id}",
        title="Annotate routes so static analysis stops contradicting itself",
        rationale=(
            "Stale or contradictory signals don't usually map to a runtime detection; the leverage is "
            "in raising the signal-to-noise of future scans."
        ),
        signal_kind="config_audit",
        suggested_rule=(
            "Add a route-manifest test that asserts route categories (admin/public/internal/health) "
            "match a single source of truth — e.g., a decorator on the handler that the test reads. "
            "Future AttackMap runs will then trust the explicit annotation over heuristic guesses."
        ),
        related_insight_ids=[insight.id],
        attack_techniques=techniques_for_insight(insight),
    )


_INSIGHT_GENERATORS: dict[InsightKind, Callable[[Insight], DetectionOpportunity]] = {
    "shared_secret_blast_radius": _opp_for_shared_secret_blast_radius,
    "sensitive_asset_reachability": _opp_for_sensitive_asset_reachability,
    "admin_action_without_auth": _opp_for_admin_action_without_auth,
    "audit_gap": _opp_for_audit_gap,
    "defense_gap_in_chain": _opp_for_defense_gap_in_chain,
    "control_strength_mismatch": _opp_for_control_strength_mismatch,
    "asymmetric_protection": _opp_for_asymmetric_protection,
    "single_point_of_failure": _opp_for_single_point_of_failure,
    "control_bypass": _opp_for_control_bypass,
    "trust_boundary_violation": _opp_for_trust_boundary_violation,
    "stale_or_contradictory_signal": _opp_for_stale_or_contradictory_signal,
}


def generate_detection_opportunities(
    insights: list[Insight],
    findings: list[Finding],
) -> list[DetectionOpportunity]:
    """Produce one DetectionOpportunity per insight kind observed.

    Findings are folded into existing opportunities by title-keyword overlap so
    we don't double-count (e.g., a heuristic finding about webhook auth and the
    `sensitive_asset_reachability` insight share a detection rule).
    """
    opportunities: list[DetectionOpportunity] = []
    seen_kinds: set[InsightKind] = set()

    for insight in insights:
        if insight.kind in seen_kinds:
            continue
        generator = _INSIGHT_GENERATORS.get(insight.kind)
        if generator is None:
            continue
        seen_kinds.add(insight.kind)
        opportunities.append(generator(insight))

    if findings:
        for opportunity in opportunities:
            related: list[str] = []
            haystack_keywords = opportunity.title.lower().split()
            for finding in findings:
                title_lower = finding.title.lower()
                if any(keyword in title_lower for keyword in haystack_keywords if len(keyword) > 4):
                    related.append(finding.title)
            if related:
                opportunity.related_finding_titles.extend(related[:3])

        finding_techniques: list[AttackTechnique] = []
        seen_tids: set[str] = set()
        for finding in findings:
            for tech in techniques_for_finding(finding):
                if tech.technique_id in seen_tids:
                    continue
                seen_tids.add(tech.technique_id)
                finding_techniques.append(tech)
        if finding_techniques and not opportunities:
            opportunities.append(
                _opportunity(
                    opportunity_id="detect:findings:residual",
                    title="Detection coverage for findings without a paired insight",
                    rationale=(
                        "These findings did not generate cross-cutting insights but are still "
                        "actionable with runtime telemetry."
                    ),
                    signal_kind="log",
                    suggested_rule=(
                        "Add per-finding logging at the affected handler with a structured "
                        "`{finding_id, route, status_code}` payload, and aggregate in the SIEM."
                    ),
                    related_finding_titles=[f.title for f in findings[:5]],
                    attack_techniques=finding_techniques[:6],
                )
            )

    return opportunities


__all__ = ["generate_detection_opportunities"]
