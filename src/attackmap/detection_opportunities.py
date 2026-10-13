"""Generate detection-engineering hints from insights and findings.

For each notable observation, suggest a runtime signal a defender could
add to catch the same condition in production. Insight-level opportunities
are prose rule sketches. Opportunities generated per finding class (#251:
taint/injection routes, SSRF, BOLA, webhook signatures, CI workflows, leaked
AWS keys, route-less code weaknesses) also carry a deployable Sigma rule with its log source, required fields, false-positive
notes and sample events, rendered from the templates in
:mod:`attackmap.detections`.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

from .attack_taxonomy import techniques_for_finding, techniques_for_insight
from .detections import (
    RenderedRule,
    has_path_params,
    regex_literal,
    render_rule,
    route_example,
    route_scopable,
    route_selector,
    rule_uuid,
    sigma_method,
    stem_selector,
    template_data,
)
from .detections.sigma import correlation_problems, sigma_matches, sigma_problems
from .taint_sinks import canonical_kind
from .taxonomy import ATTACK_TECHNIQUES, INFORMATIONAL_RULES, attack_url, taxonomy_for
from .models import (
    AttackSurface,
    AttackTechnique,
    BolaCandidate,
    DetectionLogsource,
    DetectionOpportunity,
    DetectionTestEvents,
    Finding,
    Insight,
    InsightKind,
    ScanResult,
    TaintChain,
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
    related_rule_ids: list[str] | None = None,
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
        related_rule_ids=related_rule_ids or [],
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
    scan: ScanResult | None = None,
    attack_surfaces: list[AttackSurface] | None = None,
) -> list[DetectionOpportunity]:
    """Produce one DetectionOpportunity per insight kind observed, plus
    deployable per-finding-class rules (#251) when ``scan`` is given.

    Findings are folded into existing opportunities by their rule id's
    ATT&CK techniques so we don't double-count (e.g., a heuristic finding about webhook auth and the
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
        # Link findings by rule id (#250): a finding relates to an opportunity
        # when its rule's registered ATT&CK techniques share a technique
        # (parent id) with the opportunity's — ignoring T1190, which nearly
        # every web finding carries. No title-word matching.
        for opportunity in opportunities:
            opp_parents = {_parent(t.technique_id) for t in opportunity.attack_techniques} - _UBIQUITOUS
            if not opp_parents:
                continue
            for finding in findings:
                entry = taxonomy_for(finding.rule_id)
                if entry is None or not (opp_parents & {_parent(t) for t in entry.attack}):
                    continue
                if finding.rule_id not in opportunity.related_rule_ids:
                    opportunity.related_rule_ids.append(finding.rule_id)  # type: ignore[arg-type]
                    if len(opportunity.related_finding_titles) < 3:
                        opportunity.related_finding_titles.append(finding.title)

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
                    related_rule_ids=sorted({f.rule_id for f in findings if f.rule_id})[:10],
                    attack_techniques=finding_techniques[:6],
                )
            )

    webhook = _opp_for_webhook_signatures(findings, attack_surfaces or [])
    if webhook is not None:
        opportunities.append(webhook)

    if scan is not None:
        opportunities.extend(_finding_class_opportunities(findings, scan))

    return opportunities


_WEBHOOK_RULES = ("public-webhook", "webhook-weak-verification")


def _opp_for_webhook_signatures(
    findings: list[Finding], surfaces: list[AttackSurface]
) -> DetectionOpportunity | None:
    """Webhooks with absent or weak signature verification (#243, part B),
    with a Sigma rule for deliveries that lack the signature header (#251)."""
    related = [f for f in findings if f.rule_id in _WEBHOOK_RULES]
    if not related:
        return None
    routes: list[str] = []
    for finding in related:
        for line in finding.evidence:
            route = " ".join(line.split(" in ", 1)[0].split()[:2])
            if route and route not in routes:
                routes.append(route)
    listed = ", ".join(f"`{r}`" for r in routes[:3]) or "the webhook routes"
    techniques: list[AttackTechnique] = []
    for finding in related:
        for tech in techniques_for_finding(finding):
            if tech.technique_id not in {t.technique_id for t in techniques}:
                techniques.append(tech)
    opportunity = _opportunity(
        opportunity_id="detect:webhook-signature",
        title="Alert on webhook requests with missing or invalid signature headers",
        rationale=(
            "A webhook that doesn't verify (or weakly verifies) its signature accepts forged events. "
            "Until verification is fixed, the requests themselves show the attempt: genuine provider "
            "deliveries always carry a valid signature and a fresh timestamp."
        ),
        signal_kind="log",
        suggested_rule=(
            f"Log the signature header, its verification result and the signed timestamp for {listed}. "
            "Alert when a request arrives with the signature header missing, failing verification, or a "
            "timestamp older than 5 minutes; and when the same event/delivery id is seen twice. "
            "A burst of failures from one source IP suggests forging or timing probes."
        ),
        related_finding_titles=[f.title for f in related],
        related_rule_ids=[f.rule_id for f in related if f.rule_id],
        attack_techniques=techniques,
    )
    rendered = _webhook_rule(routes, opportunity.related_rule_ids, surfaces)
    if rendered is not None:
        _attach(opportunity, rendered)
    return opportunity


# ---------- Deployable rules per finding class (#251) ----------

# Caps: one rule per (rule id, method, route), at most this many routes per
# rule id, and a ceiling on per-route rules, shared fairly across rule ids,
# so a huge repo can't flood the report. The two SSRF follow-ups (metadata
# egress, CloudTrail) are per repository and sit outside the cap. The
# finding itself still lists every route; the rules cover the first ones.
_MAX_ROUTES_PER_RULE = 5
_MAX_RULE_OPPORTUNITIES = 60

# Taint sink kind (canonical) -> finding rule id, where it isn't the dashed kind.
_FLOW_RULE_IDS = {"sql_execute": "sql-injection", "path_traversal": "path-traversal"}
# Sinks only flow-confirmed chains count for (#239), as in `generate_findings`.
_FLOW_ONLY_SINKS = frozenset({"sql_execute", "dynamic_open"})
_BODY_SOURCES = frozenset({"body", "header", "cookie", "upload_filename", "message"})
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE", "MUTATION"})

# A quoted parameter name in the traced source expression
# (`request.args.get("q")`, `r.URL.Query().Get("q")`, `$_GET['q']`) or a
# dotted one (`req.query.q`).
_QUOTED_PARAM = re.compile(r"""["']([A-Za-z0-9_][A-Za-z0-9_.\-]{0,63})["']""")
_DOTTED_PARAM = re.compile(r"\.(?:query|params|args|form|GET)\.([A-Za-z_$][A-Za-z0-9_$]{0,63})")


# `suggested_rule` prefix of opportunities whose prose is their Sigma rule.
SIGMA_POINTER = "Deploy Sigma rule "

_BOLA_THRESHOLD = 50
_BOLA_TIMESPAN = "10m"


def _taint_rule_id(chain: TaintChain) -> str:
    kind = canonical_kind(chain.sink_kind)
    return _FLOW_RULE_IDS.get(kind, kind.replace("_", "-"))


def _location_keys(finding: Finding) -> set[tuple[str, int | None]]:
    return {(loc.file, loc.line) for loc in finding.locations}


def _source_param(chain: TaintChain) -> str | None:
    """The query parameter carrying the tainted value, when the traced source
    expression names one."""
    if chain.source_kind != "query":
        return None
    for step in chain.flow:
        if step.kind != "source" or not step.evidence_text:
            continue
        text = step.evidence_text.split(":", 1)[-1]
        match = _QUOTED_PARAM.search(text) or _DOTTED_PARAM.search(text)
        if match:
            return match.group(1)
    return None


def _short(text: str, limit: int = 120) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _checked(rendered: RenderedRule) -> RenderedRule | None:
    """Keep a rendered rule only if it is valid Sigma and its sample events
    behave: every positive matches, no negative does. A template filled with
    unusual repo text (a route containing a payload marker) is dropped rather
    than shipped broken."""
    if sigma_problems(rendered.sigma):
        return None
    if rendered.correlation is not None and correlation_problems(rendered.correlation, [rendered.sigma]):
        return None
    positives = rendered.test_events["positive"]
    if not positives or not all(sigma_matches(rendered.sigma, e) for e in positives):
        return None
    if any(sigma_matches(rendered.sigma, e) for e in rendered.test_events["negative"]):
        return None
    return rendered


def _attach(opportunity: DetectionOpportunity, rendered: RenderedRule) -> None:
    opportunity.sigma = rendered.sigma
    opportunity.sigma_correlation = rendered.correlation
    opportunity.logsource = DetectionLogsource(**rendered.logsource)
    opportunity.fields_required = rendered.fields_required
    opportunity.false_positive_notes = rendered.false_positive_notes
    opportunity.test_events = DetectionTestEvents(**rendered.test_events)


def _techniques(rule_id: str) -> list[AttackTechnique]:
    entry = taxonomy_for(rule_id)
    if entry is None:
        return []
    return [
        AttackTechnique(technique_id=tid, name=name, tactic=tactic, url=attack_url(tid))
        for tid in entry.attack
        for name, tactic in [ATTACK_TECHNIQUES[tid]]
    ]


def _rule_opportunity(
    *,
    opportunity_id: str,
    finding: Finding,
    rendered: RenderedRule,
    rationale: str,
    signal_kind: str = "log",
) -> DetectionOpportunity:
    sigma = rendered.sigma
    opportunity = _opportunity(
        opportunity_id=opportunity_id,
        title=sigma["title"],
        rationale=rationale,
        signal_kind=signal_kind,
        suggested_rule=(
            f"{SIGMA_POINTER}{sigma['id']} ({DetectionLogsource(**rendered.logsource).label()} logs). "
            + sigma["description"]
        ),
        related_finding_titles=[finding.title],
        related_rule_ids=[finding.rule_id] if finding.rule_id else [],
        attack_techniques=_techniques(finding.rule_id or ""),
    )
    _attach(opportunity, rendered)
    return opportunity


def _sigma_escape(text: str) -> str:
    """Escape Sigma's wildcard characters so a marker matches literally."""
    return text.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")


def _regex_escape(text: str) -> str:
    return regex_literal(text)


def _payload_selector(
    payload: dict, param: str | None, source_kind: str | None, path_has_params: bool
) -> tuple[dict | list[dict], str, bool]:
    """The payload selection (a field map, or a list of maps = any of them),
    where it looks (for the description), and whether the positive sample
    belongs in the request path rather than the query string."""
    raw = [str(m) for m in payload["contains"]]
    markers = [_sigma_escape(m) for m in raw]
    prefix = payload.get("anchor") == "prefix"
    if source_kind == "path_param" and path_has_params:
        return {"cs-uri-stem|contains": markers}, "path", True
    if param and payload.get("regex", True) and source_kind in (None, "query"):
        alternatives = "|".join(_regex_escape(m) for m in raw)
        regex = f"(?:^|&){_regex_escape(param)}=" + ("" if prefix else "[^&]*") + f"(?:{alternatives})"
        return {"cs-uri-query|re|i": regex}, f"`{param}` query parameter", False
    query = {"cs-uri-query|contains": [f"={m}" for m in markers] if prefix else markers}
    if source_kind is None and path_has_params:
        # Reachability-only chain: the input may be the path parameter or a
        # query parameter, so look in both.
        return [query, {"cs-uri-stem|contains": markers}], "query string or path", False
    return query, "query string", False


def _route_params(path: str) -> dict[str, str] | None:
    """Route selection params, or ``None`` when the route is too broad or
    too long to scope a rule to (see `detections.route_scopable`)."""
    selector = route_selector(path)
    if selector is None:
        return None
    return {"route_field": selector[0], "route_value": selector[1]}


def _taint_rule(rule_id: str, chain: TaintChain, payload: dict) -> RenderedRule | None:
    route = _route_params(chain.route_path)
    if route is None:
        return None
    method = sigma_method(chain.route_method)
    method_route = _short(f"{chain.route_method} {chain.route_path}")
    param = _source_param(chain)
    in_path = has_path_params(chain.route_path)
    selection, where, in_stem = _payload_selector(payload, param, chain.source_kind, in_path)
    name = param or "q"
    sample, benign = str(payload["sample"]), str(payload["benign"])
    if in_stem:
        positive_stem, positive_query = route_example(chain.route_path, sample), ""
    else:
        positive_stem = route_example(chain.route_path)
        positive_query = str(payload.get("query", "${param}=${sample}")).replace("${param}", name).replace(
            "${sample}", sample
        )
    blind = ""
    if chain.source_kind in _BODY_SOURCES:
        blind = (
            f" Blind spot: the traced input arrives in the request {chain.source_kind}, which access logs "
            "don't record; feed request bodies from a WAF or application log into cs-uri-query, or adapt the field."
        )
    source = f"{chain.source_kind} parameter {param}" if param else (chain.source_kind or "a request value")
    rendered = render_rule(
        "injection-route",
        rule_ids=[rule_id],
        key=f"{chain.route_method} {chain.route_path} {chain.route_file}",
        params={
            "label": payload["label"],
            "level": payload["level"],
            "method_route": method_route,
            "method": method,
            "method_example": method or "GET",
            **route,
            "route_example": route_example(chain.route_path),
            "payload_selection": selection,
            "payload_where": where,
            "positive_stem": positive_stem,
            "positive_query": positive_query,
            "negative_query": f"{name}={benign}",
            "source": source,
            "location": f"{chain.sink_file}:{chain.sink_line}" if chain.sink_line else chain.sink_file,
            "rule_id": rule_id,
            "blind_spot": blind,
        },
        extra_falsepositives=list(payload.get("falsepositives") or []),
    )
    return _checked(rendered)


def _taint_opportunities(scan: ScanResult, by_rule: dict[str, Finding]) -> list[DetectionOpportunity]:
    payloads = template_data("injection").get("payloads", {})
    covered = {rule_id: _location_keys(finding) for rule_id, finding in by_rule.items()}
    out: list[DetectionOpportunity] = []
    seen: set[tuple[str, str, str]] = set()
    per_rule: dict[str, int] = {}
    for chain in scan.taint_chains:
        if chain.sanitized or chain.speculative:
            continue
        if chain.sink_kind in _FLOW_ONLY_SINKS and not chain.source_kind:
            continue
        rule_id = _taint_rule_id(chain)
        finding = by_rule.get(rule_id)
        payload = payloads.get(rule_id)
        if finding is None or payload is None:
            continue
        # The chain must be one the (possibly partially suppressed) finding covers.
        if (chain.sink_file, chain.sink_line) not in covered[rule_id]:
            continue
        key = (rule_id, chain.route_method.upper(), chain.route_path)
        if key in seen or per_rule.get(rule_id, 0) >= _MAX_ROUTES_PER_RULE:
            continue
        rendered = _taint_rule(rule_id, chain, payload)
        if rendered is None:
            continue
        seen.add(key)
        per_rule[rule_id] = per_rule.get(rule_id, 0) + 1
        out.append(
            _rule_opportunity(
                opportunity_id=f"detect:{rule_id}:{chain.route_method.upper()}:{chain.route_path}",
                finding=finding,
                rendered=rendered,
                rationale=(
                    f"Request input reaches a {payload['label'].lower()} sink from "
                    f"{_short(chain.route_method + ' ' + chain.route_path)}. Requests carrying "
                    f"{payload['label'].lower()} syntax to that route are the exploitation attempts."
                ),
            )
        )
    return out


def _ssrf_followups(
    ssrf_opps: list[DetectionOpportunity], finding: Finding, scan: ScanResult
) -> list[DetectionOpportunity]:
    """Metadata-service egress and instance-credential reuse, once per scan."""
    covered = _location_keys(finding)
    chain = next(
        (
            c
            for c in scan.taint_chains
            if _taint_rule_id(c) == "ssrf" and not c.sanitized and not c.speculative
            and (c.sink_file, c.sink_line) in covered
        ),
        None,
    )
    if chain is None or not ssrf_opps:
        return []
    location = f"{chain.sink_file}:{chain.sink_line}" if chain.sink_line else chain.sink_file
    out: list[DetectionOpportunity] = []
    for template_id, signal_kind, rationale in (
        (
            "ssrf-metadata-egress",
            "network",
            "A working SSRF is usually pointed at the cloud metadata service first; the connection itself is "
            "visible in host or VPC network telemetry regardless of which route carried the request.",
        ),
        (
            "ssrf-instance-credentials-cloudtrail",
            "log",
            "Credentials stolen from the metadata service through SSRF are then used from the attacker's "
            "infrastructure; CloudTrail shows the instance role's session calling AWS from a foreign IP.",
        ),
    ):
        rendered = _checked(
            render_rule(template_id, rule_ids=["ssrf"], key=chain.sink_file, params={"location": location})
        )
        if rendered is not None:
            out.append(
                _rule_opportunity(
                    opportunity_id=f"detect:ssrf:{template_id}",
                    finding=finding,
                    rendered=rendered,
                    rationale=rationale,
                    signal_kind=signal_kind,
                )
            )
    return out


def _bola_rule(rule_id: str, cand: BolaCandidate) -> RenderedRule | None:
    route = _route_params(cand.route_path)
    if route is None:
        return None
    method = sigma_method(cand.route_method)
    in_path = cand.surface == "path_param" and has_path_params(cand.route_path)
    value_field = "cs-uri-stem" if in_path else "cs-uri-query"
    principal = "cs-username" if cand.authn_evidence else "c-ip"
    key = f"{cand.route_method} {cand.route_path}"
    rendered = render_rule(
        "bola-cardinality",
        rule_ids=[rule_id],
        key=f"{key} {cand.route_file}",
        params={
            "rule_name": "attackmap_bola_"
            + rule_uuid("bola-cardinality", rule_id, f"{key} {cand.route_file}").replace("-", "")[:12],
            "method_route": _short(key),
            "method": method,
            "method_example": method or "GET",
            **route,
            "positive_stem": route_example(cand.route_path),
            "positive_query": "" if in_path else f"{cand.id_param}=1001",
            "id_param": cand.id_param,
            "rule_id": rule_id,
            "location": f"{cand.route_file}:{cand.route_line}" if cand.route_line else cand.route_file,
            "principal_field": principal,
            "principal_value": "alice" if principal == "cs-username" else "203.0.113.10",
            "value_field": value_field,
            "threshold": _BOLA_THRESHOLD,
            "timespan": _BOLA_TIMESPAN,
            "level": "high" if rule_id == "bola-modify" else "medium",
        },
    )
    return _checked(rendered)


def _bola_opportunities(scan: ScanResult, by_rule: dict[str, Finding]) -> list[DetectionOpportunity]:
    covered = {r: _location_keys(f) for r, f in by_rule.items() if r in ("bola-read", "bola-modify")}
    out: list[DetectionOpportunity] = []
    seen: set[tuple[str, str, str]] = set()
    per_rule: dict[str, int] = {}
    for cand in scan.authz_candidates:
        if cand.has_ownership_check or cand.surface == "graphql_field":
            continue
        rule_id = "bola-modify" if cand.route_method.upper() in _WRITE_METHODS else "bola-read"
        finding = by_rule.get(rule_id)
        if finding is None or (cand.route_file, cand.route_line) not in covered[rule_id]:
            continue
        key = (rule_id, cand.route_method.upper(), cand.route_path)
        if key in seen or per_rule.get(rule_id, 0) >= _MAX_ROUTES_PER_RULE:
            continue
        rendered = _bola_rule(rule_id, cand)
        if rendered is None:
            continue
        seen.add(key)
        per_rule[rule_id] = per_rule.get(rule_id, 0) + 1
        out.append(
            _rule_opportunity(
                opportunity_id=f"detect:{rule_id}:{cand.route_method.upper()}:{cand.route_path}",
                finding=finding,
                rendered=rendered,
                rationale=(
                    f"{_short(cand.route_method + ' ' + cand.route_path)} takes the object id `{cand.id_param}` "
                    "without an object-level check. Enumeration shows up as one principal touching far more "
                    "distinct objects than normal use does."
                ),
            )
        )
    return out


def _webhook_rule(
    routes: list[str], rule_ids: list[str], surfaces: list[AttackSurface]
) -> RenderedRule | None:
    """Sigma rule for POSTs to the webhook routes without the provider's
    signature header. Routes whose provider is unknown are checked against
    every known signature header."""
    headers: dict[str, list[str]] = template_data("webhook").get("headers", {})
    providers: dict[str, str] = {}
    for surface in surfaces:
        verification = surface.webhook_verification
        if verification is not None and verification.provider in headers:
            providers.setdefault(surface.route, verification.provider)
    # Sorted, so the rule (and its id) doesn't depend on evidence order;
    # catch-all routes (`/:hook`, `*`) are left out rather than widening the
    # rule to every POST on the site.
    scoped = sorted({r.split(" ", 1)[-1] for r in routes if route_scopable(r.split(" ", 1)[-1])})[:10]
    groups: dict[str, list[str]] = {}
    for path in scoped:
        groups.setdefault(providers.get(path, "unknown"), []).append(path)
    if not groups:
        return None
    all_headers = [h for hs in headers.values() for h in hs]
    detection: dict[str, object] = {}
    used: list[str] = []
    for provider, paths in sorted(groups.items()):
        names = headers.get(provider, all_headers)
        stem = stem_selector(paths)
        if stem is None:
            continue
        selection: dict[str, object] = {"cs-method": "POST", stem[0]: stem[1]}
        for header in names:
            selection[f"cs({header})"] = None
            if header not in used:
                used.append(header)
        detection[f"selection_{provider}"] = selection
    detection["condition"] = "1 of selection_*"
    first_provider, first_paths = next(iter(sorted(groups.items())))
    example = route_example(first_paths[0])
    signed = headers.get(first_provider, all_headers)
    known = sorted(p for p in groups if p != "unknown")
    paths = scoped
    rendered = render_rule(
        "webhook-signature-missing",
        rule_ids=rule_ids or ["public-webhook"],
        key="|".join(scoped),
        params={
            "routes_text": ", ".join(_short(p, 80) for p in paths[:3]) + (" and more" if len(paths) > 3 else ""),
            "provider_text": "/".join(known) if known else "known provider",
            "state_text": "absent or weak signature verification",
            "rule_ids_text": ", ".join(rule_ids) or "public-webhook",
            "fields": ["cs-method", "cs-uri-stem", "sc-status", *[f"cs({h})" for h in used]],
            "detection": detection,
            "route_example": example,
            "signed_event": {
                "cs-method": "POST",
                "cs-uri-stem": example,
                "sc-status": 200,
                **{f"cs({h})": "t=1700000000,v1=5257a869e7" for h in signed},
            },
        },
    )
    return _checked(rendered)


def _workflow_opportunities(scan: ScanResult, by_rule: dict[str, Finding]) -> list[DetectionOpportunity]:
    """GitHub audit-log rules per untrusted trigger, and the CloudTrail rule
    for OIDC tokens minted by pull-request runs."""
    triggers: dict[str, dict] = template_data("workflow").get("triggers", {})
    # rule id -> workflow files its (unsuppressed) finding covers
    files: dict[str, list[str]] = {}
    covered: dict[str, set[tuple[str, int | None]]] = {}
    for issue in scan.workflow_issues:
        rule_id = issue.kind.replace("_", "-")
        finding = by_rule.get(rule_id)
        if finding is None:
            continue
        if rule_id not in covered:
            covered[rule_id] = _location_keys(finding)
        if (issue.file, issue.line) not in covered[rule_id]:
            continue
        if issue.file not in files.setdefault(rule_id, []):
            files[rule_id].append(issue.file)
    out: list[DetectionOpportunity] = []
    # One audit-log rule per trigger set; rule ids sharing it share the rule.
    by_events: dict[tuple[str, ...], list[str]] = {}
    for rule_id in files:
        if rule_id in triggers:
            by_events.setdefault(tuple(triggers[rule_id]["events"]), []).append(rule_id)
    for events, rule_ids in by_events.items():
        rule_ids = sorted(rule_ids)
        locations = [f for r in rule_ids for f in files[r]]
        rendered = _checked(
            render_rule(
                "github-untrusted-trigger-run",
                rule_ids=rule_ids,
                key="|".join([_repo_key(scan), *events, *sorted(locations)]),
                params={
                    "trigger_text": "/".join(events),
                    "triggers": list(events),
                    "trigger_example": events[0],
                    "kind_label": "; ".join(triggers[r]["label"] for r in rule_ids),
                    "location": _listed(locations),
                    "rule_id": ", ".join(rule_ids),
                },
            )
        )
        if rendered is None:
            continue
        opportunity = _rule_opportunity(
            opportunity_id=f"detect:workflow:{'+'.join(events)}",
            finding=by_rule[rule_ids[0]],
            rendered=rendered,
            rationale=(
                f"Runs triggered by {'/'.join(events)} execute attacker-influenced code in a workflow AttackMap "
                "flagged; the audit log shows who started each run."
            ),
        )
        for rule_id in rule_ids[1:]:
            opportunity.related_rule_ids.append(rule_id)
            opportunity.related_finding_titles.append(by_rule[rule_id].title)
        out.append(opportunity)
    if "oidc-on-untrusted-trigger" in files:
        rendered = _checked(
            render_rule(
                "github-oidc-untrusted-trigger-cloudtrail",
                rule_ids=["oidc-on-untrusted-trigger"],
                key="|".join([_repo_key(scan), *sorted(files["oidc-on-untrusted-trigger"])]),
                params={
                    "rule_id": "oidc-on-untrusted-trigger",
                    "location": _listed(files["oidc-on-untrusted-trigger"]),
                },
            )
        )
        if rendered is not None:
            out.append(
                _rule_opportunity(
                    opportunity_id="detect:oidc-on-untrusted-trigger:cloudtrail",
                    finding=by_rule["oidc-on-untrusted-trigger"],
                    rendered=rendered,
                    rationale=(
                        "An OIDC token minted by a pull-request run is only dangerous where a cloud role trusts it; "
                        "CloudTrail shows each such role assumption."
                    ),
                )
            )
    return out


def _secret_opportunities(scan: ScanResult, by_rule: dict[str, Finding]) -> list[DetectionOpportunity]:
    """CloudTrail rule for committed AWS access keys (placeholder key id:
    AttackMap keeps no secret values)."""
    data = template_data("secrets")
    kinds = set(data.get("aws_key_kinds") or [])
    out: list[DetectionOpportunity] = []
    for rule_id, items in (
        ("hardcoded-secret", scan.secret_hints),
        ("secret-in-git-history", scan.secret_history),
    ):
        finding = by_rule.get(rule_id)
        if finding is None:
            continue
        covered = _location_keys(finding)
        hits = [h for h in items if h.kind in kinds and (h.file, h.line) in covered]
        if not hits:
            continue
        locations = [f"{h.file}:{h.line}" if h.line else h.file for h in hits]
        rendered = _checked(
            render_rule(
                "aws-leaked-access-key-cloudtrail",
                rule_ids=[rule_id],
                key="|".join([_repo_key(scan), *sorted(locations)]),
                params={
                    "rule_id": rule_id,
                    "locations": _listed(locations),
                    "placeholder": data.get("placeholder", "REPLACE_WITH_LEAKED_ACCESS_KEY_ID"),
                },
            )
        )
        if rendered is not None:
            out.append(
                _rule_opportunity(
                    opportunity_id=f"detect:{rule_id}:aws-access-key",
                    finding=finding,
                    rendered=rendered,
                    rationale=(
                        "A committed AWS key must be rotated, but the leaked key itself stays useful as a tripwire: "
                        "kept active with no permissions, any use of it is an attacker who copied it."
                    ),
                )
            )
    return out


def _weakness_opportunities(scan: ScanResult, by_rule: dict[str, Finding]) -> list[DetectionOpportunity]:
    """App-wide request-marker rules for code weaknesses without a route."""
    markers: dict[str, dict] = template_data("weakness").get("markers", {})
    first: dict[str, str] = {}
    covered: dict[str, set[tuple[str, int | None]]] = {}
    for weakness in scan.code_weaknesses:
        rule_id = weakness.kind.replace("_", "-")
        finding = by_rule.get(rule_id)
        if rule_id in first or rule_id not in markers or finding is None:
            continue
        suffixes = tuple(markers[rule_id].get("suffixes") or ())
        if suffixes and not weakness.file.lower().endswith(suffixes):
            continue
        if rule_id not in covered:
            covered[rule_id] = _location_keys(finding)
        if (weakness.file, weakness.line) not in covered[rule_id]:
            continue
        first[rule_id] = f"{weakness.file}:{weakness.line}" if weakness.line else weakness.file
    out: list[DetectionOpportunity] = []
    for rule_id, location in first.items():
        spec = markers[rule_id]
        rendered = _checked(
            render_rule(
                "weakness-request-markers",
                rule_ids=[rule_id],
                key=f"{_repo_key(scan)}|{location.rsplit(':', 1)[0]}",
                params={
                    "label": spec["label"],
                    "kind_label": spec["kind_label"],
                    "level": spec["level"],
                    "markers": [_sigma_escape(str(m)) for m in spec["contains"]],
                    "falsepositives": list(spec.get("falsepositives") or []),
                    "sample": spec["sample"],
                    "benign": spec["benign"],
                    "location": location,
                    "rule_id": rule_id,
                },
            )
        )
        if rendered is not None:
            out.append(
                _rule_opportunity(
                    opportunity_id=f"detect:{rule_id}:requests",
                    finding=by_rule[rule_id],
                    rendered=rendered,
                    rationale=(
                        f"{spec['label']} has no single route here; requests probing for it carry recognizable "
                        "markers in the query string."
                    ),
                )
            )
    return out


def _repo_key(scan: ScanResult) -> str:
    """The scanned directory's name, folded into the ids of repository-wide
    rules (workflows, keys, weaknesses) whose other inputs, such as
    `.github/workflows/ci.yml`, repeat across repositories."""
    try:
        return Path(scan.root).resolve().name
    except (OSError, RuntimeError, ValueError):
        return Path(scan.root).name


def _listed(items: list[str], limit: int = 3) -> str:
    shown = ", ".join(_short(i, 80) for i in items[:limit])
    return shown + (f" and {len(items) - limit} more" if len(items) > limit else "")


def _cloud_opportunities(scan: ScanResult, findings: list[Finding]) -> list[DetectionOpportunity]:
    """Kubernetes audit-log and CloudTrail rules for cloud / IaC
    misconfigurations (#351), one per template per repository. A template
    applies to the records its mapping allows (platform, AWS resource type)
    that a finding of that rule id still covers after suppression; cloud
    findings are tiered, so the covered set is the union over the tiers."""
    mapping: dict[str, list[dict]] = template_data("cloud").get("mapping", {})
    if not scan.cloud_misconfigs or not mapping:
        return []
    covered: dict[str, set[tuple[str, int | None]]] = {}
    first: dict[str, Finding] = {}
    for finding in findings:
        if finding.rule_id in mapping:
            covered.setdefault(finding.rule_id, set()).update(_location_keys(finding))
            first.setdefault(finding.rule_id, finding)
    # template id -> (rule ids, locations), in first-seen order
    plan: dict[str, tuple[list[str], list[str]]] = {}
    for record in scan.cloud_misconfigs:
        rule_id = record.kind.replace("_", "-")
        if rule_id not in covered or (record.file, record.line) not in covered[rule_id]:
            continue
        resource_type = (record.resource or "").split(".", 1)[0]
        for spec in mapping[rule_id]:
            platforms = spec.get("platforms") or []
            types = spec.get("resource_types") or []
            if platforms and record.platform not in platforms:
                continue
            if types and resource_type not in types:
                continue
            rule_ids, locations = plan.setdefault(spec["template"], ([], []))
            if rule_id not in rule_ids:
                rule_ids.append(rule_id)
            where = f"{record.file}:{record.line}" if record.line else record.file
            if record.resource:
                where = f"{record.resource} ({where})"
            if where not in locations:
                locations.append(where)
    out: list[DetectionOpportunity] = []
    for template_id, (rule_ids, locations) in plan.items():
        rendered = _checked(
            render_rule(
                template_id,
                rule_ids=rule_ids,
                key="|".join([_repo_key(scan), template_id]),
                params={"locations": _listed(locations), "rule_id": ", ".join(rule_ids)},
            )
        )
        if rendered is None:
            continue
        opportunity = _rule_opportunity(
            opportunity_id=f"detect:cloud:{template_id}",
            finding=first[rule_ids[0]],
            rendered=rendered,
            rationale=(
                "The repository's infrastructure code applies this setting; the control-plane log shows "
                "it being applied, by whom, and to which resource, including copies AttackMap never saw."
            ),
        )
        for rule_id in rule_ids[1:]:
            opportunity.related_rule_ids.append(rule_id)
            opportunity.related_finding_titles.append(first[rule_id].title)
        out.append(opportunity)
    return out


def _finding_class_opportunities(findings: list[Finding], scan: ScanResult) -> list[DetectionOpportunity]:
    by_rule: dict[str, Finding] = {}
    for finding in findings:
        if finding.rule_id and finding.rule_id not in by_rule:
            by_rule[finding.rule_id] = finding
    # Per-route rules share one budget (fairly across rule ids); the
    # per-repository rules (a handful at most, one per template) are always kept.
    routes = _fair_cap(_taint_opportunities(scan, by_rule) + _bola_opportunities(scan, by_rule))
    out = [o for o in routes if not o.id.startswith("detect:bola-")]
    ssrf_finding = by_rule.get("ssrf")
    if ssrf_finding is not None:
        out += _ssrf_followups([o for o in out if "ssrf" in o.related_rule_ids], ssrf_finding, scan)
    out += [o for o in routes if o.id.startswith("detect:bola-")]
    out += _workflow_opportunities(scan, by_rule)
    out += _secret_opportunities(scan, by_rule)
    out += _weakness_opportunities(scan, by_rule)
    out += _cloud_opportunities(scan, findings)
    return out


def _fair_cap(opportunities: list[DetectionOpportunity], limit: int = _MAX_RULE_OPPORTUNITIES) -> list[DetectionOpportunity]:
    """At most ``limit`` per-route rules, taken round-robin across rule ids
    so no class (often BOLA, generated last) is the one always dropped.
    Kept rules stay in their original order."""
    if len(opportunities) <= limit:
        return opportunities
    by_rule: dict[str, list[int]] = {}
    for index, opp in enumerate(opportunities):
        by_rule.setdefault(opp.related_rule_ids[0] if opp.related_rule_ids else "", []).append(index)
    keep: set[int] = set()
    queues = list(by_rule.values())
    depth = 0
    while len(keep) < limit and any(depth < len(q) for q in queues):
        for queue in queues:
            if depth < len(queue) and len(keep) < limit:
                keep.add(queue[depth])
        depth += 1
    return [opp for index, opp in enumerate(opportunities) if index in keep]


def detection_coverage(
    findings: list[Finding], opportunities: list[DetectionOpportunity]
) -> list[dict[str, object]]:
    """Per finding class (rule id) in this report: how many deployable rules
    cover it and from which log sources (#251)."""
    rows: list[dict[str, object]] = []
    seen: set[str] = set()
    for finding in findings:
        rule_id = finding.rule_id
        if not rule_id or rule_id in seen or rule_id in INFORMATIONAL_RULES:
            continue
        seen.add(rule_id)
        covering = [o for o in opportunities if o.sigma is not None and rule_id in o.related_rule_ids]
        sources: list[str] = []
        for opp in covering:
            label = opp.logsource.label() if opp.logsource else "unknown"
            if label not in sources:
                sources.append(label)
        rows.append(
            {
                "rule_id": rule_id,
                "title": finding.title,
                "sigma_rules": len(covering),
                "correlation_rules": sum(1 for o in covering if o.sigma_correlation is not None),
                "logsources": sources,
            }
        )
    return rows


_UBIQUITOUS = frozenset({"T1190"})


def _parent(technique_id: str) -> str:
    return technique_id.split(".", 1)[0]


__all__ = ["SIGMA_POINTER", "detection_coverage", "generate_detection_opportunities"]
