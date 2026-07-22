from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from .diff import finding_id
from .models import AttackPath, AttackSurface, Finding, ScanResult
from .security_overlay import build_security_overlay

LOW_QUALITY_SEGMENTS = ("/tests/", "/__tests__/", "/fixtures/", "/mocks/", "/examples/")


SYSTEM_PROMPT_TEMPLATE = """You are AttackMap Review Analyst, a defensive security reviewer.

Operating rules:
- Be evidence-first. Every claim must map to provided evidence.
- Do not invent findings, routes, services, data stores, trust boundaries, or mitigations.
- Distinguish observed vs inferred signals clearly.
- Keep output defensive and remediation-oriented. Do not provide offensive exploitation instructions.
- If evidence is weak or partial, say so directly.

The evidence pack now includes five layers you must reason over:
- `assets` — value-at-risk inventory (with criticality)
- `controls` — defensive controls observed AND expected-but-absent
- `notable_observations` — pre-computed cross-cutting insights connecting assets, controls, surfaces, and chains
- `attack_techniques_observed` — MITRE ATT&CK technique mappings for findings and insights
- `detection_opportunities` — defender-facing detection-engineering hints (Sigma/KQL-style rule sketches)

When writing the review, lead with the highest-severity notable_observations and connect them to specific assets, controls, and ATT&CK techniques. Tell the story — do not just enumerate findings. Explicitly call out where a defense gap meets a critical asset, and reference the relevant ATT&CK technique(s) and any detection opportunity that would catch the same condition at runtime.

Output sections (in order):
1. System Overview
2. Notable Observations (top 3, each as a 2–4 sentence story citing surface/finding/asset/control IDs and the ATT&CK technique it maps to)
3. Asset and Control Map (which crown jewels exist, what protects them, what is missing)
4. Detection Opportunities (top 3 — for each, name the runtime signal that would catch the static finding)
5. Strengths
6. Weaknesses / Risk Hotspots
7. Key Evidence Chains
8. Prioritized Recommendations
9. Analyst Confidence and Limitations

Formatting constraints:
- Use concise, human-readable language for engineers and defenders.
- For each weakness and recommendation, include why it is prioritized.
- Cite evidence IDs from the provided evidence pack where practical (surface:N, finding:N, path:N, asset:*, control:*, insight:*).
"""


USER_PROMPT_TEMPLATE = """Generate a grounded defensive review for this repository.

Requirements:
- Use only the evidence pack below.
- Mark each major statement as OBSERVED or INFERRED.
- Prioritize by practical defensive risk reduction.
- Include explicit trust-boundary commentary where evidence supports it.
- Call out source-quality caveats (tests/fixtures/examples) when relevant.

Repository context:
{repo_context}

Evidence pack (JSON):
{evidence_json}
"""


HUNT_SYSTEM_PROMPT = """You are AttackMap Hunt Analyst, an experienced red-team reviewer generating VULNERABILITY HYPOTHESES for a human to confirm.

Your job is NOT to report confirmed vulnerabilities. It is to reason over the structured evidence and surface candidate exploit chains and weakness hypotheses that a human analyst might miss — especially NOVEL combinations that span multiple signals (e.g. a public unauthenticated surface whose taint chain reaches a dangerous sink next to a critical asset, or an outlier route that breaks a cohort's auth norm).

Hard rules (violating any of these makes the output worthless):
- These are HYPOTHESES / LEADS, not detections. Every hypothesis is something a human must verify by reading the code.
- Ground everything. Each hypothesis MUST cite specific evidence IDs from the pack (surface:N, finding:N, path:N, taint:N, exploit:N, anomaly:N, asset:*, control:*, insight:*). Do NOT invent routes, files, sinks, data stores, or CVEs. If you cannot ground a hypothesis in provided evidence, do not emit it.
- Do NOT assign CVE identifiers. Do NOT write exploit code, payloads, or step-by-step exploitation instructions. Describe the *chain* and the *class* of weakness only.
- Be honest about uncertainty. Prefer fewer, higher-quality hypotheses over speculation. If the evidence is thin, say the hypothesis is speculative and rank it low.

For each hypothesis provide:
- **Title** — the candidate weakness/chain in one line.
- **Confidence tier** — HIGH / MEDIUM / LOW / SPECULATIVE (based on how directly the evidence supports it).
- **Hypothesized chain** — the entry → propagation → impact story, referencing the evidence IDs at each step.
- **Evidence** — the exact IDs this rests on.
- **What a human must verify** — the concrete checks (which file/function to read, which assumption to confirm) that would confirm or kill this lead.

Output ordering: rank hypotheses by (confidence tier, then potential impact), highest first."""


HUNT_USER_PROMPT = """Act as a red-team analyst and produce ranked VULNERABILITY HYPOTHESES for this repository — candidate exploit chains and weakness leads for a human to confirm.

Requirements:
- Use ONLY the evidence pack below; cite evidence IDs for every hypothesis.
- Favor novel cross-signal combinations (surface + taint + asset + control gap + anomaly) over restating a single finding.
- Each hypothesis must include its confidence tier and an explicit "what a human must verify" section.
- No CVE assignment, no exploit code. Hypotheses, not detections.
- If the evidence supports few or no credible chains, say so plainly rather than inventing leads.

Repository context:
{repo_context}

Evidence pack (JSON):
{evidence_json}
"""


REMEDIATION_SYSTEM_PROMPT = """You are AttackMap Remediation Engineer. For each finding in the evidence pack, propose a concrete, minimal fix a developer can review and apply.

Hard rules:
- Ground every suggestion in the finding's cited evidence (file:line) and its `mitigation` text. Do NOT invent files, functions, routes, or APIs that aren't in the evidence pack.
- Suggestions are REVIEW-FIRST, not auto-applied. Where the exact code isn't in the evidence, describe the change precisely (what to add/replace, and where) rather than fabricating a diff you can't ground.
- Prefer the smallest change that removes the vulnerability class (parameterize the query, add the missing auth guard, allow-list the field, pin the algorithm, disable the entity resolver, upgrade the pinned dependency).
- No exploit code. Be honest when a fix needs human judgment (e.g. "confirm this route should require auth") or when the evidence is too thin to propose a specific change.

For each finding provide:
- **Finding** — title + the evidence id(s) it addresses.
- **Fix** — the concrete change, as a suggested diff/snippet when the code is in evidence, else a precise instruction (file + what to change).
- **Why it works** — one line tying the change to the weakness class.
- **Verify** — how the developer confirms the fix (test to run, behavior to check).

Order by severity, then exploitability. Group identical fixes across many sites into one suggestion noting the count."""


REMEDIATION_USER_PROMPT = """Propose concrete, review-first remediations for the findings in this repository.

Requirements:
- Use ONLY the evidence pack below; cite finding/evidence ids.
- Smallest safe change per finding; group repeated fixes.
- No invented code, no exploit code; flag where human judgment is needed.

Repository context:
{repo_context}

Evidence pack (JSON):
{evidence_json}
"""


TRIAGE_SYSTEM_PROMPT = """You are AttackMap Triage Analyst. You do NOT find new issues — you ORGANIZE the existing heuristic findings in the evidence pack into a prioritized, de-duplicated, clustered shortlist a reviewer can work top-down.

Hard rules:
- Use ONLY findings already in the evidence pack. Do NOT invent findings, routes, files, sinks, data stores, or CVEs. Every item you list MUST cite the finding's `finding_id` (and may cite `finding:N`).
- Do NOT change a finding's severity or evidence. You may group related findings and explain WHY they cluster (shared root cause, same trust boundary, same asset), but the underlying facts stay as given.
- Cluster by root cause (e.g. "missing authorization", "injection reachable from public routes", "vulnerable dependencies", "weak crypto"). Within and across clusters, rank by severity, then exploitability, then score.
- Be concise: a ranked list, each item one or two lines. Lead with the cluster that most needs attention.

For each shortlist item:
- **[rank] finding_id — title** (severity, and exploitability/score if present)
- one-line rationale: why it ranks here / what it clusters with.

End with a one-paragraph "start here" summary naming the top cluster and the single highest-priority finding_id."""


TRIAGE_USER_PROMPT = """Triage the existing findings for this repository into a ranked, clustered shortlist.

Requirements:
- Organize ONLY the findings in the evidence pack; cite each by `finding_id`.
- Cluster by root cause; rank by severity, then exploitability, then score.
- Do not invent or re-score findings; this is prioritization, not discovery.

Repository context:
{repo_context}

Evidence pack (JSON):
{evidence_json}
"""


@dataclass(frozen=True)
class RenderedReviewPrompt:
    system: str
    user: str
    evidence_json: str


def _is_low_quality_source(path_or_text: str) -> bool:
    normalized = path_or_text.replace("\\", "/").lower()
    return any(segment in f"/{normalized}/" for segment in LOW_QUALITY_SEGMENTS)


def _is_protocol_derived_surface(surface: AttackSurface) -> bool:
    file_lower = surface.file.lower()
    route_lower = surface.route.lower()
    return "lexicon" in file_lower or "/xrpc/" in route_lower or "atproto_" in " ".join(surface.auth_signals).lower()


def _surface_evidence_class(surface: AttackSurface) -> str:
    if _is_low_quality_source(surface.file):
        return "low_quality"
    if _is_protocol_derived_surface(surface):
        return "inferred_protocol"
    if surface.exposure == "public":
        return "observed_runtime_public"
    if surface.exposure == "internal":
        return "observed_runtime_internal"
    return "inferred"


def _repo_context(scan: ScanResult) -> str:
    language_text = ", ".join(scan.languages) if scan.languages else "unknown"
    datastore_text = ", ".join(sorted({db.kind for db in scan.databases})) if scan.databases else "none"
    return (
        f"root={scan.root}; files_scanned={scan.files_scanned}; "
        f"languages={language_text}; routes={len(scan.routes)}; "
        f"external_calls={len(scan.external_calls)}; datastores={datastore_text}; "
        f"auth_hints={len(scan.auth_hints)}; secret_hints={len(scan.secret_hints)}"
    )


def _evidence_pack(
    scan: ScanResult,
    attack_surfaces: list[AttackSurface],
    findings: list[Finding],
    attack_paths: list[AttackPath],
) -> dict:
    surfaces_payload = [
        {
            "id": f"surface:{idx + 1}",
            "method": surface.method,
            "route": surface.route,
            "file": surface.file,
            "category": surface.category,
            "exposure": surface.exposure,
            "risk": surface.risk,
            "evidence_class": _surface_evidence_class(surface),
            "auth_signals": surface.auth_signals,
            "data_store_interaction": surface.data_store_interaction,
            "outbound_integration": surface.outbound_integration,
            "rationale": surface.rationale,
        }
        for idx, surface in enumerate(attack_surfaces[:50])
    ]

    findings_payload = [
        {
            "id": f"finding:{idx + 1}",
            "finding_id": finding_id(finding.title),
            "title": finding.title,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "score": finding.score,
            "exploitability": finding.exploitability,
            "evidence": finding.evidence[:10],
            "mitigation": finding.mitigation,
        }
        for idx, finding in enumerate(findings[:30])
    ]

    attack_paths_payload = [
        {
            "id": f"path:{idx + 1}",
            "name": path.name,
            "steps": path.steps[:8],
            "impact": path.impact,
        }
        for idx, path in enumerate(attack_paths[:10])
    ]

    evidence_counts = {
        "observed_runtime_public": sum(1 for item in surfaces_payload if item["evidence_class"] == "observed_runtime_public"),
        "observed_runtime_internal": sum(1 for item in surfaces_payload if item["evidence_class"] == "observed_runtime_internal"),
        "inferred_protocol": sum(1 for item in surfaces_payload if item["evidence_class"] == "inferred_protocol"),
        "low_quality": sum(1 for item in surfaces_payload if item["evidence_class"] == "low_quality"),
    }

    overlay = build_security_overlay(scan, attack_surfaces, findings, attack_paths)
    assets_payload = [asset.model_dump() for asset in overlay.assets]
    controls_payload = [control.model_dump() for control in overlay.controls]
    insights_payload = [insight.model_dump() for insight in overlay.insights]
    detection_payload = [opp.model_dump() for opp in overlay.detection_opportunities]

    techniques_observed: dict[str, dict] = {}
    for insight in overlay.insights:
        for tech in insight.attack_techniques:
            techniques_observed.setdefault(tech.technique_id, tech.model_dump())
    for finding in overlay.findings:
        for tech in finding.attack_techniques:
            techniques_observed.setdefault(tech.technique_id, tech.model_dump())
    techniques_payload = sorted(techniques_observed.values(), key=lambda t: t["technique_id"])

    return {
        "scan_summary": {
            "root": scan.root,
            "files_scanned": scan.files_scanned,
            "languages": scan.languages,
            "route_count": len(scan.routes),
            "external_call_count": len(scan.external_calls),
            "database_count": len(scan.databases),
            "auth_hint_count": len(scan.auth_hints),
            "secret_hint_count": len(scan.secret_hints),
            "asset_count": len(assets_payload),
            "control_count_present": sum(1 for c in controls_payload if c["strength"] != "absent"),
            "control_count_absent": sum(1 for c in controls_payload if c["strength"] == "absent"),
            "notable_observation_count": len(insights_payload),
            "detection_opportunity_count": len(detection_payload),
            "attack_techniques_observed_count": len(techniques_payload),
        },
        "evidence_counts": evidence_counts,
        "attack_surfaces": surfaces_payload,
        "findings": findings_payload,
        "attack_paths": attack_paths_payload,
        "assets": assets_payload,
        "controls": controls_payload,
        "notable_observations": insights_payload,
        "detection_opportunities": detection_payload,
        "attack_techniques_observed": techniques_payload,
    }


def render_system_prompt() -> str:
    return SYSTEM_PROMPT_TEMPLATE.strip()


def render_user_prompt(
    scan: ScanResult,
    attack_surfaces: list[AttackSurface],
    findings: list[Finding],
    attack_paths: list[AttackPath],
) -> str:
    evidence_payload = _evidence_pack(scan, attack_surfaces, findings, attack_paths)
    evidence_json = json.dumps(evidence_payload, indent=2, sort_keys=True)
    return USER_PROMPT_TEMPLATE.format(repo_context=_repo_context(scan), evidence_json=evidence_json).strip()


def render_review_prompts(
    scan: ScanResult,
    attack_surfaces: list[AttackSurface],
    findings: list[Finding],
    attack_paths: list[AttackPath],
) -> RenderedReviewPrompt:
    evidence_payload = _evidence_pack(scan, attack_surfaces, findings, attack_paths)
    evidence_json = json.dumps(evidence_payload, indent=2, sort_keys=True)
    return RenderedReviewPrompt(
        system=render_system_prompt(),
        user=USER_PROMPT_TEMPLATE.format(repo_context=_repo_context(scan), evidence_json=evidence_json).strip(),
        evidence_json=evidence_json,
    )


def _hunt_evidence_pack(
    scan: ScanResult,
    attack_surfaces: list[AttackSurface],
    findings: list[Finding],
    attack_paths: list[AttackPath],
) -> dict:
    """Base evidence pack augmented with the raw signals a hunter reasons over
    directly: taint chains, fused exploitability scores, and anomalies. These
    carry their own citable IDs (taint:N, exploit:N, anomaly:N)."""
    from .exploitability import score_exploitability

    pack = _evidence_pack(scan, attack_surfaces, findings, attack_paths)
    pack["taint_chains"] = [
        {
            "id": f"taint:{idx + 1}",
            "route": f"{c.route_method} {c.route_path}",
            "route_file": c.route_file,
            "sink_kind": c.sink_kind,
            "sink": f"{c.sink_file}:{c.sink_line}",
            "hops": c.hops,
            "import_path": c.files[:8],
        }
        for idx, c in enumerate(scan.taint_chains[:40])
    ]
    pack["exploitability"] = [
        {
            "id": f"exploit:{idx + 1}",
            "subject": s.subject,
            "score": s.score,
            "tier": s.tier,
            "factors": [f"{f.name} ({f.points:+d})" for f in s.factors],
        }
        for idx, s in enumerate(score_exploitability(scan, attack_surfaces)[:20])
    ]
    pack["anomalies"] = [
        {
            "id": f"anomaly:{idx + 1}",
            "kind": a.kind,
            "route": f"{a.route_method} {a.route_path}",
            "peer_group": a.peer_group,
            "deviation": a.deviation,
            "confidence": a.confidence,
        }
        for idx, a in enumerate(scan.anomalies[:30])
    ]
    return pack


def render_hunt_prompts(
    scan: ScanResult,
    attack_surfaces: list[AttackSurface],
    findings: list[Finding],
    attack_paths: list[AttackPath],
) -> RenderedReviewPrompt:
    """Render the red-team vulnerability-hypothesis prompts (#80). Same
    grounding contract as the review — every hypothesis must cite evidence IDs."""
    evidence_payload = _hunt_evidence_pack(scan, attack_surfaces, findings, attack_paths)
    evidence_json = json.dumps(evidence_payload, indent=2, sort_keys=True)
    return RenderedReviewPrompt(
        system=HUNT_SYSTEM_PROMPT.strip(),
        user=HUNT_USER_PROMPT.format(repo_context=_repo_context(scan), evidence_json=evidence_json).strip(),
        evidence_json=evidence_json,
    )


HUNT_VERIFY_SYSTEM_PROMPT = """You are AttackMap Hunt Verifier, an adversarial red-team reviewer.

You are given the SAME evidence pack as the hunt, PLUS a `code_excerpts` section containing the ACTUAL SOURCE at each cited route/sink location. Your job is to produce vulnerability hypotheses AND adjudicate each one against the shown code.

For every hypothesis, assign a VERDICT:
- **CONFIRMED** — the shown code clearly exhibits the weakness (e.g. request data concatenated into the query at the cited sink line).
- **REFUTED** — the shown code contradicts the hypothesis (e.g. the query is parameterized, the value is a constant, an auth guard is present, the sink consumes a static local file). Refute aggressively; a plausible-but-wrong lead is worse than none.
- **NEEDS HUMAN REVIEW** — the excerpt is insufficient (the relevant code isn't shown, or provenance can't be determined from what's provided).

Hard rules:
- Base each verdict on the `code_excerpts` when the location is present; do NOT invent code beyond what's shown.
- Cite the evidence ids and the excerpt you relied on. No CVE assignment, no exploit code.
- Prefer fewer, well-adjudicated hypotheses over speculation.

For each: **Title**, **Verdict** (+ one-line justification quoting the excerpt), **Hypothesized chain** (evidence ids), **What a human must verify** (only for CONFIRMED / NEEDS REVIEW). Order CONFIRMED first, then NEEDS REVIEW, then REFUTED."""


HUNT_VERIFY_USER_PROMPT = """Produce and adjudicate vulnerability hypotheses for this repository. For each, assign CONFIRMED / REFUTED / NEEDS HUMAN REVIEW based on the actual source in `code_excerpts`.

Requirements:
- Use ONLY the evidence pack + code excerpts below; cite ids and the excerpt line you relied on.
- Refute leads the shown code contradicts (parameterized query, constant arg, auth present, static-file sink).
- No CVE assignment, no exploit code.

Repository context:
{repo_context}

Evidence pack (JSON):
{evidence_json}
"""


def _code_excerpts(scan: ScanResult, findings: list[Finding], max_locations: int = 24, ctx: int = 3) -> dict:
    """Gather actual source at cited route/sink/finding locations so the verify
    pass adjudicates against real code, not abstract ids (#hunt-verify)."""
    root = Path(scan.root)
    locs: list[tuple[str, int]] = []
    for c in scan.taint_chains:
        if c.sink_line:
            locs.append((c.sink_file, c.sink_line))
    loc_re = re.compile(r"([^\s:]+\.[A-Za-z0-9]+):(\d+)")
    for f in findings:
        for ev in f.evidence:
            m = loc_re.search(ev)
            if m:
                locs.append((m.group(1), int(m.group(2))))
                break
    seen: set[tuple[str, int]] = set()
    out: dict[str, str] = {}
    file_cache: dict[str, list[str]] = {}
    for rel, line in locs:
        key = (rel, line)
        if key in seen or len(out) >= max_locations:
            continue
        seen.add(key)
        if rel not in file_cache:
            try:
                p = root / rel
                file_cache[rel] = (
                    p.read_text(encoding="utf-8", errors="ignore").splitlines()
                    if p.is_file() and p.stat().st_size <= 1_000_000
                    else []
                )
            except (OSError, ValueError):
                file_cache[rel] = []
        lines = file_cache[rel]
        if not lines:
            continue
        lo = max(0, line - 1 - ctx)
        hi = min(len(lines), line + ctx)
        excerpt = "\n".join(f"{i + 1}: {lines[i]}" for i in range(lo, hi))
        out[f"{rel}:{line}"] = excerpt
    return out


def render_hunt_verify_prompts(
    scan: ScanResult,
    attack_surfaces: list[AttackSurface],
    findings: list[Finding],
    attack_paths: list[AttackPath],
) -> RenderedReviewPrompt:
    """Hunt evidence pack augmented with actual source at cited locations, for
    an adjudicated (CONFIRMED/REFUTED/NEEDS-REVIEW) hunt pass."""
    pack = _hunt_evidence_pack(scan, attack_surfaces, findings, attack_paths)
    pack["code_excerpts"] = _code_excerpts(scan, findings)
    evidence_json = json.dumps(pack, indent=2, sort_keys=True)
    return RenderedReviewPrompt(
        system=HUNT_VERIFY_SYSTEM_PROMPT.strip(),
        user=HUNT_VERIFY_USER_PROMPT.format(
            repo_context=_repo_context(scan), evidence_json=evidence_json
        ).strip(),
        evidence_json=evidence_json,
    )


# The multi-pass hunt harness (#147) generates hypotheses once, then has N
# independent skeptics adjudicate the SAME fixed list. Generation appends a
# machine-readable block so the harness can extract a stable, id-keyed list.
HYPOTHESIS_MARKER = "=== HYPOTHESES ==="

HUNT_GENERATE_SYSTEM_PROMPT = (
    HUNT_SYSTEM_PROMPT
    + "\n\nAt the very END of your response, output a final section that begins with"
    f" the EXACT line:\n{HYPOTHESIS_MARKER}\n"
    "Then one line per hypothesis you surfaced above, numbered in the same order:\n"
    "H<n>: <one-line title> [evidence: <ids>]\n"
    "This machine-readable list is REQUIRED and must cover every hypothesis exactly once."
)

HUNT_SKEPTIC_SYSTEM_PROMPT = """You are an independent AttackMap Hunt Skeptic. You are given a FIXED numbered list of vulnerability hypotheses (evidence pack key `hypotheses`), the structured evidence, and a `code_excerpts` section with the ACTUAL source at cited locations. Adjudicate EACH hypothesis by its id against the shown code — independently, as if no one else has judged it.

Verdicts:
- CONFIRMED — the shown code clearly exhibits the weakness.
- REFUTED — the shown code contradicts it (parameterized query, constant arg, auth guard present, static-file sink), OR no provided evidence supports it.
- NEEDS_REVIEW — the excerpt shown is insufficient to decide.

Bias: refute aggressively. A plausible-but-wrong lead is worse than none. When genuinely unsure, prefer REFUTED over CONFIRMED.

OUTPUT FORMAT — for EVERY hypothesis id, exactly one line, nothing else:
VERDICT <id>: <CONFIRMED|REFUTED|NEEDS_REVIEW> — <one-line justification citing the excerpt/evidence>
Emit a line for every id in the list; never invent ids that aren't listed. No CVE assignment, no exploit code."""

HUNT_SKEPTIC_USER_PROMPT = """Independently adjudicate each listed hypothesis against the actual source in `code_excerpts`. One `VERDICT <id>: …` line per hypothesis, no other prose.

Repository context:
{repo_context}

Evidence pack (JSON):
{evidence_json}
"""


def render_hunt_generate_prompts(
    scan: ScanResult,
    attack_surfaces: list[AttackSurface],
    findings: list[Finding],
    attack_paths: list[AttackPath],
) -> RenderedReviewPrompt:
    """Hunt generation pass for the multi-pass harness (#147a): produces ranked
    hypotheses PLUS a machine-readable `=== HYPOTHESES ===` list the harness
    parses into a fixed, id-keyed set for independent verification."""
    evidence_payload = _hunt_evidence_pack(scan, attack_surfaces, findings, attack_paths)
    evidence_json = json.dumps(evidence_payload, indent=2, sort_keys=True)
    return RenderedReviewPrompt(
        system=HUNT_GENERATE_SYSTEM_PROMPT.strip(),
        user=HUNT_USER_PROMPT.format(repo_context=_repo_context(scan), evidence_json=evidence_json).strip(),
        evidence_json=evidence_json,
    )


def render_skeptic_prompts(
    scan: ScanResult,
    attack_surfaces: list[AttackSurface],
    findings: list[Finding],
    attack_paths: list[AttackPath],
    hypotheses: list[dict],
) -> RenderedReviewPrompt:
    """One independent skeptic pass (#147a): adjudicate a FIXED id-keyed
    hypothesis list against `code_excerpts`. ``hypotheses`` is a list of
    ``{"id": "H1", "title": "…"}`` dicts (kept plain to avoid an import cycle)."""
    pack = _hunt_evidence_pack(scan, attack_surfaces, findings, attack_paths)
    pack["code_excerpts"] = _code_excerpts(scan, findings)
    pack["hypotheses"] = [{"id": h["id"], "title": h["title"]} for h in hypotheses]
    evidence_json = json.dumps(pack, indent=2, sort_keys=True)
    return RenderedReviewPrompt(
        system=HUNT_SKEPTIC_SYSTEM_PROMPT.strip(),
        user=HUNT_SKEPTIC_USER_PROMPT.format(
            repo_context=_repo_context(scan), evidence_json=evidence_json
        ).strip(),
        evidence_json=evidence_json,
    )


def render_triage_prompts(
    scan: ScanResult,
    attack_surfaces: list[AttackSurface],
    findings: list[Finding],
    attack_paths: list[AttackPath],
) -> RenderedReviewPrompt:
    """Render the triage prompts (#145): cluster/dedupe/rank the EXISTING
    findings into a shortlist that cites real finding IDs — organization, not
    discovery."""
    # Pre-rank by the triage priority (severity → exploitability → score) and
    # dedupe before the evidence pack applies its finding cap, so the pack's
    # top-N are the actual top priorities — otherwise the LLM could miss a
    # high-exploitability finding the deterministic fallback would surface (#145).
    from .triage import rank_findings

    ranked = rank_findings(findings)
    evidence_payload = _evidence_pack(scan, attack_surfaces, ranked, attack_paths)
    evidence_json = json.dumps(evidence_payload, indent=2, sort_keys=True)
    return RenderedReviewPrompt(
        system=TRIAGE_SYSTEM_PROMPT.strip(),
        user=TRIAGE_USER_PROMPT.format(
            repo_context=_repo_context(scan), evidence_json=evidence_json
        ).strip(),
        evidence_json=evidence_json,
    )


def render_remediation_prompts(
    scan: ScanResult,
    attack_surfaces: list[AttackSurface],
    findings: list[Finding],
    attack_paths: list[AttackPath],
) -> RenderedReviewPrompt:
    """Render the remediation prompts (#106): concrete, review-first fixes per
    finding, grounded in evidence IDs / cited file:line."""
    evidence_payload = _evidence_pack(scan, attack_surfaces, findings, attack_paths)
    evidence_json = json.dumps(evidence_payload, indent=2, sort_keys=True)
    return RenderedReviewPrompt(
        system=REMEDIATION_SYSTEM_PROMPT.strip(),
        user=REMEDIATION_USER_PROMPT.format(
            repo_context=_repo_context(scan), evidence_json=evidence_json
        ).strip(),
        evidence_json=evidence_json,
    )
