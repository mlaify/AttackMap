from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


# Provenance field. Present on every analyzer-emitted signal so downstream
# consumers can trace a signal back to the analyzer that produced it.
# Excluded from serialization by default (see #14) so JSON/CLI reports are
# byte-for-byte unchanged; access it via Python attribute for debugging,
# confidence scoring, or future finder logic.
_PROVENANCE_FIELD = Field(default=None, exclude=True, repr=False)


class Route(BaseModel):
    path: str
    method: str = "ANY"
    file: str
    line: int | None = None
    source_analyzer: str | None = _PROVENANCE_FIELD


class ExternalCall(BaseModel):
    target: str
    file: str
    line: int | None = None
    evidence_text: str | None = None
    source_analyzer: str | None = _PROVENANCE_FIELD


class DatabaseHint(BaseModel):
    kind: str
    file: str
    line: int | None = None
    evidence_text: str | None = None
    source_analyzer: str | None = _PROVENANCE_FIELD


class AuthHint(BaseModel):
    hint: str
    file: str
    line: int | None = None
    evidence_text: str | None = None
    confidence: float = 0.7
    source_analyzer: str | None = _PROVENANCE_FIELD


class ServiceHint(BaseModel):
    hint: str
    file: str
    line: int | None = None
    evidence_text: str | None = None
    confidence: float = 0.7
    source_analyzer: str | None = _PROVENANCE_FIELD


class EdgeHint(BaseModel):
    hint: str
    file: str
    line: int | None = None
    evidence_text: str | None = None
    confidence: float = 0.7
    source_analyzer: str | None = _PROVENANCE_FIELD


class EntrypointHint(BaseModel):
    hint: str
    file: str
    line: int | None = None
    evidence_text: str | None = None
    confidence: float = 0.7
    source_analyzer: str | None = _PROVENANCE_FIELD


class ProtocolHint(BaseModel):
    hint: str
    file: str
    line: int | None = None
    evidence_text: str | None = None
    confidence: float = 0.7
    source_analyzer: str | None = _PROVENANCE_FIELD


class FrameworkHint(BaseModel):
    hint: str
    file: str
    line: int | None = None
    evidence_text: str | None = None
    confidence: float = 0.7
    source_analyzer: str | None = _PROVENANCE_FIELD


class SecretHint(BaseModel):
    name: str
    file: str
    line: int | None = None
    evidence_text: str | None = None
    confidence: float = 0.85
    source_analyzer: str | None = _PROVENANCE_FIELD
    # Optional classification. `env_reference` means we spotted a call
    # like `os.getenv("API_KEY")` — the value is at runtime. Anything
    # else identifies a literal secret pasted directly into code or
    # config (#39). Consumers can elevate hardcoded-literal findings
    # since exposure is broader than env references.
    kind: str = "env_reference"


class DependencyHint(BaseModel):
    """A single third-party dependency declared in a manifest (#48).

    Emitted by the SBOM analyzer. Slice 1 covers direct dependencies
    only (no lockfile parsing) — the ``version`` field carries whatever
    the manifest wrote verbatim (``^4.16.0``, ``>=2,<3``, ``latest``,
    etc.); consumers that need a resolved version look at lockfiles.
    """

    name: str
    version: str
    ecosystem: Literal["pypi", "npm", "go", "cargo", "composer"]
    file: str
    line: int | None = None
    # dev / build-only dependency (``devDependencies``, ``require-dev``,
    # PEP-621 ``optional-dependencies[dev]``). Runtime consumers weight
    # these differently: a dev-time RCE still matters, but a dev-only
    # dep isn't part of the shipped attack surface.
    dev: bool = False
    evidence_text: str | None = None
    source_analyzer: str | None = _PROVENANCE_FIELD


class CodeWeakness(BaseModel):
    """A novel vulnerability-class weakness in source (#77).

    Emitted by the built-in `weaknesses` finder — bug classes beyond the
    taint/crypto/web-hardening families, detected from concrete risky
    constructs (not absence).
    """

    kind: Literal[
        "prototype_pollution",
        "mass_assignment",
        "jwt_weakness",
        "xxe",
        "redos",
        "insecure_upload",
        "graphql_exposure",
    ]
    file: str
    line: int | None = None
    evidence_text: str | None = None
    severity: Literal["low", "medium", "high"] = "medium"
    source_analyzer: str | None = _PROVENANCE_FIELD


class Anomaly(BaseModel):
    """A within-repo consistency outlier — the odd-one-out in a peer group (#78).

    Emitted by the `anomalies` analyzer. Rather than matching a known-bad
    signature, it flags a route that deviates from the norm its siblings
    establish: peers in the same resource cohort carry an auth/validation
    signal (or are read-only) and this one doesn't. The bigger and more
    consistent the peer group, the more likely the deviation is a mistake —
    so `confidence` scales with `consistent_peers`.
    """

    kind: Literal["auth_outlier", "validation_outlier", "method_outlier"]
    route_path: str
    route_method: str
    route_file: str
    route_line: int | None = None
    peer_group: str  # the shared path-prefix cohort key (e.g. "api/users")
    peer_group_size: int  # total sibling routes in the cohort
    consistent_peers: int  # siblings that exhibit the norm this route breaks
    deviation: str  # human-readable description of what is odd
    peer_examples: list[str] = Field(default_factory=list)  # sample "METHOD path" peers
    severity: Literal["low", "medium", "high"] = "medium"
    confidence: float = 0.5
    source_analyzer: str | None = _PROVENANCE_FIELD


class WebHardeningIssue(BaseModel):
    """A web-hardening misconfiguration (#71).

    Emitted by the built-in web-hardening finder. Detects
    positively-present misconfigurations (wildcard CORS with credentials,
    explicit CSRF disable, insecure cookie flags, unsafe-inline/eval CSP,
    debug enabled) rather than hard-to-judge absences.
    """

    kind: Literal[
        "cors_wildcard_credentials",
        "csrf_disabled",
        "insecure_cookie",
        "weak_csp",
        "debug_enabled",
    ]
    file: str
    line: int | None = None
    evidence_text: str | None = None
    severity: Literal["low", "medium", "high"] = "medium"
    source_analyzer: str | None = _PROVENANCE_FIELD


class WorkflowIssue(BaseModel):
    """A CI-workflow security issue in a GitHub Actions file (#142).

    Emitted by the built-in workflow scanner over ``.github/workflows/*.yml``.
    Every issue is a positively-present misconfiguration (an unpinned action,
    an untrusted-code checkout under ``pull_request_target``, a secret or an
    attacker-controlled context interpolated into a shell step, ``write-all``
    permissions, a self-hosted runner on a PR trigger) — a hardened workflow
    produces nothing.
    """

    kind: Literal[
        "unpinned_action",
        "pr_target_checkout",
        "secret_in_run",
        "script_injection",
        "broad_permissions",
        "self_hosted_pr",
    ]
    file: str
    line: int | None = None
    # Human-readable location within the workflow (job / step) so evidence
    # points somewhere actionable even when a precise line isn't available.
    context: str | None = None
    evidence_text: str | None = None
    severity: Literal["low", "medium", "high"] = "medium"
    source_analyzer: str | None = _PROVENANCE_FIELD


class CryptoWeakness(BaseModel):
    """An insecure-cryptography or weak-randomness usage (#70).

    Emitted by the built-in crypto finder. Heuristic and regex-based;
    the noisy families (weak hash, insecure RNG) are gated on a
    security-context identifier to keep precision high.
    """

    kind: Literal[
        "weak_password_hash",
        "weak_cipher",
        "ecb_mode",
        "static_iv_salt",
        "insecure_random",
        "insecure_tls",
    ]
    file: str
    line: int | None = None
    evidence_text: str | None = None
    severity: Literal["low", "medium", "high"] = "medium"
    source_analyzer: str | None = _PROVENANCE_FIELD


class BolaCandidate(BaseModel):
    """A route that may be missing object-level authorization (#69).

    Emitted by the authz analyzer when a route takes a resource
    identifier and reaches a datastore, but no ownership/authorization
    check is visible near the handler. Heuristic — the ownership-marker
    scan is the main false-positive reducer; confidence stays honest.
    """

    route_path: str
    route_method: str
    route_file: str
    route_line: int | None = None
    id_param: str  # the resource-id parameter detected in the route
    reaches_db: bool = False
    db_evidence: str = ""  # how DB reachability was established
    has_ownership_check: bool = False  # True → suppressed (not a candidate)
    source_analyzer: str | None = _PROVENANCE_FIELD


class TaintChain(BaseModel):
    """Cross-file data-flow evidence: a route reaches a sink via imports.

    Emitted by the lite taint analyzer (see #45). Each entry names the
    starting route, the sink kind and location, and the chain of files
    the import-walk traversed. Confidence encodes that import-edge is a
    heuristic proxy for call-edge — real dispatch may not hit the sink.
    """

    route_path: str
    route_method: str
    route_file: str
    sink_kind: Literal[
        "sql_execute",
        "subprocess_shell",
        "eval",
        "exec",
        "dynamic_open",
        "unsafe_deserialization",
        "ssti",
        "ssrf",
        "nosql_injection",
        "open_redirect",
    ]
    sink_file: str
    sink_line: int | None = None
    # Number of import edges walked. 0 = same file, 1 = direct import,
    # 2 = transitive (imported module imports the sink module).
    hops: int
    # Chain of files walked, ordered [route_file, ..., sink_file].
    files: list[str] = Field(default_factory=list)
    evidence_text: str | None = None
    confidence: float = 0.6
    source_analyzer: str | None = _PROVENANCE_FIELD


class Vulnerability(BaseModel):
    """A known CVE / advisory affecting a resolved dependency (#60).

    One entry per (dep × advisory). ``package_version`` is the concrete
    lower-bound the CVE lookup resolved from the manifest spec — it may
    differ from the DependencyHint's raw ``version`` string.
    """

    id: str  # OSV entry id — CVE-2023-1234, GHSA-xxxx-xxxx, etc.
    aliases: list[str] = Field(default_factory=list)
    summary: str = ""
    severity: Literal["low", "medium", "high"] = "medium"
    cvss_score: float | None = None
    references: list[str] = Field(default_factory=list)
    affected_range: str = ""  # human-readable "affected [lower, upper)" text
    package_name: str
    package_version: str
    ecosystem: Literal["pypi", "npm", "go", "cargo", "composer"]
    source_analyzer: str | None = _PROVENANCE_FIELD


SignalKind = Literal[
    "route",
    "external_call",
    "database",
    "auth",
    "service",
    "edge",
    "entrypoint",
    "protocol",
    "framework",
    "secret",
    "taint",
    "dependency",
]


class Signal(BaseModel):
    """Unified view of a single static-analysis signal.

    Synthesized from the typed hint lists on `ScanResult` via `all_signals()`.
    Existing analyzer plugins keep populating the typed hint lists; downstream
    consumers (insights, controls, asset detection, prompts) can iterate over
    the unified Signal stream to reason uniformly about location, confidence,
    and evidence.
    """

    kind: SignalKind
    label: str
    file: str
    line: int | None = None
    confidence: float = 0.7
    evidence_text: str | None = None
    properties: dict[str, str] = Field(default_factory=dict)

    def location(self) -> str:
        """Stable `file:line` reference if line known, else just file."""
        return f"{self.file}:{self.line}" if self.line is not None else self.file


class AttackSurface(BaseModel):
    route: str
    method: str
    file: str
    category: Literal["webhook", "admin", "auth", "upload", "internal", "health", "public_api"]
    exposure: Literal["public", "internal", "unknown"] = "public"
    risk: Literal["low", "medium", "high"]
    auth_signals: list[str] = Field(default_factory=list)
    data_store_interaction: bool = False
    outbound_integration: bool = False
    rationale: list[str] = Field(default_factory=list)
    line: int | None = None

    def location(self) -> str:
        return f"{self.file}:{self.line}" if self.line is not None else self.file


class AttackTechnique(BaseModel):
    """Reference to a MITRE ATT&CK technique (Enterprise matrix)."""

    technique_id: str  # e.g., "T1190", "T1078.004"
    name: str  # e.g., "Exploit Public-Facing Application"
    tactic: str  # e.g., "Initial Access"
    url: str | None = None  # https://attack.mitre.org/techniques/T1190/


ExploitabilityTier = Literal["critical", "high", "medium", "low"]


class ExploitabilityFactor(BaseModel):
    """One named, signed contribution to an exploitability score (#79).

    Kept explicit so every score is explainable — the report shows exactly
    which signals raised (or, at 0 points, notably did not raise) the number.
    """

    name: str  # e.g. "public exposure", "no auth at entry", "reaches sql_execute sink"
    points: int
    detail: str = ""  # concrete evidence for this factor


class ExploitabilityScore(BaseModel):
    """A fused 'exploitable now' score for one route→sink combination (#79).

    Deterministic: the same scan always yields the same score, and `factors`
    sums (before the 0–100 clamp) to `raw_score`, so nothing is hidden.
    """

    subject: str  # human label, e.g. "GET /search → sql_execute"
    route: str
    method: str
    sink_kind: str
    location: str  # sink file:line
    score: int  # 0–100 (clamped)
    raw_score: int  # pre-clamp sum of factor points
    tier: ExploitabilityTier
    factors: list[ExploitabilityFactor] = Field(default_factory=list)


class Finding(BaseModel):
    title: str
    severity: Literal["low", "medium", "high"]
    evidence: list[str] = Field(default_factory=list)
    mitigation: str
    confidence: Literal["low", "medium", "high"] = "medium"
    attack_techniques: list[AttackTechnique] = Field(default_factory=list)
    # Optional categorization tags. Vocabulary (see #4): exposed-endpoint,
    # auth-missing, data-risk, secret-exposure, integration-risk,
    # framework-chain, service-chain, atproto-chain, weak-signal. Multiple
    # tags may apply per finding.
    tags: list[str] = Field(default_factory=list)
    # Numeric prioritization score (higher = triage first within the same
    # severity band). Computed from severity + confidence; used as a
    # secondary sort key. `None` means "not scored" for backward compat.
    score: int | None = None
    # Fused 'exploitable now' score (#79), 0–100, with a tier. Set on
    # findings that sit on a route→sink path; `None` when not applicable.
    exploitability: int | None = None
    exploitability_tier: ExploitabilityTier | None = None


class AttackPath(BaseModel):
    name: str
    steps: list[str]
    impact: str


AssetKind = Literal[
    "credentials",
    "session",
    "user_pii",
    "payment",
    "internal_secret",
    "audit_log",
    "business_data",
    "configuration",
]


class Asset(BaseModel):
    id: str
    kind: AssetKind
    name: str
    criticality: Literal["critical", "high", "medium", "low"]
    locations: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


ControlKind = Literal[
    "authentication",
    "authorization",
    "input_validation",
    "output_encoding",
    "rate_limiting",
    "csrf_protection",
    "encryption_at_rest",
    "encryption_in_transit",
    "audit_logging",
    "rbac",
    "mfa",
    "secret_management",
    "security_headers",
]


ControlStrength = Literal["strong", "moderate", "weak", "absent"]


class Control(BaseModel):
    id: str
    kind: ControlKind
    name: str
    strength: ControlStrength
    scope: Literal["global", "module", "route", "service", "asset"]
    placements: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    notes: str | None = None


InsightKind = Literal[
    "shared_secret_blast_radius",
    "sensitive_asset_reachability",
    "control_bypass",
    "defense_gap_in_chain",
    "asymmetric_protection",
    "trust_boundary_violation",
    "audit_gap",
    "control_strength_mismatch",
    "single_point_of_failure",
    "stale_or_contradictory_signal",
    "admin_action_without_auth",
]


class Insight(BaseModel):
    id: str
    kind: InsightKind
    title: str
    narrative: str
    severity: Literal["critical", "high", "medium", "low", "informational"]
    confidence: Literal["high", "medium", "low"]
    evidence: list[str] = Field(default_factory=list)
    related_assets: list[str] = Field(default_factory=list)
    related_controls: list[str] = Field(default_factory=list)
    related_routes: list[str] = Field(default_factory=list)
    suggested_action: str | None = None
    attack_techniques: list[AttackTechnique] = Field(default_factory=list)


class DetectionOpportunity(BaseModel):
    """A defender-facing detection-engineering hint produced from an insight or finding.

    Designed to answer: "given this static-analysis finding, what runtime
    detection signal would catch the same condition in production?"
    """

    id: str
    title: str
    rationale: str
    signal_kind: Literal["log", "metric", "trace", "network", "config_audit"]
    suggested_rule: str  # human-readable rule sketch (Sigma/KQL/Splunk-style)
    related_insight_ids: list[str] = Field(default_factory=list)
    related_finding_titles: list[str] = Field(default_factory=list)
    attack_techniques: list[AttackTechnique] = Field(default_factory=list)


class ScanResult(BaseModel):
    root: str
    languages: list[str] = Field(default_factory=list)
    routes: list[Route] = Field(default_factory=list)
    external_calls: list[ExternalCall] = Field(default_factory=list)
    databases: list[DatabaseHint] = Field(default_factory=list)
    auth_hints: list[AuthHint] = Field(default_factory=list)
    service_hints: list[ServiceHint] = Field(default_factory=list)
    edge_hints: list[EdgeHint] = Field(default_factory=list)
    entrypoint_hints: list[EntrypointHint] = Field(default_factory=list)
    protocol_hints: list[ProtocolHint] = Field(default_factory=list)
    framework_hints: list[FrameworkHint] = Field(default_factory=list)
    secret_hints: list[SecretHint] = Field(default_factory=list)
    taint_chains: list[TaintChain] = Field(default_factory=list)
    dependencies: list[DependencyHint] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    authz_candidates: list[BolaCandidate] = Field(default_factory=list)
    crypto_weaknesses: list[CryptoWeakness] = Field(default_factory=list)
    web_hardening_issues: list[WebHardeningIssue] = Field(default_factory=list)
    code_weaknesses: list[CodeWeakness] = Field(default_factory=list)
    workflow_issues: list[WorkflowIssue] = Field(default_factory=list)
    anomalies: list[Anomaly] = Field(default_factory=list)
    files_scanned: int = 0

    @property
    def root_path(self) -> Path:
        return Path(self.root)

    def all_signals(self) -> list[Signal]:
        """Synthesize the unified Signal stream from typed hint lists.

        Cheap O(n) view — does not mutate `self`. Order: routes, external calls,
        databases, then the hint families (auth, service, edge, entrypoint,
        protocol, framework, secret) in that order.
        """
        signals: list[Signal] = []
        for r in self.routes:
            signals.append(
                Signal(
                    kind="route",
                    label=f"{r.method} {r.path}",
                    file=r.file,
                    line=r.line,
                    properties={"method": r.method, "path": r.path},
                )
            )
        for ext in self.external_calls:
            signals.append(
                Signal(
                    kind="external_call",
                    label=ext.target,
                    file=ext.file,
                    line=ext.line,
                    evidence_text=ext.evidence_text,
                )
            )
        for db in self.databases:
            signals.append(
                Signal(
                    kind="database",
                    label=db.kind,
                    file=db.file,
                    line=db.line,
                    evidence_text=db.evidence_text,
                    properties={"kind": db.kind},
                )
            )
        _hint_kind_pairs: tuple[tuple[SignalKind, list], ...] = (
            ("auth", self.auth_hints),
            ("service", self.service_hints),
            ("edge", self.edge_hints),
            ("entrypoint", self.entrypoint_hints),
            ("protocol", self.protocol_hints),
            ("framework", self.framework_hints),
        )
        for kind, hints in _hint_kind_pairs:
            for h in hints:
                signals.append(
                    Signal(
                        kind=kind,
                        label=h.hint,
                        file=h.file,
                        line=getattr(h, "line", None),
                        evidence_text=getattr(h, "evidence_text", None),
                        confidence=getattr(h, "confidence", 0.7),
                    )
                )
        for s in self.secret_hints:
            signals.append(
                Signal(
                    kind="secret",
                    label=s.name,
                    file=s.file,
                    line=s.line,
                    evidence_text=s.evidence_text,
                    confidence=getattr(s, "confidence", 0.85),
                )
            )
        for tc in self.taint_chains:
            signals.append(
                Signal(
                    kind="taint",
                    label=f"{tc.route_method} {tc.route_path} → {tc.sink_kind}",
                    file=tc.sink_file,
                    line=tc.sink_line,
                    evidence_text=tc.evidence_text,
                    confidence=tc.confidence,
                    properties={
                        "hops": str(tc.hops),
                        "sink_kind": tc.sink_kind,
                        "route_file": tc.route_file,
                    },
                )
            )
        for dep in self.dependencies:
            signals.append(
                Signal(
                    kind="dependency",
                    label=f"{dep.ecosystem}:{dep.name}@{dep.version}",
                    file=dep.file,
                    line=dep.line,
                    evidence_text=dep.evidence_text,
                    confidence=0.9,  # manifest declarations are hard evidence
                    properties={
                        "ecosystem": dep.ecosystem,
                        "name": dep.name,
                        "version": dep.version,
                        "dev": "true" if dep.dev else "false",
                    },
                )
            )
        return signals
