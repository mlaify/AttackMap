from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


class Route(BaseModel):
    path: str
    method: str = "ANY"
    file: str
    line: int | None = None


class ExternalCall(BaseModel):
    target: str
    file: str
    line: int | None = None
    evidence_text: str | None = None


class DatabaseHint(BaseModel):
    kind: str
    file: str
    line: int | None = None
    evidence_text: str | None = None


class AuthHint(BaseModel):
    hint: str
    file: str
    line: int | None = None
    evidence_text: str | None = None
    confidence: float = 0.7


class ServiceHint(BaseModel):
    hint: str
    file: str
    line: int | None = None
    evidence_text: str | None = None
    confidence: float = 0.7


class EdgeHint(BaseModel):
    hint: str
    file: str
    line: int | None = None
    evidence_text: str | None = None
    confidence: float = 0.7


class EntrypointHint(BaseModel):
    hint: str
    file: str
    line: int | None = None
    evidence_text: str | None = None
    confidence: float = 0.7


class ProtocolHint(BaseModel):
    hint: str
    file: str
    line: int | None = None
    evidence_text: str | None = None
    confidence: float = 0.7


class FrameworkHint(BaseModel):
    hint: str
    file: str
    line: int | None = None
    evidence_text: str | None = None
    confidence: float = 0.7


class SecretHint(BaseModel):
    name: str
    file: str
    line: int | None = None
    evidence_text: str | None = None
    confidence: float = 0.85


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


class Finding(BaseModel):
    title: str
    severity: Literal["low", "medium", "high"]
    evidence: list[str] = Field(default_factory=list)
    mitigation: str
    confidence: Literal["low", "medium", "high"] = "medium"
    attack_techniques: list[AttackTechnique] = Field(default_factory=list)


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
        return signals
