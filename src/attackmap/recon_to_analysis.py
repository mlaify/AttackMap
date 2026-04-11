from __future__ import annotations

from dataclasses import dataclass
import re

from .analyzer import identify_attack_surfaces
from .models import AttackPath, AttackSurface, AuthHint, Finding, ScanResult
from .threat_model import generate_attack_paths, generate_findings


@dataclass(frozen=True)
class AnalysisOutputs:
    attack_surfaces: list[AttackSurface]
    findings: list[Finding]
    attack_paths: list[AttackPath]


NON_AUTH_HINT_PREFIXES: tuple[str, ...] = (
    "service_name:",
    "service_role:",
    "entrypoint:",
    "edge:",
    "handler_type:",
    "handler_visibility:",
    "handler_visibility_basis:",
    "controller:",
    "service:",
    "omeka_",
    "laminas_",
    "atproto_namespace:",
    "atproto_namespace_ref:",
    "atproto_xrpc_ref:",
    "atproto_lexicon:",
    "atproto_event_stream:",
    "atproto_service_note:",
    "atproto_service_edge:",
    "atproto_repo:",
)

AUTH_SIGNAL_PATTERN = re.compile(
    r"(auth|jwt|oauth|token|session|password|bearer|authorization|mfa|passport|login_required)",
    re.IGNORECASE,
)

EXPLICIT_AUTH_HINT_PREFIXES: tuple[str, ...] = ("atproto_auth:",)


def _is_likely_auth_signal(value: str) -> bool:
    lowered = value.lower()
    if lowered.startswith(EXPLICIT_AUTH_HINT_PREFIXES):
        return True
    if lowered.startswith(NON_AUTH_HINT_PREFIXES):
        return False
    return bool(AUTH_SIGNAL_PATTERN.search(lowered))


def _auth_filtered_scan(scan: ScanResult) -> ScanResult:
    """
    Build a conservative auth-focused view of ScanResult.

    Why:
    `auth_hints` is temporarily overloaded with non-auth analyzer metadata
    (service names, edges, protocol notes). For attack-surface and finding
    generation, treat only likely auth signals as auth to avoid overconfidence.
    """
    migrated_non_auth_hints = {
        (hint.hint, hint.file)
        for hint in [
            *scan.service_hints,
            *scan.edge_hints,
            *scan.entrypoint_hints,
            *scan.protocol_hints,
            *scan.framework_hints,
        ]
    }
    filtered_auth_hints = [
        hint
        for hint in scan.auth_hints
        if (hint.hint, hint.file) not in migrated_non_auth_hints and _is_likely_auth_signal(hint.hint)
    ]
    return scan.model_copy(update={"auth_hints": [AuthHint(hint=hint.hint, file=hint.file) for hint in filtered_auth_hints]})


def to_attack_surface(scan: ScanResult) -> list[AttackSurface]:
    """Translate recon signals into classified attack-surface entries."""
    return identify_attack_surfaces(_auth_filtered_scan(scan))


def to_findings(scan: ScanResult, attack_surfaces: list[AttackSurface] | None = None) -> list[Finding]:
    """Translate recon signals (and optional surfaces) into conservative findings."""
    auth_filtered_scan = _auth_filtered_scan(scan)
    if attack_surfaces is not None:
        return generate_findings(auth_filtered_scan, attack_surfaces)
    return generate_findings(auth_filtered_scan)


def to_attack_paths(scan: ScanResult, attack_surfaces: list[AttackSurface] | None = None) -> list[AttackPath]:
    """
    Translate recon signals into plausible, heuristic attack paths.

    Keep full hints for path generation so temporary overloaded hints still
    support chain-linking while migration is in progress.
    """
    return generate_attack_paths(scan, attack_surfaces=attack_surfaces)


def translate_recon(scan: ScanResult) -> AnalysisOutputs:
    """
    Formal translation stage from ScanResult to higher-level analysis artifacts.

    This remains deterministic and explainable by relying only on existing
    signal-driven heuristics from analyzer/threat_model modules.
    """
    attack_surfaces = to_attack_surface(scan)
    findings = to_findings(scan, attack_surfaces)
    attack_paths = to_attack_paths(scan)
    return AnalysisOutputs(
        attack_surfaces=attack_surfaces,
        findings=findings,
        attack_paths=attack_paths,
    )
