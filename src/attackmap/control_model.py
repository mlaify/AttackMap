from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Asset, AttackSurface, Control, ControlKind, ControlStrength, ScanResult


@dataclass(frozen=True)
class _ControlPattern:
    kind: ControlKind
    name: str
    strength: ControlStrength
    pattern: re.Pattern[str]
    notes: str | None = None


_CONTROL_PATTERNS: tuple[_ControlPattern, ...] = (
    _ControlPattern(
        kind="authentication",
        name="Password hashing (bcrypt/argon2/scrypt)",
        strength="strong",
        pattern=re.compile(r"\b(bcrypt|argon2|scrypt|pbkdf2)\b", re.IGNORECASE),
        notes="Strong adaptive hash function observed.",
    ),
    _ControlPattern(
        kind="authentication",
        name="JWT verification",
        strength="moderate",
        pattern=re.compile(r"jwt[._-]?(verify|decode|sign)|jsonwebtoken", re.IGNORECASE),
        notes="JWT signature verification implies token-based auth.",
    ),
    _ControlPattern(
        kind="authentication",
        name="Auth middleware / guards",
        strength="moderate",
        pattern=re.compile(
            r"\b(passport|require[_-]?auth|requireauth|@login_required|@auth\.login_required|authenticate_user|ensureauthenticated|@auth_required|isauthenticated)\b",
            re.IGNORECASE,
        ),
    ),
    _ControlPattern(
        kind="mfa",
        name="Multi-factor authentication",
        strength="strong",
        pattern=re.compile(r"\b(mfa|totp|2fa|webauthn|fido2|otp)\b", re.IGNORECASE),
    ),
    _ControlPattern(
        kind="authorization",
        name="Role / permission checks",
        strength="moderate",
        pattern=re.compile(
            r"\b(haspermission|require_role|requireroles?|@permission_required|@requires_role|hasrole|abilities|policy_check|authorize\()\b",
            re.IGNORECASE,
        ),
    ),
    _ControlPattern(
        kind="rbac",
        name="Role-based access control",
        strength="moderate",
        pattern=re.compile(r"\b(rbac|role_based|access_control_list|acl_check)\b", re.IGNORECASE),
    ),
    _ControlPattern(
        kind="input_validation",
        name="Schema validation library",
        strength="moderate",
        pattern=re.compile(
            r"\b(zod|joi|yup|ajv|pydantic|marshmallow|cerberus|validator\.is|class-validator)\b",
            re.IGNORECASE,
        ),
    ),
    _ControlPattern(
        kind="rate_limiting",
        name="Rate limiting middleware",
        strength="moderate",
        pattern=re.compile(
            r"\b(rate[_-]?limit|express-rate-limit|slowapi|throttle|bottleneck|rack-attack)\b",
            re.IGNORECASE,
        ),
    ),
    _ControlPattern(
        kind="csrf_protection",
        name="CSRF protection",
        strength="moderate",
        pattern=re.compile(
            r"\b(csurf|csrf[_-]?token|csrf_protect|csrfprotect|samesite=(strict|lax))\b",
            re.IGNORECASE,
        ),
    ),
    _ControlPattern(
        kind="encryption_in_transit",
        name="TLS / HTTPS / mTLS",
        strength="moderate",
        pattern=re.compile(r"\b(https://|tls|mtls|sslcontext|ssl_ctx|forcessl|hsts)\b", re.IGNORECASE),
    ),
    _ControlPattern(
        kind="encryption_at_rest",
        name="At-rest encryption / KMS",
        strength="moderate",
        pattern=re.compile(r"\b(kms|envelope_encrypt|aes-256|fernet|libsodium|sealedbox)\b", re.IGNORECASE),
    ),
    _ControlPattern(
        kind="audit_logging",
        name="Audit / security logging",
        strength="moderate",
        pattern=re.compile(
            r"\b(audit_log|security_event|log_security|audit\.log|securityaudit|logaudit)\b",
            re.IGNORECASE,
        ),
    ),
    _ControlPattern(
        kind="security_headers",
        name="Security headers (helmet/secure)",
        strength="moderate",
        pattern=re.compile(r"\b(helmet|secure-headers|csp|content_security_policy|x-frame-options)\b", re.IGNORECASE),
    ),
    _ControlPattern(
        kind="output_encoding",
        name="Output encoding / sanitization",
        strength="moderate",
        pattern=re.compile(r"\b(escape_html|sanitize-html|dompurify|bleach\.clean|markupsafe)\b", re.IGNORECASE),
    ),
    _ControlPattern(
        kind="secret_management",
        name="Vault / secret manager",
        strength="strong",
        pattern=re.compile(r"\b(hashicorp[_-]?vault|aws_secretsmanager|gcp_secretmanager|azure_keyvault|doppler)\b", re.IGNORECASE),
    ),
)


_SCOPE_HINTS: dict[ControlKind, str] = {
    "authentication": "Routes that read or modify user-scoped data should sit behind this.",
    "authorization": "Privileged or tenant-bounded routes should enforce this.",
    "input_validation": "All untrusted input boundaries should validate request shape.",
    "rate_limiting": "Auth endpoints and write-heavy endpoints should be throttled.",
    "csrf_protection": "Browser-driven state-changing endpoints should require CSRF tokens.",
    "audit_logging": "Critical-asset access and admin actions should be audit-logged.",
    "encryption_in_transit": "All public surfaces should require TLS.",
    "encryption_at_rest": "Sensitive-asset stores should be encrypted.",
    "secret_management": "Long-lived credentials should be sourced from a vault.",
    "mfa": "Privileged flows should require a second factor.",
}


def _scope_for(asset_kind: str) -> str:
    if asset_kind in {"credentials", "session"}:
        return "asset"
    return "global"


def _all_signal_text(scan: ScanResult) -> list[tuple[str, str, int | None]]:
    """Return (text_blob, file, line) tuples from all hint sources for pattern matching."""
    blobs: list[tuple[str, str, int | None]] = []
    for hint in scan.auth_hints:
        blobs.append((hint.hint, hint.file, hint.line))
    for hint in scan.framework_hints:
        blobs.append((hint.hint, hint.file, hint.line))
    for hint in scan.service_hints:
        blobs.append((hint.hint, hint.file, hint.line))
    for hint in scan.protocol_hints:
        blobs.append((hint.hint, hint.file, hint.line))
    for hint in scan.entrypoint_hints:
        blobs.append((hint.hint, hint.file, hint.line))
    for hint in scan.edge_hints:
        blobs.append((hint.hint, hint.file, hint.line))
    for route in scan.routes:
        blobs.append((route.path, route.file, route.line))
    return blobs


def _format_loc(file_path: str, line: int | None) -> str:
    return f"{file_path}:{line}" if line is not None else file_path


def _detect_present_controls(scan: ScanResult) -> list[Control]:
    blobs = _all_signal_text(scan)
    controls_by_id: dict[str, Control] = {}
    placements_by_id: dict[str, set[str]] = {}
    evidence_by_id: dict[str, set[str]] = {}

    for cp in _CONTROL_PATTERNS:
        for text, file_path, line in blobs:
            if cp.pattern.search(text):
                control_id = f"control:{cp.kind}:{cp.name.lower().replace(' ', '_').replace('/', '_')}"
                placements_by_id.setdefault(control_id, set()).add(file_path)
                evidence_by_id.setdefault(control_id, set()).add(f"{text} ({_format_loc(file_path, line)})")
                if control_id not in controls_by_id:
                    controls_by_id[control_id] = Control(
                        id=control_id,
                        kind=cp.kind,
                        name=cp.name,
                        strength=cp.strength,
                        scope="global",
                        placements=[],
                        evidence=[],
                        notes=cp.notes,
                    )

    finalized: list[Control] = []
    for control_id, control in controls_by_id.items():
        placements = sorted(placements_by_id.get(control_id, set()))
        evidence = sorted(evidence_by_id.get(control_id, set()))[:8]
        scope = "global" if len(placements) >= 3 else ("module" if len(placements) > 1 else "route")
        finalized.append(control.model_copy(update={"placements": placements[:12], "evidence": evidence, "scope": scope}))
    finalized.sort(key=lambda c: (c.kind, c.name))
    return finalized


def _detect_absent_controls(
    scan: ScanResult,
    attack_surfaces: list[AttackSurface],
    assets: list[Asset],
    present_kinds: set[ControlKind],
) -> list[Control]:
    """Surface controls that are *expected* but not detected anywhere."""
    absences: list[Control] = []

    has_public_routes = any(s.exposure == "public" for s in attack_surfaces)
    has_admin_or_auth = any(s.category in {"admin", "auth"} for s in attack_surfaces)
    has_state_changing_public = any(
        s.exposure == "public" and s.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}
        for s in attack_surfaces
    )
    sensitive_kinds = {"credentials", "session", "user_pii", "payment"}
    has_sensitive_assets = any(asset.criticality in {"critical", "high"} for asset in assets) or any(
        asset.kind in sensitive_kinds for asset in assets
    )

    expected: list[tuple[ControlKind, str, str]] = []
    if has_public_routes and "rate_limiting" not in present_kinds:
        expected.append(("rate_limiting", "Rate limiting", "Public routes observed without any rate-limiting markers."))
    if has_admin_or_auth and "authentication" not in present_kinds:
        expected.append(("authentication", "Authentication enforcement", "Admin or auth routes observed without any auth-middleware markers."))
    if has_state_changing_public and "csrf_protection" not in present_kinds:
        expected.append(("csrf_protection", "CSRF protection", "Public state-changing routes observed without CSRF markers."))
    if has_sensitive_assets and "audit_logging" not in present_kinds:
        expected.append(("audit_logging", "Audit logging", "Sensitive assets identified but no audit-logging markers found."))
    if has_sensitive_assets and "encryption_at_rest" not in present_kinds:
        expected.append(("encryption_at_rest", "Encryption at rest", "Sensitive assets identified but no at-rest encryption markers found."))
    if has_admin_or_auth and "mfa" not in present_kinds:
        expected.append(("mfa", "Multi-factor authentication", "Auth/admin surfaces observed without MFA markers."))

    for kind, name, notes in expected:
        absences.append(
            Control(
                id=f"control:absent:{kind}",
                kind=kind,
                name=name,
                strength="absent",
                scope="global",
                placements=[],
                evidence=[],
                notes=notes,
            )
        )
    return absences


def detect_controls(
    scan: ScanResult,
    attack_surfaces: list[AttackSurface],
    assets: list[Asset],
) -> list[Control]:
    present = _detect_present_controls(scan)
    present_kinds: set[ControlKind] = {c.kind for c in present}
    absent = _detect_absent_controls(scan, attack_surfaces, assets, present_kinds)

    _strength_rank = {"strong": 0, "moderate": 1, "weak": 2, "absent": 3}
    combined = present + absent
    combined.sort(key=lambda c: (_strength_rank.get(c.strength, 9), c.kind, c.name))
    return combined
