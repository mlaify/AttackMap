from __future__ import annotations

from .analyzer import identify_attack_surfaces
from .models import AttackPath, AttackSurface, Finding, ScanResult


def _surface_label(surface: AttackSurface) -> str:
    return f"{surface.method} {surface.route} in {surface.file}"


def _severity_rank(value: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(value, 3)


def _action_step(label: str, action: str) -> str:
    return f"{label}: {action}"


def generate_findings(scan: ScanResult, attack_surfaces: list[AttackSurface] | None = None) -> list[Finding]:
    surfaces = attack_surfaces if attack_surfaces is not None else identify_attack_surfaces(scan)
    findings: list[Finding] = []
    webhook_surfaces = [surface for surface in surfaces if surface.category == "webhook"]
    admin_surfaces = [surface for surface in surfaces if surface.category == "admin"]
    upload_surfaces = [surface for surface in surfaces if surface.category == "upload"]
    auth_surfaces = [surface for surface in surfaces if surface.category == "auth"]
    public_data_surfaces = [
        surface
        for surface in surfaces
        if surface.exposure == "public" and surface.data_store_interaction and surface.category != "health"
    ]
    public_integration_surfaces = [
        surface
        for surface in surfaces
        if surface.exposure == "public" and surface.outbound_integration
    ]

    if webhook_surfaces:
        findings.append(
            Finding(
                title="Webhook endpoints detected",
                severity="high",
                evidence=[_surface_label(surface) for surface in webhook_surfaces],
                mitigation="Verify request signatures, constrain source IPs when possible, and enforce strict payload validation.",
                confidence="high",
            )
        )

    if admin_surfaces:
        findings.append(
            Finding(
                title="Privileged administrative endpoints exposed",
                severity="high",
                evidence=[_surface_label(surface) for surface in admin_surfaces[:10]],
                mitigation="Require strong authentication, enforce authorization server-side, and isolate admin routes from public exposure where possible.",
                confidence="high",
            )
        )

    if upload_surfaces:
        findings.append(
            Finding(
                title="File or import endpoints widen attacker-controlled input",
                severity="high",
                evidence=[_surface_label(surface) for surface in upload_surfaces[:10]],
                mitigation="Constrain file types, scan uploads, isolate parsers, and treat imported content as fully untrusted.",
                confidence="medium",
            )
        )

    if auth_surfaces and not any(surface.auth_signals for surface in auth_surfaces):
        findings.append(
            Finding(
                title="Authentication endpoints detected without nearby auth indicators",
                severity="medium",
                evidence=[_surface_label(surface) for surface in auth_surfaces[:10]],
                mitigation="Review login and session handlers for rate limiting, token handling, and clear server-side authorization checks.",
                confidence="medium",
            )
        )

    if public_integration_surfaces and not any(h.hint in {"jwt", "oauth", "bearer", "token"} for h in scan.auth_hints):
        findings.append(
            Finding(
                title="Outbound integrations without strong auth indicators",
                severity="medium",
                evidence=[_surface_label(surface) for surface in public_integration_surfaces[:10]],
                mitigation="Review authentication, request signing, and least-privilege credentials for outbound service calls.",
                confidence="medium",
            )
        )

    if scan.secret_hints:
        findings.append(
            Finding(
                title="Secret-bearing environment variables referenced in code",
                severity="medium",
                evidence=[f"{hint.name} in {hint.file}" for hint in scan.secret_hints[:10]],
                mitigation="Ensure secrets are injected securely, never logged, rotated regularly, and scoped to minimum required privilege.",
                confidence="high",
            )
        )

    if public_data_surfaces:
        findings.append(
            Finding(
                title="Public routes likely sit on top of sensitive data operations",
                severity="medium",
                evidence=[_surface_label(surface) for surface in public_data_surfaces[:10]],
                mitigation="Validate input consistently, enforce authorization at the service boundary, and parameterize all database operations.",
                confidence="medium",
            )
        )

    if not findings:
        findings.append(
            Finding(
                title="Limited attack surface identified by heuristic scan",
                severity="low",
                evidence=["No major route, secret, or integration patterns triggered a stronger finding."],
                mitigation="Expand parser coverage and manually validate architecture assumptions.",
                confidence="low",
            )
        )

    return sorted(findings, key=lambda finding: (_severity_rank(finding.severity), finding.title))


def generate_attack_paths(scan: ScanResult) -> list[AttackPath]:
    surfaces = identify_attack_surfaces(scan)
    paths: list[AttackPath] = []
    webhook_surface = next((surface for surface in surfaces if surface.category == "webhook"), None)
    admin_surface = next((surface for surface in surfaces if surface.category == "admin"), None)
    auth_surface = next((surface for surface in surfaces if surface.category == "auth"), None)
    upload_surface = next((surface for surface in surfaces if surface.category == "upload"), None)
    public_data_surface = next(
        (surface for surface in surfaces if surface.exposure == "public" and surface.data_store_interaction and surface.category != "health"),
        None,
    )
    integration_surface = next(
        (surface for surface in surfaces if surface.exposure == "public" and surface.outbound_integration),
        None,
    )

    if webhook_surface:
        paths.append(
            AttackPath(
                name="Webhook abuse to backend action",
                steps=[
                    _action_step("Entry", f"{webhook_surface.method} {webhook_surface.route} in {webhook_surface.file} is reachable from an untrusted caller"),
                    _action_step("Abuse", "An attacker sends forged or replayed webhook payloads"),
                    _action_step("Boundary crossed", "The application accepts untrusted event data as if it came from a trusted provider"),
                    _action_step("Result", "Downstream state changes or data modifications occur"),
                ],
                impact="Unauthorized actions, fraud, or inconsistent data state.",
            )
        )

    if admin_surface:
        paths.append(
            AttackPath(
                name="Admin function abuse",
                steps=[
                    _action_step("Entry", f"{admin_surface.method} {admin_surface.route} in {admin_surface.file} exposes privileged behavior"),
                    _action_step("Abuse", "An attacker bypasses, weakens, or reuses administrative access controls"),
                    _action_step("Boundary crossed", "Administrative operations execute with attacker influence"),
                ],
                impact="Privilege escalation, destructive configuration changes, or sensitive data access.",
            )
        )

    if auth_surface:
        paths.append(
            AttackPath(
                name="Authentication boundary attack",
                steps=[
                    _action_step("Entry", f"{auth_surface.method} {auth_surface.route} in {auth_surface.file} governs identity or session state"),
                    _action_step("Abuse", "Credentials, tokens, or sessions are brute-forced, replayed, or mishandled"),
                    _action_step("Boundary crossed", "The attacker gains an authenticated foothold"),
                    _action_step("Next move", "That foothold is used to reach higher-value internal actions"),
                ],
                impact="Account takeover or a stepping stone into higher-value internal actions.",
            )
        )

    if upload_surface:
        paths.append(
            AttackPath(
                name="Untrusted file processing abuse",
                steps=[
                    _action_step("Entry", f"{upload_surface.method} {upload_surface.route} in {upload_surface.file} accepts attacker-supplied content"),
                    _action_step("Abuse", "The attacker submits crafted files or import payloads"),
                    _action_step("Boundary crossed", "Parsers, storage layers, or downstream consumers trust the content too broadly"),
                    _action_step("Result", "Malicious content is executed, persisted, or used to deny service"),
                ],
                impact="Remote code execution, stored malicious content, or parser-driven denial of service.",
            )
        )

    if public_data_surface:
        paths.append(
            AttackPath(
                name="Input-to-database abuse",
                steps=[
                    _action_step("Entry", f"{public_data_surface.method} {public_data_surface.route} in {public_data_surface.file} accepts attacker-controlled input"),
                    _action_step("Abuse", "That input flows into business logic without enough validation or authorization"),
                    _action_step("Boundary crossed", "The data layer receives malformed or malicious payloads"),
                    _action_step("Result", "Application confidentiality, integrity, or authorization guarantees are weakened"),
                ],
                impact="Data exposure, data corruption, or privilege escalation through unsafe backend operations.",
            )
        )

    if integration_surface:
        paths.append(
            AttackPath(
                name="Third-party integration trust abuse",
                steps=[
                    _action_step("Entry", f"{integration_surface.method} {integration_surface.route} in {integration_surface.file} can influence third-party communication"),
                    _action_step("Abuse", "The attacker targets assumptions around external service communication"),
                    _action_step("Boundary crossed", "The application accepts tampered or spoofed external responses"),
                    _action_step("Result", "Internal logic trusts external state too broadly and makes unsafe decisions"),
                ],
                impact="Bad decisions, poisoned data, or chained compromise through an upstream dependency.",
            )
        )

    return paths
