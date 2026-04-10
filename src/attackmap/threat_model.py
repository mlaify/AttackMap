from __future__ import annotations

from .analyzer import identify_attack_surfaces
from .models import AttackPath, AttackSurface, Finding, ScanResult


def _surface_label(surface: AttackSurface) -> str:
    return f"{surface.method} {surface.route} in {surface.file}"


def _severity_rank(value: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(value, 3)


def _action_step(label: str, action: str) -> str:
    return f"{label}: {action}"


def _finding_evidence(surface: AttackSurface) -> str:
    details: list[str] = [_surface_label(surface)]
    if surface.auth_signals:
        details.append(f"auth signals: {', '.join(surface.auth_signals)}")
    else:
        details.append("no auth signals observed")
    if surface.data_store_interaction:
        details.append("data store reachable")
    if surface.outbound_integration:
        details.append("external integration reachable")
    return "; ".join(details)


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
                title="Public webhook endpoint may trust attacker-controlled events",
                severity="high",
                evidence=[_finding_evidence(surface) for surface in webhook_surfaces[:10]],
                mitigation="Require signature verification before processing webhook payloads, reject replays, and keep any downstream state change behind strict validation.",
                confidence="high",
            )
        )

    if admin_surfaces:
        findings.append(
            Finding(
                title="Administrative routes appear reachable from the main application surface",
                severity="high",
                evidence=[_finding_evidence(surface) for surface in admin_surfaces[:10]],
                mitigation="Require strong authentication and explicit server-side authorization on every admin action, and move admin routes behind a narrower exposure boundary where possible.",
                confidence="high",
            )
        )

    if upload_surfaces:
        findings.append(
            Finding(
                title="Upload or import routes expand attacker-controlled input handling",
                severity="high",
                evidence=[_finding_evidence(surface) for surface in upload_surfaces[:10]],
                mitigation="Constrain accepted formats, isolate parsers, scan uploaded content, and treat imported files as untrusted all the way through storage and processing.",
                confidence="medium",
            )
        )

    if auth_surfaces and not any(surface.auth_signals for surface in auth_surfaces):
        findings.append(
            Finding(
                title="Authentication routes were detected without strong nearby auth controls",
                severity="medium",
                evidence=[_finding_evidence(surface) for surface in auth_surfaces[:10]],
                mitigation="Review these routes for rate limiting, credential validation, token or session handling, and the exact point where trust is established server-side.",
                confidence="medium",
            )
        )

    if public_integration_surfaces and not any(h.hint in {"jwt", "oauth", "bearer", "token"} for h in scan.auth_hints):
        findings.append(
            Finding(
                title="Public routes appear to influence outbound integrations without clear auth signals",
                severity="medium",
                evidence=[_finding_evidence(surface) for surface in public_integration_surfaces[:10]],
                mitigation="Check how outbound requests are authenticated, signed, and authorized, and confirm that untrusted route input cannot directly steer third-party actions.",
                confidence="medium",
            )
        )

    if scan.secret_hints:
        findings.append(
            Finding(
                title="Secret-bearing environment variables are referenced in executable paths",
                severity="medium",
                evidence=[f"{hint.name} in {hint.file}" for hint in scan.secret_hints[:10]],
                mitigation="Confirm these secrets are injected securely, never logged or returned, rotated regularly, and scoped only to the privileges each route actually needs.",
                confidence="high",
            )
        )

    if public_data_surfaces:
        findings.append(
            Finding(
                title="Public routes likely sit close to sensitive data operations",
                severity="medium",
                evidence=[_finding_evidence(surface) for surface in public_data_surfaces[:10]],
                mitigation="Validate untrusted input before it reaches business logic, enforce authorization at the route boundary, and verify that downstream queries or writes stay parameterized.",
                confidence="medium",
            )
        )

    if not findings:
        findings.append(
            Finding(
                title="Heuristic scan found only a limited attack surface",
                severity="low",
                evidence=["No major route, secret, or integration patterns triggered a stronger finding."],
                mitigation="Treat this as a weak signal, expand parser coverage, and manually validate the real entry points and trust boundaries.",
                confidence="low",
            )
        )

    return sorted(findings, key=lambda finding: (_severity_rank(finding.severity), finding.title))


def generate_attack_paths(scan: ScanResult) -> list[AttackPath]:
    surfaces = identify_attack_surfaces(scan)
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

    if webhook_surface and (public_data_surface or integration_surface):
        strongest_surface = webhook_surface
        impact = "Unauthorized state changes can be triggered from the internet and then propagated into internal data or downstream systems."
        steps = [
            _action_step("Entry", f"An attacker reaches {strongest_surface.method} {strongest_surface.route} in {strongest_surface.file}, a webhook-style endpoint that accepts untrusted inbound events"),
            _action_step("Weak point", "The endpoint is treated like a trusted integration boundary before its input is fully verified"),
        ]
        if public_data_surface:
            steps.append(_action_step("Propagation", "Attacker-controlled input is processed close to a data store, making unauthorized writes or state changes plausible"))
        if integration_surface:
            steps.append(_action_step("Propagation", "The same request path can also influence outbound service calls, which widens the blast radius beyond the application itself"))
        steps.append(_action_step("Impact", "The attacker drives business actions that should only occur after a trusted event or validated request"))
        return [
            AttackPath(
                name="External event spoofing into internal state change",
                steps=steps,
                impact=impact,
            )
        ]

    if admin_surface:
        return [
            AttackPath(
                name="Administrative route abuse",
                steps=[
                    _action_step("Entry", f"An attacker reaches {admin_surface.method} {admin_surface.route} in {admin_surface.file}, a route associated with privileged behavior"),
                    _action_step("Weak point", "Authentication or authorization around that route is bypassed, reused, or enforced too late"),
                    _action_step("Propagation", "Administrative actions execute with attacker influence and affect higher-value parts of the system"),
                    _action_step("Impact", "Privileged changes, sensitive data access, or configuration abuse follow from a single foothold"),
                ],
                impact="Privilege escalation or destructive administrative actions from a route that should be tightly controlled.",
            )
        ]

    if auth_surface:
        return [
            AttackPath(
                name="Authentication boundary bypass",
                steps=[
                    _action_step("Entry", f"An attacker targets {auth_surface.method} {auth_surface.route} in {auth_surface.file}, which controls login, tokens, or session state"),
                    _action_step("Weak point", "Credential handling, token validation, or session establishment is weaker than the route implies"),
                    _action_step("Propagation", "The attacker converts that weakness into an authenticated foothold"),
                    _action_step("Impact", "The foothold becomes the starting point for deeper movement into protected application behavior"),
                ],
                impact="Account takeover or a trusted session that opens access to additional internal actions.",
            )
        ]

    if upload_surface:
        return [
            AttackPath(
                name="Untrusted file handling abuse",
                steps=[
                    _action_step("Entry", f"An attacker submits content to {upload_surface.method} {upload_surface.route} in {upload_surface.file}"),
                    _action_step("Weak point", "The application accepts or parses attacker-controlled files too broadly"),
                    _action_step("Propagation", "Storage, parsing, or downstream consumers treat that content as safer than it is"),
                    _action_step("Impact", "The result is execution, persistence of malicious content, or operational disruption"),
                ],
                impact="Stored malicious content, parser abuse, or denial of service from untrusted file input.",
            )
        ]

    if public_data_surface:
        return [
            AttackPath(
                name="Public input into sensitive data path",
                steps=[
                    _action_step("Entry", f"An attacker uses {public_data_surface.method} {public_data_surface.route} in {public_data_surface.file} as a public foothold"),
                    _action_step("Weak point", "Input validation or authorization is weaker than the route exposure suggests"),
                    _action_step("Propagation", "Attacker-controlled data reaches code operating close to the data store"),
                    _action_step("Impact", "Confidentiality, integrity, or authorization guarantees around application data are weakened"),
                ],
                impact="Unauthorized data access or modification through a public-facing application route.",
            )
        ]

    if integration_surface:
        return [
            AttackPath(
                name="Outbound trust boundary abuse",
                steps=[
                    _action_step("Entry", f"An attacker influences {integration_surface.method} {integration_surface.route} in {integration_surface.file}, which sits near an outbound integration"),
                    _action_step("Weak point", "The application assumes too much trust in external calls or responses"),
                    _action_step("Propagation", "Spoofed, replayed, or attacker-steered third-party interactions affect internal logic"),
                    _action_step("Impact", "Unsafe business decisions or downstream actions follow from a weak external trust boundary"),
                ],
                impact="Poisoned state or unsafe downstream actions caused by over-trusting an external dependency.",
            )
        ]

    return []
