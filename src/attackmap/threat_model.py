from __future__ import annotations

from .models import AttackPath, Finding, ScanResult


def generate_findings(scan: ScanResult) -> list[Finding]:
    findings: list[Finding] = []

    if any("/webhook" in route.path.lower() for route in scan.routes):
        findings.append(
            Finding(
                title="Webhook endpoints detected",
                severity="high",
                evidence=[f"{route.method} {route.path} in {route.file}" for route in scan.routes if "/webhook" in route.path.lower()],
                mitigation="Verify request signatures, constrain source IPs when possible, and enforce strict payload validation.",
                confidence="high",
            )
        )

    if scan.external_calls and not any(h.hint in {"jwt", "oauth", "bearer", "token"} for h in scan.auth_hints):
        findings.append(
            Finding(
                title="Outbound integrations without strong auth indicators",
                severity="medium",
                evidence=[f"{call.target} in {call.file}" for call in scan.external_calls[:10]],
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

    if scan.routes and scan.databases:
        findings.append(
            Finding(
                title="Direct route-to-database interaction likely present",
                severity="medium",
                evidence=[f"Routes: {len(scan.routes)}", f"Datastores: {', '.join(sorted({d.kind for d in scan.databases}))}"],
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

    return findings


def generate_attack_paths(scan: ScanResult) -> list[AttackPath]:
    paths: list[AttackPath] = []

    if any("/webhook" in route.path.lower() for route in scan.routes):
        paths.append(
            AttackPath(
                name="Webhook abuse to backend action",
                steps=[
                    "Attacker identifies publicly reachable webhook endpoint",
                    "Attacker submits forged or replayed webhook payload",
                    "Application processes untrusted input",
                    "Downstream state change or data modification occurs",
                ],
                impact="Unauthorized actions, fraud, or inconsistent data state.",
            )
        )

    if scan.routes and scan.databases:
        paths.append(
            AttackPath(
                name="Input-to-database abuse",
                steps=[
                    "Attacker reaches exposed application route",
                    "Untrusted input flows into business logic",
                    "Data layer receives malformed or malicious payload",
                    "Application integrity or confidentiality is affected",
                ],
                impact="Data exposure, data corruption, or privilege escalation through unsafe backend operations.",
            )
        )

    if scan.external_calls:
        paths.append(
            AttackPath(
                name="Third-party integration trust abuse",
                steps=[
                    "Attacker targets assumptions around external service communication",
                    "Application accepts tampered or spoofed responses",
                    "Internal logic trusts external state too broadly",
                ],
                impact="Bad decisions, poisoned data, or chained compromise through an upstream dependency.",
            )
        )

    return paths
