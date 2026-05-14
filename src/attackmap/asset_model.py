from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Asset, AssetKind, ScanResult

LOW_QUALITY_SEGMENTS = ("/tests/", "/__tests__/", "/fixtures/", "/mocks/", "/examples/", "/test_", "/_test.")


def _is_low_quality(path: str) -> bool:
    normalized = ("/" + path.replace("\\", "/").lower() + "/")
    return any(segment in normalized for segment in LOW_QUALITY_SEGMENTS)


@dataclass(frozen=True)
class _AssetRule:
    kind: AssetKind
    name: str
    criticality: str
    secret_patterns: tuple[str, ...] = ()
    route_patterns: tuple[str, ...] = ()
    file_patterns: tuple[str, ...] = ()


_ASSET_RULES: tuple[_AssetRule, ...] = (
    _AssetRule(
        kind="session",
        name="Authentication tokens / session material",
        criticality="critical",
        secret_patterns=("jwt_secret", "session_secret", "cookie_secret", "auth_secret", "refresh_secret", "signing_key"),
        route_patterns=("/login", "/signin", "/token", "/oauth", "/session", "/refresh", "/logout"),
        file_patterns=("auth/", "session/", "/jwt"),
    ),
    _AssetRule(
        kind="credentials",
        name="User credentials at rest",
        criticality="critical",
        secret_patterns=("password_pepper", "hash_secret"),
        route_patterns=("/password", "/signup", "/register", "/reset-password", "/forgot"),
        file_patterns=("models/user", "models/account", "entities/user", "entities/account", "user_repository", "auth/password"),
    ),
    _AssetRule(
        kind="payment",
        name="Payment / billing records",
        criticality="critical",
        secret_patterns=("stripe", "paypal", "braintree", "adyen", "billing_key"),
        route_patterns=("/payment", "/checkout", "/billing", "/invoice", "/subscription", "/charge"),
        file_patterns=("models/payment", "models/invoice", "models/order", "entities/payment", "entities/invoice", "entities/order", "billing/"),
    ),
    _AssetRule(
        kind="user_pii",
        name="User PII / profile data",
        criticality="high",
        route_patterns=("/users", "/user/", "/profile", "/account", "/me", "/contacts", "/address"),
        file_patterns=("models/user", "models/profile", "models/contact", "entities/user", "entities/profile", "user_repository", "user_service"),
    ),
    _AssetRule(
        kind="internal_secret",
        name="Internal service / API secrets",
        criticality="high",
        secret_patterns=(
            "api_key",
            "private_key",
            "webhook_secret",
            "signing_secret",
            "service_token",
            "admin_token",
            "internal_key",
            "encryption_key",
            "master_key",
            "deploy_key",
        ),
        file_patterns=("vault/", "kms/", "/keys/"),
    ),
    _AssetRule(
        kind="audit_log",
        name="Audit / security logs",
        criticality="medium",
        route_patterns=("/audit", "/security/log", "/events"),
        file_patterns=("audit/", "/audit_log", "security/log", "logs/security"),
    ),
    _AssetRule(
        kind="configuration",
        name="Security-relevant configuration",
        criticality="medium",
        secret_patterns=("config_signing", "feature_flag_secret"),
        file_patterns=(".env", "config/secrets", "secrets.yml", "secrets.yaml", "config/security"),
    ),
)


def _normalize(text: str) -> str:
    return text.replace("\\", "/").lower()


def _matches_any(haystack: str, needles: tuple[str, ...]) -> bool:
    return any(needle in haystack for needle in needles)


def _loc(file_path: str, line: int | None) -> str:
    """`file:line` if line is known, else `file`."""
    return f"{file_path}:{line}" if line is not None else file_path


def _route_path_set(scan: ScanResult) -> set[str]:
    return {_normalize(route.path) for route in scan.routes}


def _route_files_for(scan: ScanResult, route_lower: str) -> list[str]:
    return [route.file for route in scan.routes if _normalize(route.path) == route_lower]


def _gather_asset(rule: _AssetRule, scan: ScanResult) -> Asset | None:
    locations: set[str] = set()
    evidence: set[str] = set()

    if rule.secret_patterns:
        for hint in scan.secret_hints:
            if _is_low_quality(hint.file):
                continue
            name_lower = hint.name.lower()
            if _matches_any(name_lower, rule.secret_patterns):
                locations.add(hint.file)
                evidence.add(f"secret:{hint.name} ({_loc(hint.file, hint.line)})")

    if rule.route_patterns:
        for route in scan.routes:
            if _is_low_quality(route.file):
                continue
            path_lower = _normalize(route.path)
            if _matches_any(path_lower, rule.route_patterns):
                locations.add(route.file)
                evidence.add(f"route:{route.method} {route.path} ({_loc(route.file, route.line)})")

    if rule.file_patterns:
        candidate_files: set[str] = set()
        candidate_files.update(route.file for route in scan.routes)
        candidate_files.update(hint.file for hint in scan.secret_hints)
        candidate_files.update(hint.file for hint in scan.framework_hints)
        candidate_files.update(hint.file for hint in scan.service_hints)
        candidate_files.update(hint.file for hint in scan.auth_hints)
        for file_path in candidate_files:
            if _is_low_quality(file_path):
                continue
            file_lower = _normalize(file_path)
            if _matches_any(file_lower, rule.file_patterns):
                locations.add(file_path)
                evidence.add(f"file:{file_path}")

    if not evidence:
        return None

    asset_id = f"asset:{rule.kind}"
    return Asset(
        id=asset_id,
        kind=rule.kind,
        name=rule.name,
        criticality=rule.criticality,  # type: ignore[arg-type]
        locations=sorted(locations),
        evidence=sorted(evidence)[:12],
    )


_SECRET_KIND_HEURISTICS: tuple[tuple[re.Pattern[str], AssetKind, str, str], ...] = (
    (re.compile(r"jwt|session|cookie|refresh|auth_secret"), "session", "Auth/session secret", "critical"),
    (re.compile(r"stripe|paypal|braintree|adyen"), "payment", "Payment processor secret", "critical"),
    (re.compile(r"webhook|signing|hmac"), "internal_secret", "Webhook / signing secret", "high"),
    (re.compile(r"api[_-]?key|service[_-]?token|admin[_-]?token|deploy[_-]?key"), "internal_secret", "API / service token", "high"),
    (re.compile(r"private[_-]?key|encryption[_-]?key|master[_-]?key"), "internal_secret", "Cryptographic key material", "critical"),
)


def _secrets_as_assets(scan: ScanResult) -> list[Asset]:
    assets: list[Asset] = []
    seen_ids: set[str] = set()
    for hint in scan.secret_hints:
        if _is_low_quality(hint.file):
            continue
        name_lower = hint.name.lower()
        for pattern, kind, name, criticality in _SECRET_KIND_HEURISTICS:
            if pattern.search(name_lower):
                asset_id = f"asset:secret:{name_lower}"
                if asset_id in seen_ids:
                    break
                seen_ids.add(asset_id)
                assets.append(
                    Asset(
                        id=asset_id,
                        kind=kind,
                        name=f"{name}: {hint.name}",
                        criticality=criticality,  # type: ignore[arg-type]
                        locations=[hint.file],
                        evidence=[f"secret:{hint.name} ({_loc(hint.file, hint.line)})"],
                    )
                )
                break
    return assets


def _business_data_fallback(scan: ScanResult, assets: list[Asset]) -> Asset | None:
    runtime_dbs = [db for db in scan.databases if not _is_low_quality(db.file)]
    if not runtime_dbs:
        return None
    sensitive_kinds = {"user_pii", "payment", "credentials", "session"}
    if any(asset.kind in sensitive_kinds for asset in assets):
        return None
    files = sorted({db.file for db in runtime_dbs})[:8]
    kinds = sorted({db.kind for db in runtime_dbs})
    return Asset(
        id="asset:business_data",
        kind="business_data",
        name="Business / operational data store",
        criticality="medium",
        locations=files,
        evidence=[f"datastore:{kind}" for kind in kinds],
    )


def detect_assets(scan: ScanResult) -> list[Asset]:
    """Return the inferred asset inventory for a scan, deduplicated by id."""
    assets: list[Asset] = []
    seen_ids: set[str] = set()

    for rule in _ASSET_RULES:
        asset = _gather_asset(rule, scan)
        if asset is None or asset.id in seen_ids:
            continue
        seen_ids.add(asset.id)
        assets.append(asset)

    for asset in _secrets_as_assets(scan):
        if asset.id in seen_ids:
            continue
        seen_ids.add(asset.id)
        assets.append(asset)

    fallback = _business_data_fallback(scan, assets)
    if fallback is not None and fallback.id not in seen_ids:
        seen_ids.add(fallback.id)
        assets.append(fallback)

    _criticality_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    assets.sort(key=lambda asset: (_criticality_rank.get(asset.criticality, 9), asset.kind, asset.id))
    return assets
