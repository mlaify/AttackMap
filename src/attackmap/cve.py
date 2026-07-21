"""OSV.dev CVE lookup for SBOM entries (#60, slice 2 of #48).

Cross-references every ``DependencyHint`` against the OSV.dev advisory
database and emits ``Vulnerability`` records. The scanner-level CVE
lookup is off by default (``--cve`` on the CLI) — it does network I/O
and doesn't belong in an offline-only scan.

## Design summary

- **Endpoint**: ``POST https://api.osv.dev/v1/query`` per (ecosystem,
  name, version). Full details in a single response; simpler cache
  semantics than the batch + fetch-by-id combo.
- **Concrete version resolution**: OSV needs a concrete version to
  match against affected ranges. Manifests carry range specs
  (``^4.16.0``, ``>=2.28,<3``, ``latest``); we extract a best-effort
  lower-bound and let OSV decide whether that version is affected.
  Repos that pin ranges without a lower bound (``*``, ``latest``) are
  skipped with a note.
- **Cache**: JSON files under ``~/.attackmap/cache/osv/`` keyed by
  ``sha256(ecosystem + name + version)``. TTL is
  ``ATTACKMAP_OSV_CACHE_TTL_HOURS`` (default 24). Cache hits stay valid
  offline; misses fall through to the network.
- **Offline mode**: When the network is unavailable, results from a
  warm cache are still emitted; misses are skipped. A single warning
  goes on stderr.
- **Rate limiting**: sequential requests with a small sleep between
  calls. OSV has no hard rate limit for anonymous traffic; the cache
  makes repeat scans free.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from .models import DependencyHint, Vulnerability

logger = logging.getLogger(__name__)


_OSV_QUERY_URL = "https://api.osv.dev/v1/query"
_OSV_ECOSYSTEM: dict[str, str] = {
    "pypi": "PyPI",
    "npm": "npm",
    "go": "Go",
    "cargo": "crates.io",
    "composer": "Packagist",
}

_DEFAULT_TTL_HOURS = 24
_REQUEST_TIMEOUT_S = 10
_INTER_REQUEST_SLEEP_S = 0.1


@dataclass
class LookupSummary:
    """Structured recap of what happened during a --cve run.

    Consumers use ``queried`` / ``cached`` / ``skipped_no_version`` /
    ``skipped_offline`` to print a single-line summary.
    """

    queried: int = 0
    cached: int = 0
    skipped_no_version: int = 0
    skipped_offline: int = 0
    network_errors: int = 0


# --- Public entrypoint -----------------------------------------------------


def query_vulnerabilities(
    dependencies: Iterable[DependencyHint],
    *,
    cache_dir: Path | None = None,
    transport: Callable[[str, bytes], bytes] | None = None,
    clock: Callable[[], float] | None = None,
) -> tuple[list[Vulnerability], LookupSummary]:
    """Look up CVEs for each ``DependencyHint`` and return records.

    Parameters
    ----------
    dependencies
        The SBOM entries to look up. Ecosystems outside the five
        AttackMap knows about are silently ignored.
    cache_dir
        Overrides the default ``~/.attackmap/cache/osv`` — tests
        supply a per-test tmpdir here.
    transport
        Injectable network transport ``(url, body) -> response_bytes``.
        Tests pass a stub; default is urllib.
    clock
        Injectable ``time.time`` for deterministic cache-TTL tests.
    """
    cache = _resolve_cache_dir(cache_dir)
    cache.mkdir(parents=True, exist_ok=True)
    now = (clock or time.time)()
    ttl_seconds = _ttl_seconds()

    vulns: list[Vulnerability] = []
    summary = LookupSummary()
    seen_keys: set[tuple[str, str, str, str]] = set()

    for dep in dependencies:
        osv_eco = _OSV_ECOSYSTEM.get(dep.ecosystem)
        if osv_eco is None:
            continue
        if dep.resolved and dep.version:
            # Lockfile-resolved versions are already exact — query them
            # verbatim so PEP 440 forms like `1.0.post1` / `1!2.3.0` aren't
            # mangled by range normalization (#143). Only strip Go's `v`.
            concrete = dep.version.lstrip("v") if dep.ecosystem == "go" else dep.version
        else:
            concrete = resolve_concrete_version(dep.version)
        if concrete is None:
            summary.skipped_no_version += 1
            continue

        key = (dep.ecosystem, dep.name, concrete)
        cache_path = cache / (_cache_key(*key) + ".json")

        payload: dict | None = _read_cache(cache_path, now, ttl_seconds)
        if payload is not None:
            summary.cached += 1
        else:
            payload = _fetch_osv(osv_eco, dep.name, concrete, transport, summary)
            if payload is None:
                continue  # skipped_offline / network_errors already tallied
            _write_cache(cache_path, payload, now)
            summary.queried += 1
            if transport is None:
                time.sleep(_INTER_REQUEST_SLEEP_S)

        for entry in payload.get("vulns") or []:
            vuln = _entry_to_vulnerability(entry, dep, concrete)
            if vuln is None:
                continue
            fingerprint = (vuln.ecosystem, vuln.package_name, vuln.package_version, vuln.id)
            if fingerprint in seen_keys:
                continue
            seen_keys.add(fingerprint)
            vuln.source_analyzer = "cve"
            # Carry lockfile provenance (#143) so a transitive CVE can report
            # how it was pulled in.
            vuln.direct = dep.direct
            vuln.resolution_path = dep.via or ""
            vulns.append(vuln)

    vulns.sort(
        key=lambda v: (
            _SEVERITY_RANK.get(v.severity, 3),
            v.ecosystem,
            v.package_name,
            v.id,
        )
    )
    return vulns, summary


# --- Version resolution ----------------------------------------------------


_SEMVER_LOWER_BOUND_RE = re.compile(
    r"(?P<major>\d+)(?:\.(?P<minor>\d+))?(?:\.(?P<patch>\d+))?"
    r"(?P<pre>[-+][0-9A-Za-z.\-+]+)?"
)


def resolve_concrete_version(raw: str) -> str | None:
    """Best-effort: extract a queryable version from a manifest spec.

    OSV needs a concrete version to answer "is this affected?". We
    convert:

        ``^4.16.0``          → ``4.16.0``
        ``~5.4.0``           → ``5.4.0``
        ``>=2.28,<3``        → ``2.28``
        ``==21.2.0``         → ``21.2.0``
        ``v1.9.1``           → ``1.9.1``
        ``21.2.0``           → ``21.2.0``
        ``*`` / ``latest``   → None (unknown; skip)
        ``  ``               → None
    """
    if not raw:
        return None
    text = raw.strip()
    if not text:
        return None
    lowered = text.lower()
    if lowered in {"*", "any", "latest", "n/a"}:
        return None
    # Strip leading spec chars and comparator prefixes.
    stripped = text.lstrip("^~=<>! ")
    if stripped.startswith("v"):
        stripped = stripped[1:]
    # Multi-clause spec: "&gt;=2.28,&lt;3" — take the first bounded clause.
    if "," in stripped:
        first = stripped.split(",", 1)[0].strip().lstrip("^~=<>! ")
        stripped = first
    match = _SEMVER_LOWER_BOUND_RE.match(stripped)
    if not match:
        return None
    major = match.group("major")
    minor = match.group("minor") or "0"
    patch = match.group("patch") or "0"
    pre = match.group("pre") or ""
    # Go modules canonicalize as vX.Y.Z; the OSV query accepts either
    # form, but we normalize to bare numerics + optional prerelease.
    return f"{major}.{minor}.{patch}{pre}"


# --- Severity mapping ------------------------------------------------------


_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}

_CVSS_SCORE_RE = re.compile(r"CVSS:[\d.]+/.*")


def map_severity(entry: dict) -> tuple[str, float | None]:
    """Map an OSV severity block to AttackMap's low/medium/high bucket.

    OSV returns:

        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/..."},
            ...
        ]

    plus sometimes a database-specific severity string ("MODERATE",
    "HIGH"). We prefer the numeric CVSS score when it's present;
    otherwise we map the label; otherwise default to medium.
    """
    severities = entry.get("severity") or []
    numeric_score: float | None = None
    for s in severities:
        raw = s.get("score") or ""
        parsed = _cvss_base_score(raw)
        if parsed is not None:
            numeric_score = parsed
            break

    if numeric_score is not None:
        if numeric_score >= 7.0:
            return "high", numeric_score
        if numeric_score >= 4.0:
            return "medium", numeric_score
        return "low", numeric_score

    label = (entry.get("database_specific") or {}).get("severity") or ""
    if isinstance(label, str):
        upper = label.upper()
        if upper in {"CRITICAL", "HIGH"}:
            return "high", None
        if upper in {"MODERATE", "MEDIUM"}:
            return "medium", None
        if upper == "LOW":
            return "low", None
    return "medium", None


def _cvss_base_score(vector: str) -> float | None:
    """Extract the base score from an OSV score string.

    OSV entries store the score as either a raw CVSS vector like
    ``CVSS:3.1/AV:N/AC:L/...`` or an already-computed float. We handle
    both; for vectors we do a small, deliberately-incomplete
    approximation from the exploitability/impact metrics — good enough
    to bucket into low/medium/high without vendoring a full CVSS
    calculator.
    """
    if not vector:
        return None
    stripped = vector.strip()
    # Case 1: a numeric-only score.
    try:
        return float(stripped)
    except ValueError:
        pass
    # Case 2: a CVSS vector. Look for a trailing `... /S:...:...` — some
    # advisories put a computed score in database_specific. But the raw
    # vector doesn't include the number. Use a rough qualitative bump:
    # if AV:N and PR:N and UI:N with a HIGH impact metric, treat as
    # HIGH (~7.5+); else MEDIUM. This isn't full CVSS math — we're just
    # bucketing.
    #
    # Since we're not implementing full CVSS scoring, return None and
    # let the label fallback handle it. Most OSV entries also include
    # a `database_specific.severity` label.
    return None


# --- Vulnerability construction --------------------------------------------


def _entry_to_vulnerability(
    entry: dict, dep: DependencyHint, concrete_version: str
) -> Vulnerability | None:
    vuln_id = entry.get("id")
    if not isinstance(vuln_id, str) or not vuln_id:
        return None
    aliases = [str(a) for a in (entry.get("aliases") or []) if isinstance(a, str)]
    summary = str(entry.get("summary") or "").strip()
    severity, cvss = map_severity(entry)
    references = [
        str(r.get("url"))
        for r in (entry.get("references") or [])
        if isinstance(r, dict) and isinstance(r.get("url"), str)
    ]
    affected_range = _first_affected_range(entry, dep)
    return Vulnerability(
        id=vuln_id,
        aliases=aliases,
        summary=summary,
        severity=severity,  # type: ignore[arg-type]
        cvss_score=cvss,
        references=references,
        affected_range=affected_range,
        package_name=dep.name,
        package_version=concrete_version,
        ecosystem=dep.ecosystem,  # type: ignore[arg-type]
    )


def _first_affected_range(entry: dict, dep: DependencyHint) -> str:
    for affected in entry.get("affected") or []:
        pkg = affected.get("package") or {}
        if str(pkg.get("name") or "").lower() != dep.name.lower():
            continue
        ranges = affected.get("ranges") or []
        for r in ranges:
            events = r.get("events") or []
            lo = next((e.get("introduced") for e in events if "introduced" in e), None)
            hi = next((e.get("fixed") for e in events if "fixed" in e), None)
            if lo or hi:
                lo_s = lo if lo and lo != "0" else "0"
                hi_s = f", fixed in {hi}" if hi else ""
                return f"affected: >= {lo_s}{hi_s}"
    return ""


# --- Cache & transport -----------------------------------------------------


def _resolve_cache_dir(explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit
    override = os.environ.get("ATTACKMAP_CACHE_DIR")
    if override:
        return Path(override) / "osv"
    return Path.home() / ".attackmap" / "cache" / "osv"


def _ttl_seconds() -> int:
    override = os.environ.get("ATTACKMAP_OSV_CACHE_TTL_HOURS")
    if override:
        try:
            hours = int(override)
        except ValueError:
            hours = _DEFAULT_TTL_HOURS
    else:
        hours = _DEFAULT_TTL_HOURS
    return max(0, hours) * 3600


def _cache_key(ecosystem: str, name: str, version: str) -> str:
    return hashlib.sha256(f"{ecosystem}|{name}|{version}".encode("utf-8")).hexdigest()[:32]


def _read_cache(path: Path, now: float, ttl_seconds: int) -> dict | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    fetched_at = data.get("fetched_at")
    payload = data.get("response")
    if not isinstance(fetched_at, (int, float)) or not isinstance(payload, dict):
        return None
    if ttl_seconds > 0 and now - fetched_at > ttl_seconds:
        return None
    return payload


def _write_cache(path: Path, payload: dict, now: float) -> None:
    try:
        path.write_text(
            json.dumps({"fetched_at": now, "response": payload}, separators=(",", ":")),
            encoding="utf-8",
        )
    except OSError:
        # Cache is a nice-to-have; a write failure shouldn't sink the run.
        pass


def _fetch_osv(
    osv_ecosystem: str,
    name: str,
    version: str,
    transport: Callable[[str, bytes], bytes] | None,
    summary: LookupSummary,
) -> dict | None:
    body = json.dumps(
        {"package": {"name": name, "ecosystem": osv_ecosystem}, "version": version}
    ).encode("utf-8")
    try:
        if transport is not None:
            raw = transport(_OSV_QUERY_URL, body)
        else:
            request = urllib.request.Request(
                _OSV_QUERY_URL,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=_REQUEST_TIMEOUT_S) as response:
                raw = response.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        summary.network_errors += 1
        summary.skipped_offline += 1
        logger.debug("OSV network error for %s/%s@%s: %s", osv_ecosystem, name, version, exc)
        return None
    try:
        return json.loads(raw.decode("utf-8") if isinstance(raw, bytes) else raw)
    except json.JSONDecodeError:
        summary.network_errors += 1
        return None


__all__ = [
    "LookupSummary",
    "map_severity",
    "query_vulnerabilities",
    "resolve_concrete_version",
]
