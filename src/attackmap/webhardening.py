"""Web-hardening gap detection (#71).

A per-file pass (invoked from the built-in scanner's existing read loop)
that flags *positively-present* web misconfigurations rather than
hard-to-judge absences:

    cors_wildcard_credentials  wildcard/reflected origin WITH credentials
    csrf_disabled              CSRF explicitly disabled or exempted
    insecure_cookie            httpOnly/secure=false, SameSite=None, etc.
    weak_csp                   CSP allowing 'unsafe-inline' / 'unsafe-eval'
    debug_enabled              debug mode / actuator wildcard exposure

Pure-absence checks ("no CSP header anywhere") are intentionally out of
scope — they're noisy without whole-app reasoning. Everything here keys
off a concrete risky construct in the source.
"""

from __future__ import annotations

import re

from .models import WebHardeningIssue


def _rx(pattern: str) -> re.Pattern[str]:
    # MULTILINE so `^`-anchored patterns (e.g. Django's `DEBUG = True`)
    # match at each line start, not just the start of the file.
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE)


# CORS is a two-part condition (wildcard/reflected origin + credentials).
# Detected via file-level co-occurrence so argument order and framework
# don't matter.
_CORS_WILD_ORIGIN = _rx(
    r"access-control-allow-origin['\"]?\s*[:,]\s*['\"]?\*"
    r"|origins?\s*[:=]\s*['\"]\*['\"]"
    r"|origin\s*:\s*true\b"
)
_CORS_CREDENTIALS = _rx(
    r"access-control-allow-credentials['\"]?\s*[:,]\s*['\"]?true"
    r"|credentials\s*:\s*true"
    r"|supports_credentials\s*=\s*True"
)

# Single-pattern families: (kind, severity, pattern).
_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    # --- CSRF explicitly disabled ---------------------------------------
    (
        "csrf_disabled",
        "medium",
        _rx(
            r"@?csrf_exempt\b"
            r"|WTF_CSRF_ENABLED\s*=\s*False"
            r"|\.csrf\s*\(\s*\)\s*\.\s*disable\s*\("
            r"|csrf\s*\(\s*(?:[\w.]+\s*->\s*[\w.]+\s*\.\s*disable\s*\(\)|[\w.:]+::disable)\s*\)"
            r"|\bcsrf\s*:\s*false"
        ),
    ),
    # --- insecure cookie flags ------------------------------------------
    (
        "insecure_cookie",
        "medium",
        _rx(
            r"httpOnly\s*:\s*false"
            r"|\bsecure\s*:\s*false"
            r"|sameSite\s*:\s*['\"]?none"
            r"|SESSION_COOKIE_SECURE\s*=\s*False"
            r"|SESSION_COOKIE_HTTPONLY\s*=\s*False"
            r"|SESSION_COOKIE_SAMESITE\s*=\s*['\"]?None"
            r"|;\s*samesite=none(?!.*;\s*secure)"
        ),
    ),
    # --- weak CSP -------------------------------------------------------
    (
        "weak_csp",
        "medium",
        # 'unsafe-inline' / 'unsafe-eval' only appear in a CSP context.
        _rx(r"['\"]unsafe-(?:inline|eval)['\"]|(?<![\w-])unsafe-(?:inline|eval)(?![\w-])"),
    ),
    # --- debug enabled --------------------------------------------------
    (
        "debug_enabled",
        "medium",
        _rx(
            r"app\.run\s*\([^)]*debug\s*=\s*True"
            r"|^\s*DEBUG\s*=\s*True"
            r"|\bapp\.debug\s*=\s*true"
            r"|FLASK_DEBUG\s*=\s*1"
            r"|consider_all_requests_local\s*=\s*true"
            r"|management\.endpoints\.web\.exposure\.include\s*=\s*\*"
            r"|exposure\.include['\"]?\s*[:=]\s*['\"]\*['\"]"
        ),
    ),
)


def find_web_hardening_issues(content: str, rel_file: str) -> list[WebHardeningIssue]:
    """Return web-hardening issues in one file's ``content`` (deduped by
    (kind, line))."""
    seen: set[tuple[str, int]] = set()
    out: list[WebHardeningIssue] = []

    def _add(kind: str, severity: str, offset: int) -> None:
        line = content.count("\n", 0, offset) + 1
        key = (kind, line)
        if key in seen:
            return
        seen.add(key)
        out.append(
            WebHardeningIssue(
                kind=kind,  # type: ignore[arg-type]
                file=rel_file,
                line=line,
                evidence_text=_snippet(content, offset),
                severity=severity,  # type: ignore[arg-type]
                source_analyzer="webhardening",
            )
        )

    # CORS: only when BOTH a wildcard/reflected origin and credentials
    # appear in the file. Anchor the finding at the origin declaration.
    origin_match = _CORS_WILD_ORIGIN.search(content)
    if origin_match is not None and _CORS_CREDENTIALS.search(content) is not None:
        _add("cors_wildcard_credentials", "high", origin_match.start())

    for kind, severity, pattern in _PATTERNS:
        for match in pattern.finditer(content):
            _add(kind, severity, match.start())

    return out


def _snippet(content: str, offset: int, radius: int = 120) -> str:
    start = max(0, content.rfind("\n", 0, offset) + 1)
    end = content.find("\n", offset)
    if end == -1:
        end = len(content)
    line = content[start:end].strip()
    return line[:radius] + ("…" if len(line) > radius else "")


__all__ = ["find_web_hardening_issues"]
