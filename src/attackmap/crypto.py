"""Insecure-cryptography & weak-randomness detection (#70).

A cheap, high-signal regex pass over each source file, invoked from the
built-in scanner (content is already in hand — no extra file walk).

Detected families (each → a ``CryptoWeakness``):

    weak_password_hash  MD5/SHA-1 applied to a password-shaped value
    weak_cipher         DES / 3DES / RC4 / Blowfish
    ecb_mode            ECB block-cipher mode (incl. Java's AES default)
    static_iv_salt      hard-coded IV or salt literal
    insecure_random     non-CSPRNG used for a security value
    insecure_tls        certificate / hostname verification disabled

Precision note (SSRF lesson from #68): the two families that would
otherwise be noisy — ``weak_password_hash`` and ``insecure_random`` —
are gated on a security-context identifier in the same statement.
Unambiguous families (DES, RC4, ECB, ``verify=False``) fire on the
pattern alone.
"""

from __future__ import annotations

import re

from .models import CryptoWeakness

# Identifiers that mark a value as security-sensitive. Gate the noisy
# families on one of these appearing in the same call/statement.
#
# Matched as a SUBSTRING (no word boundaries) so compound identifiers
# like `user_password`, `sessionId`, and `reset_token` are caught. We
# deliberately omit generic words like "hash" that collide with common
# non-security identifiers (`hashlib`, `hashmap`).
_SECURITY_CTX = (
    r"(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|"
    r"private[_-]?key|nonce|otp|salt|seed|session|csrf|cred)"
)


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


# Each entry: (kind, severity, compiled pattern). Order is stable for
# deterministic output.
_CRYPTO_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    # --- weak password hashing (gated on a password-shaped identifier) ---
    (
        "weak_password_hash",
        "high",
        _rx(rf"\b(?:hashlib\.)?(?:md5|sha1)\s*\([^)]*{_SECURITY_CTX}"),
    ),
    (
        "weak_password_hash",
        "high",
        # createHash('md5'|'sha1') ... update(password) — Node
        _rx(rf"createHash\s*\(\s*['\"](?:md5|sha1)['\"]\s*\)[^;\n]*{_SECURITY_CTX}"),
    ),
    (
        "weak_password_hash",
        "high",
        # Java MessageDigest.getInstance("MD5"|"SHA-1")
        _rx(r"MessageDigest\.getInstance\s*\(\s*['\"](?:MD5|SHA-?1)['\"]\s*\)"),
    ),
    # --- weak ciphers ----------------------------------------------------
    # CASE-SENSITIVE on purpose: algorithm tokens are uppercase/PascalCase
    # in code (`DES`, `RC4`, `TripleDES`, `Blowfish`). An IGNORECASE match
    # flags the French word "des", Spanish "rc", etc. in i18n strings —
    # observed as 12 false positives on a real repo before this fix.
    (
        "weak_cipher",
        "high",
        re.compile(r"\b(?:3?DES|DESede|TripleDES|RC4|ARC4|ARCFOUR|RC2)\b|\bBlowfish\w*"),
    ),
    (
        "weak_cipher",
        "high",
        # Node/OpenSSL-style lowercase scheme strings: 'des-cbc',
        # 'des-ede3-cbc', 'rc4', 'bf-cbc' (Blowfish). Quoted to avoid prose.
        # `bf` is too short to match alone (a 'bf' label != Blowfish), so it
        # requires a mode suffix; the distinctive names may stand alone.
        _rx(r"['\"](?:3?des(?:-ede3?)?(?:-[a-z0-9]+)*|rc4|arcfour|blowfish(?:-[a-z0-9]+)*|bf-[a-z0-9]+)['\"]"),
    ),
    # --- ECB mode --------------------------------------------------------
    # Case-sensitive uppercase tokens; plus a lowercase quoted-scheme pass.
    (
        "ecb_mode",
        "medium",
        re.compile(r"MODE_ECB|['\"/](?:AES|DES)/ECB|\bECB\b"),
    ),
    (
        "ecb_mode",
        "medium",
        # lowercase scheme strings like 'aes-256-ecb'
        _rx(r"['\"][a-z0-9]+(?:-[a-z0-9]+)*-ecb['\"]"),
    ),
    (
        "ecb_mode",
        "medium",
        # Java Cipher.getInstance("AES") defaults to ECB when no mode given
        _rx(r"Cipher\.getInstance\s*\(\s*['\"]AES['\"]\s*\)"),
    ),
    # --- static IV / salt ------------------------------------------------
    (
        "static_iv_salt",
        "medium",
        # iv = b"...." / IV: "...." / salt = '....'  (a string/bytes literal).
        # `nonce` is deliberately excluded — hardcoded nonces are mostly
        # HTTP-auth / protocol test data, not cipher-IV misuse.
        _rx(r"\b(?:iv|salt)\s*[:=]\s*(?:b|rb|u)?['\"][^'\"]{4,}['\"]"),
    ),
    # --- insecure randomness (gated on security context) -----------------
    (
        "insecure_random",
        "medium",
        _rx(rf"Math\.random\s*\(\s*\)[^;\n]*{_SECURITY_CTX}"),
    ),
    (
        "insecure_random",
        "medium",
        _rx(rf"{_SECURITY_CTX}[^;\n]*(?:Math\.random\s*\(|random\.(?:random|randint|choice|randrange)\s*\(|\bmt_rand\s*\(|\brand\s*\()"),
    ),
    (
        "insecure_random",
        "medium",
        _rx(rf"(?:random\.(?:random|randint|choice|randrange)\s*\(|\bmt_rand\s*\()[^;\n]*{_SECURITY_CTX}"),
    ),
    # --- insecure TLS ----------------------------------------------------
    (
        "insecure_tls",
        "high",
        # requests/httpx verify=False; Python ssl check_hostname=False
        _rx(r"verify\s*=\s*False|check_hostname\s*=\s*False|CERT_NONE"),
    ),
    (
        "insecure_tls",
        "high",
        # Node rejectUnauthorized: false ; Go InsecureSkipVerify: true
        _rx(r"rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true"),
    ),
    (
        "insecure_tls",
        "high",
        # deprecated protocols
        _rx(r"PROTOCOL_TLSv1(?:_1)?\b|PROTOCOL_SSLv[23]\b|SSLv3|\bTLSv1\.0\b"),
    ),
)


def find_crypto_weaknesses(content: str, rel_file: str) -> list[CryptoWeakness]:
    """Return crypto weaknesses found in one file's ``content``.

    Deduped by (kind, line) within the file so a single risky line isn't
    reported twice by overlapping patterns.
    """
    seen: set[tuple[str, int]] = set()
    out: list[CryptoWeakness] = []
    for kind, severity, pattern in _CRYPTO_PATTERNS:
        for match in pattern.finditer(content):
            line = content.count("\n", 0, match.start()) + 1
            key = (kind, line)
            if key in seen:
                continue
            seen.add(key)
            out.append(
                CryptoWeakness(
                    kind=kind,  # type: ignore[arg-type]
                    file=rel_file,
                    line=line,
                    evidence_text=_snippet(content, match.start()),
                    severity=severity,  # type: ignore[arg-type]
                    source_analyzer="crypto",
                )
            )
    return out


def _snippet(content: str, offset: int, radius: int = 120) -> str:
    start = max(0, content.rfind("\n", 0, offset) + 1)
    end = content.find("\n", offset)
    if end == -1:
        end = len(content)
    line = content[start:end].strip()
    return line[:radius] + ("…" if len(line) > radius else "")


__all__ = ["find_crypto_weaknesses"]
