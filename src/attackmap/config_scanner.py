"""Config-file scanner (#43).

YAML / TOML / JSON / INI / .env files often carry the real DB
connection strings, service URLs, and — connecting to #39 — hard-coded
credentials the source code hasn't yet inlined. `scan_repo`
intentionally covers only source, so this module fills the config gap
with the same regex-based, dependency-free approach: text-scan the
files, emit `DatabaseHint` / `ExternalCall` / `SecretHint` records
into a `ScanResult`, and let the merge pipeline dedup as usual.

Deliberately no YAML / TOML / JSON *parsers* — the goal is broad,
resilient extraction that works on malformed files too. Callers who
want structural analysis can extend on top; this layer stays regex-only.
"""

from __future__ import annotations

import bisect
import re
from pathlib import Path

from .srcpaths import SKIP_DIRS, in_skipped_dir, is_skipped_dir
from .redact import mask_secret
from .safe_fs import max_file_bytes, walk_repo
from .models import DatabaseHint, ExternalCall, ScanResult, SecretHint
from .scanner import _append_hardcoded_secret_hints, _line_snippet

# Config files larger than this are skipped — at that size they're invariably
# generated (lock files, minified bundles, or AttackMap's own JSON reports)
# rather than hand-written config, and scanning multi-megabyte text for URL /
# secret regexes is pointlessly slow.
_MAX_CONFIG_BYTES = 5_000_000


class _LineIndex:
    """O(log n) line-number lookups for a file's text.

    `scanner._line_of` counts newlines from the start on every call — O(n) each,
    which degrades to O(n^2) when a large file yields many matches (the cause of
    a scan hang on multi-megabyte JSON). Precomputing the line-start offsets once
    and binary-searching keeps extraction linear.
    """

    __slots__ = ("_starts",)

    def __init__(self, content: str) -> None:
        starts = [0]
        find = content.find
        idx = find("\n")
        while idx != -1:
            starts.append(idx + 1)
            idx = find("\n", idx + 1)
        self._starts = starts

    def line_of(self, offset: int) -> int:
        """1-indexed line number for a character offset."""
        if offset <= 0:
            return 1
        return bisect.bisect_right(self._starts, offset)


CONFIG_SUFFIXES = {".yaml", ".yml", ".toml", ".json", ".ini", ".cfg", ".env"}
# Also match dotfiles like `.env.example`, `.env.sample`, `sample.env` —
# handled via filename check rather than suffix.
_CONFIG_FILENAME_HINTS = ("env",)  # substring in stem for `.env`-family files


# Filenames excluded even when they have a matching suffix. These carry
# inventory / build state, not application config.
CONFIG_EXCLUDE_FILENAMES = frozenset({
    # AttackMap's own artifacts (#216) — never re-ingest a previous report,
    # even from an output dir written before the output marker existed.
    "attackmap-report.json",
    "defensive-review.json",
    "review-context-pack.json",
    "fleet-summary.json",
    "defensive-review-llm.meta.json",
    "benchmark-results.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "cargo.lock",
    "poetry.lock",
    "uv.lock",
    "tsconfig.json",
    "jsconfig.json",
    ".eslintrc.json",
    ".prettierrc.json",
    "renovate.json",
    "package.json",  # noisy: `scripts:` values look like URLs and DB strings
})

_SKIP_DIRS = SKIP_DIRS  # shared set (#215)

# Credential dotfiles (#252): registry / VCS / SSH credentials that neither
# the source pass (skips dotfiles) nor the suffix match above would read.
# Symlinked ones are still skipped by walk_repo (#234).
CREDENTIAL_FILENAMES = frozenset({
    ".npmrc", ".pypirc", ".netrc", "_netrc", ".dockercfg", ".git-credentials",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
})
# `.netrc`: `machine host login user password SECRET`.
_NETRC_PASSWORD_RE = re.compile(r"\bpassword\s{1,20}(?P<value>\S{4,256})")


# --- DB URL extraction --------------------------------------------------------

# `postgresql://user:pass@host:5432/db`, `mysql://...`, `mongodb://...`,
# `redis://...`, `sqlite:///path`. Scheme drives the `kind` value.
_DB_URL_PATTERN = re.compile(
    r"""(?P<scheme>postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|sqlite)
        ://
        (?P<userinfo>[^@\s"'/]*@)?          # optional user[:pass]@
        [^\s"']*                             # host + path
    """,
    re.IGNORECASE | re.VERBOSE,
)
_DB_SCHEME_TO_KIND = {
    "postgres": "postgresql",
    "postgresql": "postgresql",
    "mysql": "mysql",
    "mongodb": "mongodb",
    "mongodb+srv": "mongodb",
    "redis": "redis",
    "sqlite": "sqlite",
}

# HTTPS URLs targeting real external hosts. Skip common non-target hosts
# (localhost, example.com, github.com CI links, cdn.jsdelivr, etc.) so
# `homepage:` and `repository:` config fields don't flood ExternalCall.
_HTTP_URL_PATTERN = re.compile(r"https?://[a-zA-Z0-9._-]+(?::\d+)?(?:/[^\s\"'`]*)?")
_URL_HOST_SKIP = re.compile(
    r"^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|(?:.*\.)?(?:example\.com|invalid|"
    r"github\.com|githubusercontent\.com|jsdelivr\.net|unpkg\.com|w3\.org|"
    r"schemastore\.org|npmjs\.com))(?::\d+)?$",
    re.IGNORECASE,
)


# --- Secret KV extraction -----------------------------------------------------

# Keys that mark a secret-bearing config field. Match on the KEY side of
# a `key: value` / `key = value` pair.
_SECRET_KEY_RE = re.compile(
    # start-of-line or dict/list intro. (`-` is not a start char: YAML's
    # `- key:` already starts at the space, and allowing it made every `-` in
    # a long dashed token a new start — #236.)
    r"(?:^|[\s,{\[])"
    r"['\"]?(?P<key>[a-zA-Z0-9_.-]{0,64}"             # optional key prefix (bounded, #236)
    r"(?:password|passwd|secret|token|api[_-]?key|priv[_-]?key|private[_-]?key|apikey|_pass|_pwd))"
    r"['\"]?"
    r"\s*[:=]\s*"
    r"(?:['\"](?P<value>[^'\"\n]{4,})['\"]|(?P<bare>[^\s#'\",]{4,}))",
    re.IGNORECASE | re.MULTILINE,
)

# Values that look like placeholders / template interpolation / dev
# defaults — must NOT be flagged as real secrets. Case-insensitive
# comparison against the trimmed literal.
_PLACEHOLDER_LITERALS = frozenset({
    "changeme", "change-me", "change_me",
    "example", "example-value",
    "your-secret", "your-secret-here", "your_secret", "your_secret_here",
    "your-token-here", "your_token_here",
    "your-api-key", "your-api-key-here", "your_api_key", "your_api_key_here",
    "your-password", "your-password-here", "your_password", "your_password_here",
    "placeholder", "todo", "fixme",
    "xxx", "yyy", "zzz",
    "null", "none", "false", "true",
    "n/a", "na", "tbd",
    "root", "admin",  # noisy default usernames masquerading as passwords
})


def _is_placeholder(value: str) -> bool:
    trimmed = value.strip()
    lower = trimmed.lower()
    if lower in _PLACEHOLDER_LITERALS:
        return True
    # Template interpolation — `${ENV_VAR}`, `{{ .Values.foo }}`, `<value>`.
    if trimmed.startswith(("${", "{{", "<")):
        return True
    # Repeating single character — `xxxxxxxx`, `----`, `********`.
    if len(set(trimmed)) <= 1:
        return True
    # Environment variable substitution shape `$VAR`.
    if re.fullmatch(r"\$[A-Z_][A-Z0-9_]*", trimmed):
        return True
    # File path — probably a keyfile pointer, not the key itself.
    if trimmed.startswith(("/", "./", "../")) or trimmed.endswith((".pem", ".key", ".crt")):
        return True
    return False


def _redact(value: str) -> str:
    return mask_secret(value)


# --- Public entry points ------------------------------------------------------


def should_scan_config_file(path: Path) -> bool:
    """True if the file is a config file this module should extract from."""
    name = path.name.lower()
    if name in CREDENTIAL_FILENAMES or (name.startswith("id_") and name.split(".")[0] in CREDENTIAL_FILENAMES and not name.endswith(".pub")):
        return True
    if name in CONFIG_EXCLUDE_FILENAMES:
        return False
    if path.suffix.lower() in CONFIG_SUFFIXES:
        return True
    # .env, .env.example, sample.env, etc.
    return any(hint in name for hint in _CONFIG_FILENAME_HINTS) and name.startswith(".env") or name.endswith(".env") or ".env." in name


def scan_config_repo(root: str | Path) -> ScanResult:
    """Walk `root`, extract config-shaped signals, return a ScanResult
    that merges naturally with source-scanner output via the standard
    merge pipeline."""
    repo = Path(root).resolve()
    result = ScanResult(root=str(repo))
    if not repo.exists() or not repo.is_dir():
        return result

    for path in walk_repo(repo, prune=is_skipped_dir):
        if in_skipped_dir(path.relative_to(repo)):
            continue
        if not should_scan_config_file(path):
            continue
        try:
            if path.stat().st_size > min(_MAX_CONFIG_BYTES, max_file_bytes()):
                continue
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        result.files_scanned += 1
        relative = str(path.relative_to(repo)).replace("\\", "/")
        _extract_db_urls(content, relative, result)
        _extract_http_targets(content, relative, result)
        _extract_secret_kvs(content, relative, result)
        if path.name.lower() in {".netrc", "_netrc"}:
            _extract_netrc(content, relative, result)
        # Provider-shaped tokens, URL passwords and GCP service-account keys
        # (#252). No entropy fallback or keyword rule here: config already
        # has the key/value pass, and the entropy fallback is noisy on data.
        _append_hardcoded_secret_hints(result, relative, content, entropy=False, generic=False)
    return result


def _extract_netrc(content: str, relative: str, result: ScanResult) -> None:
    index = _LineIndex(content)
    for match in _NETRC_PASSWORD_RE.finditer(content):
        value = match.group("value")
        if _is_placeholder(value):
            continue
        result.secret_hints.append(
            SecretHint(
                name=_redact(value),
                file=relative,
                line=index.line_of(match.start()),
                evidence_text=_line_snippet(content, match.start()).replace(value, _redact(value)),
                confidence=1.0,
                kind="netrc_password",
            )
        )


def _extract_db_urls(content: str, relative: str, result: ScanResult) -> None:
    seen: set[str] = {(h.kind, h.file) for h in result.databases if h.file == relative}
    index = _LineIndex(content)
    for match in _DB_URL_PATTERN.finditer(content):
        scheme = match.group("scheme").lower()
        kind = _DB_SCHEME_TO_KIND.get(scheme, scheme)
        key = (kind, relative)
        if key not in seen:
            result.databases.append(
                DatabaseHint(
                    kind=kind,
                    file=relative,
                    line=index.line_of(match.start()),
                    evidence_text=_line_snippet(content, match.start()),
                )
            )
            seen.add(key)
        # DB URL with embedded userinfo → password in the URL is a real secret.
        userinfo = match.group("userinfo")
        if userinfo and ":" in userinfo:
            # userinfo shape is `user:pass@`; strip the trailing `@`
            user_pass = userinfo.rstrip("@")
            _, _, password = user_pass.partition(":")
            if password and not _is_placeholder(password):
                result.secret_hints.append(
                    SecretHint(
                        name=_redact(password),
                        file=relative,
                        line=index.line_of(match.start()),
                        evidence_text=_line_snippet(content, match.start()),
                        confidence=1.0,
                        kind=f"{kind}_url_password",
                    )
                )


def _extract_http_targets(content: str, relative: str, result: ScanResult) -> None:
    seen_targets = {(c.target, c.file) for c in result.external_calls if c.file == relative}
    index = _LineIndex(content)
    for match in _HTTP_URL_PATTERN.finditer(content):
        target = match.group(0)
        # Trim trailing punctuation that looks like URL end
        target = target.rstrip("),;.\"'")
        parsed_host = _extract_host(target)
        if parsed_host and _URL_HOST_SKIP.match(parsed_host):
            continue
        if (target, relative) in seen_targets:
            continue
        result.external_calls.append(
            ExternalCall(
                target=target,
                file=relative,
                line=index.line_of(match.start()),
                evidence_text=_line_snippet(content, match.start()),
            )
        )
        seen_targets.add((target, relative))


def _extract_host(url: str) -> str | None:
    match = re.match(r"https?://([^/:\s]+)", url, re.IGNORECASE)
    return match.group(1) if match else None


def _masked_kv_snippet(content: str, match: re.Match[str], value: str) -> str:
    """The line up to the value, then the masked value. Masking explicitly
    (not via the generic evidence redaction) matters when the line is long:
    a truncated snippet loses the closing quote that redaction keys on, and a
    multi-line value such as a JSON-escaped PEM key would leak (#252)."""
    group = "value" if match.group("value") is not None else "bare"
    start = match.start(group)
    line_start = content.rfind("\n", 0, start) + 1
    head = content[line_start:start].lstrip()
    if len(head) > 120:
        head = "…" + head[-119:]
    quote = content[start - 1] if group == "value" else ""
    return f"{head}{_redact(value)}{quote}"


def _extract_secret_kvs(content: str, relative: str, result: ScanResult) -> None:
    seen: set[tuple[str, int]] = {(h.name, h.line or 0) for h in result.secret_hints if h.file == relative}
    index = _LineIndex(content)
    for match in _SECRET_KEY_RE.finditer(content):
        key = match.group("key")
        value = match.group("value") or match.group("bare") or ""
        if not value or _is_placeholder(value):
            continue
        # Line from the key itself: the pattern's leading `\s` alternative can
        # consume the previous line's newline, so match.start() may sit one
        # line early (#235).
        line = index.line_of(match.start("key"))
        # Store `key` as the SecretHint.name so consumers see WHICH secret
        # was leaked (auth vs stripe vs db). Value itself is redacted into
        # evidence_text via the same helper hardcoded-secret detection uses.
        secret_key = (key, line)
        if secret_key in seen:
            continue
        seen.add(secret_key)
        result.secret_hints.append(
            SecretHint(
                name=key,
                file=relative,
                line=line,
                evidence_text=_masked_kv_snippet(content, match, value),
                confidence=0.9,
                kind="config_literal",
            )
        )


__all__ = [
    "scan_config_repo",
    "should_scan_config_file",
    "CONFIG_SUFFIXES",
    "CONFIG_EXCLUDE_FILENAMES",
]
