"""Credential redaction for every evidence string AttackMap emits (#235).

Evidence text is copied into ``attackmap-report.json``, SARIF (often uploaded
to code scanning, readable by anyone with repo read access), PR comments and
the LLM evidence pack. A credential that appears in the scanned code must
never be copied verbatim into any of them, whatever detector produced the
snippet. :func:`redact_text` is applied to every evidence field when the
model is constructed (see ``models._RedactedEvidence``), and to source
excerpts before they reach an LLM prompt.

What is masked, anywhere in a string:
    * every provider-shaped token (AWS, GitHub, Slack, Stripe, JWT, …) —
      all matches, not just the one a detector was looking for;
    * URI userinfo passwords (``scheme://user:PASS@`` → ``scheme://user:***@``)
      and token-only userinfo (``https://TOKEN@host``);
    * query / form parameters named like credentials (``?api_key=…``);
    * ``Bearer`` / ``Basic`` authorization values;
    * values assigned to credential-named keys (``password = "…"``,
      ``API_KEY=…``, ``secret: …``);
    * other high-entropy quoted literals.

Redaction is idempotent and never lengthens a masked value; at most the
first 4 characters of a secret survive (:func:`mask_secret`).
"""

from __future__ import annotations

import math
import re

MASK = "***"

# Provider-shaped tokens: a superset of scanner.HARDCODED_SECRET_PATTERNS
# (detection keeps its own list so adding a redaction shape here never changes
# which findings are produced). test_redact checks every detection pattern is
# also redacted.
SECRET_TOKEN_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "aws_access_key"),
    (re.compile(r"\b(ASIA[0-9A-Z]{16})\b"), "aws_temporary_key"),
    (re.compile(r"\b(ghp_[A-Za-z0-9]{36,})\b"), "github_pat"),
    (re.compile(r"\b(gho_[A-Za-z0-9]{36,})\b"), "github_oauth_token"),
    (re.compile(r"\b(ghu_[A-Za-z0-9]{36,})\b"), "github_user_token"),
    (re.compile(r"\b(ghs_[A-Za-z0-9]{36,})\b"), "github_server_token"),
    (re.compile(r"\b(ghr_[A-Za-z0-9]{36,})\b"), "github_refresh_token"),
    (re.compile(r"\b(github_pat_[A-Za-z0-9_]{60,})\b"), "github_fine_grained_pat"),
    (re.compile(r"\b(xox[bpsare]-[0-9A-Za-z-]{10,})\b"), "slack_token"),
    (re.compile(r"\b((?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{24,})\b"), "stripe_key"),
    (re.compile(r"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b"), "sendgrid_key"),
    (re.compile(r"\b(key-[a-f0-9]{32})\b"), "mailgun_key"),
    (re.compile(r"\b(AC[a-f0-9]{32})\b"), "twilio_account_sid"),
    (re.compile(r"\b(AIza[A-Za-z0-9_-]{35,42})\b"), "google_api_key"),
    (re.compile(r"\b(sk-ant-[A-Za-z0-9_-]{40,})\b"), "anthropic_key"),
    (re.compile(r"\b(sk-proj-[A-Za-z0-9_-]{20,})\b"), "openai_key"),
    (re.compile(r"\b(sk-svcacct-[A-Za-z0-9_-]{20,})\b"), "openai_key"),
    (re.compile(r"\b(sk-[A-Za-z0-9]{48,})\b"), "openai_key"),
    (re.compile(r"\b(glpat-[A-Za-z0-9_-]{20,})\b"), "gitlab_pat"),
    (re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"), "npm_token"),
    (re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"), "jwt"),
    # --- #252: credential families without a classic prefix -------------
    # AWS secret access key: 40 chars, only trusted next to its key name.
    (re.compile(r"(?i)aws_?secret_?(?:access_?)?key['\"]?\s{0,5}(?::=|=>|[:=])\s{0,5}['\"]?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"), "aws_secret_access_key"),
    # Azure storage / Service Bus connection-string keys.
    (re.compile(r"(?i)\bAccountKey=([A-Za-z0-9+/]{40,100}={0,2})"), "azure_storage_account_key"),
    (re.compile(r"(?i)\bSharedAccessKey=([A-Za-z0-9+/]{40,64}={0,2})"), "azure_shared_access_key"),
    # Azure AD (Entra) client secret: 3 chars, a digit, `Q~`, 31-34 chars.
    (re.compile(r"(?<![A-Za-z0-9_~.-])([A-Za-z0-9_~.]{3}\dQ~[A-Za-z0-9_~.-]{31,34})(?![A-Za-z0-9_~.-])"), "azure_ad_client_secret"),
    # Datadog API / application keys (hex, keyed by name).
    (re.compile(r"(?i)\b(?:dd|datadog)_?(?:api|app(?:lication)?)_?key['\"]?\s{0,5}[:=]\s{0,5}['\"]?([a-f0-9]{32}(?:[a-f0-9]{8})?)\b"), "datadog_key"),
    # Heroku platform API key (new format).
    (re.compile(r"\b(HRKU-AA[0-9A-Za-z_-]{58})\b"), "heroku_api_key"),
    # DigitalOcean personal / OAuth / refresh tokens.
    (re.compile(r"\b(do[opr]_v1_[a-f0-9]{64})\b"), "digitalocean_token"),
    # HashiCorp Vault service / batch tokens.
    (re.compile(r"\b(hv[sb]\.[A-Za-z0-9_-]{24,})\b"), "vault_token"),
    # .npmrc registry auth: `//registry.npmjs.org/:_authToken=…`, `_auth=`/`_password=`.
    (re.compile(r":_authToken\s{0,5}=\s{0,5}([A-Za-z0-9._~+/=-]{8,})"), "npm_auth_token"),
    (re.compile(r"(?m)^\s{0,8}(?:\S{0,200}:)?_(?:auth|password)\s{0,5}=\s{0,5}([A-Za-z0-9+/=]{8,})"), "npm_basic_auth"),
    # Docker registry auth blob in `.dockercfg` / `config.json`.
    (re.compile(r"\"auth\"\s{0,5}:\s{0,5}\"([A-Za-z0-9+/]{12,}={0,2})\""), "docker_registry_auth"),
]

_CRED_WORDS = (
    r"password|passwd|passphrase|pwd|secret|token|api[_-]?key|apikey|access[_-]?key"
    r"|private[_-]?key|priv[_-]?key|client[_-]?secret|auth[_-]?key|credentials?"
)
# Query parameters also use short signature names (`?sig=`, `&signature=`).
_QUERY_WORDS = _CRED_WORDS + r"|sig|signature"

# scheme://user:password@host  /  scheme://token@host
_URI_USERINFO = re.compile(
    r"(?P<prefix>\b[a-zA-Z][a-zA-Z0-9+.-]{0,31}://)(?P<user>[^\s:/@'\"]{0,256})(?::(?P<password>[^\s/@'\"]{1,256}))?@"
)
# ?api_key=… &token=… (query strings and form bodies)
_QUERY_PARAM = re.compile(
    rf"(?P<prefix>[?&;](?:[\w.-]{{0,64}}?(?:{_QUERY_WORDS})[\w.-]{{0,64}})=)(?P<value>[^&#\s'\"]+)",
    re.IGNORECASE,
)
# Authorization: Bearer … / Basic … (a plain word after it is prose, not a token)
_AUTH_SCHEME = re.compile(r"(?P<prefix>\b(?:Bearer|Basic)\s+)(?P<value>[A-Za-z0-9._~+/=-]{8,})")
# key = "value" / key: 'value' / KEY=value — the value of a credential-named key.
_KEY_ASSIGN = re.compile(
    # Starts only at a token boundary (not every `\b` inside `a.b-c`), and the
    # key prefix/suffix are bounded, so hostile long tokens stay linear (#236).
    rf"(?P<prefix>['\"]?(?<![\w.-])[\w.-]{{0,64}}?(?:{_CRED_WORDS})[\w.-]{{0,64}}['\"]?\s*(?::=|=>|[:=])\s*)"
    # A bare value directly followed by `(`, `[` or more identifier text is
    # code (`request.headers.get(...)`, `os.environ[...]`), not a literal.
    # An unterminated quoted value (a snippet cut at its length cap) is masked
    # too: losing the closing quote must not let the secret through (#252).
    r"(?:(?P<q>['\"])(?P<qvalue>[^'\"\n]{4,}?)(?:(?P=q)|$)|(?P<bare>[^\s'\",;#()\[\]{}]{4,})(?![(\[.\w]))",
    re.IGNORECASE,
)
_QUOTED_LITERAL = re.compile(r"(?P<q>['\"])(?P<value>[A-Za-z0-9+/_=-]{24,256})(?P=q)")

# Unquoted values that are references to a secret, not the secret itself.
_REFERENCE_VALUE = re.compile(
    r"""^(?:
        \$\{?[A-Za-z_]\w*\}?            # $VAR / ${VAR}
      | \{\{.*                          # {{ template }}
      | %\(.*                           # %(name)s
      | <[^>]*>?                        # <placeholder>
      | [A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+ # settings.SECRET_KEY, process.env.TOKEN
      | [A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+   # JWT_SECRET — the *name* of a secret
      | [A-Za-z_]\w*\(.*                # getenv(...), call(...)
      | [A-Za-z_]\w*\[.*                # os.environ[...]
      | (?:true|false|null|none|nil)
    )$""",
    re.IGNORECASE | re.VERBOSE,
)


def mask_secret(value: str) -> str:
    """Display form of a secret: at most its first 4 characters, then ``…``."""
    if len(value) < 12:
        return "…"
    return f"{value[:4]}…"


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def _is_masked(value: str) -> bool:
    return value == MASK or value.endswith("…") or set(value) <= {"*", "…", "x", "X"}


def _looks_random(value: str) -> bool:
    if value.isdigit() or (value.isalpha() and (value.islower() or value.isupper())):
        return False
    if "/" in value and value.count("/") >= 2:  # paths / mime types
        return False
    return shannon_entropy(value) >= 4.2


def _mask_group(m: re.Match[str]) -> str:
    """Mask only the secret (group 1), keeping any key-name context the
    pattern matched around it (``AccountKey=``, ``aws_secret_access_key =``)."""
    whole, start = m.group(0), m.start(0)
    return whole[: m.start(1) - start] + mask_secret(m.group(1)) + whole[m.end(1) - start :]


def redact_text(text: str | None) -> str | None:
    """Mask every credential-looking value in ``text``. Idempotent."""
    if not text or len(text) < 8:
        return text
    out = text
    for pattern, _kind in SECRET_TOKEN_PATTERNS:
        out = pattern.sub(_mask_group, out)

    def _userinfo(m: re.Match[str]) -> str:
        user, password = m.group("user"), m.group("password")
        if password is not None:
            return f"{m.group('prefix')}{user}:{MASK}@" if not _is_masked(password) else m.group(0)
        # Token-only userinfo (https://TOKEN@github.com) — mask when it isn't
        # an ordinary username (git@, user@).
        if len(user) >= 16 and not _is_masked(user):
            return f"{m.group('prefix')}{MASK}@"
        return m.group(0)

    out = _URI_USERINFO.sub(_userinfo, out)
    out = _QUERY_PARAM.sub(lambda m: m.group(0) if _is_masked(m.group("value")) else m.group("prefix") + MASK, out)
    out = _AUTH_SCHEME.sub(
        lambda m: m.group(0)
        if _is_masked(m.group("value")) or m.group("value").isalpha()
        else m.group("prefix") + MASK,
        out,
    )

    def _assign(m: re.Match[str]) -> str:
        if m.group("q"):
            value = m.group("qvalue")
            terminated = m.group(0).endswith(m.group("q")) and len(m.group(0)) > len(m.group("prefix")) + 1 + len(value)
            if not terminated:
                value = value.rstrip("…")  # snippet cut mid-value: not "already masked"
            if _is_masked(value) or _REFERENCE_VALUE.match(value):
                return m.group(0)
            return f"{m.group('prefix')}{m.group('q')}{MASK}{m.group('q')}"
        value = m.group("bare")
        if _is_masked(value) or _REFERENCE_VALUE.match(value):
            return m.group(0)
        return f"{m.group('prefix')}{MASK}"

    out = _KEY_ASSIGN.sub(_assign, out)

    def _literal(m: re.Match[str]) -> str:
        value = m.group("value")
        if _is_masked(value) or not _looks_random(value):
            return m.group(0)
        return f"{m.group('q')}{mask_secret(value)}{m.group('q')}"

    return _QUOTED_LITERAL.sub(_literal, out)


def redact_list(values: list[str]) -> list[str]:
    return [redact_text(v) or "" for v in values]
