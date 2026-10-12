"""Webhook signature verification (#243, part B).

A public webhook is only as trustworthy as the check on its payload. For each
webhook surface this module reads the handler (its span, see
:mod:`handler_span`), the functions it delegates to (one hop, through
:class:`authz._HopResolver`) and JS middleware mounted with ``.use(...)`` in
the same file, and decides how the events are authenticated:

- ``verified``: a provider verifier (Stripe ``constructEvent``, Svix / Standard
  Webhooks ``verify``, Twilio ``validateRequest``, Slack's ``SignatureVerifier``,
  an SNS ``MessageValidator``…) or an HMAC checked with a constant-time compare.
- ``weak_compare``: an HMAC compared with ``==`` / ``===`` / ``bytes.Equal``,
  which leaks how much of a forged signature matched.
- ``no_replay_guard``: a scheme that signs a timestamp (Slack, Stripe, Svix)
  verified by hand without checking that timestamp, so a captured event can be
  replayed. Schemes without a signed timestamp (GitHub, Shopify, Twilio) aren't
  held to this: they have nothing to check it against.
- ``absent``: nothing in reach verifies the payload.
- ``unknown``: the handler couldn't be read, or verification code exists in
  the file that the handler doesn't visibly reach.

The result is set on ``AttackSurface.webhook_verification``. The webhook
findings, the attack path and the detection opportunity read it.
"""

from __future__ import annotations

import re
from pathlib import Path

from .authz import _HopResolver, _read_file_content
from .handler_span import span_bounds
from .models import AttackSurface, ScanResult, WebhookVerification
from .srcpaths import JS_TS_SUFFIXES

# --- provider verifiers ------------------------------------------------------

# A provider SDK call that verifies the signature (and, where the scheme signs
# one, the timestamp) — the handler needs nothing else.
_SDK_VERIFIERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "stripe",
        re.compile(
            r"\bconstructEvent(?:Async)?\s*\("  # stripe-node, stripe-php
            r"|\bWebhook\s*\.\s*construct_event\s*\("  # stripe-python
            r"|\bwebhook\s*\.\s*ConstructEvent\w*\s*\("  # stripe-go
        ),
    ),
    (
        "github",
        re.compile(r"\.\s*verifyAndReceive\s*\(|\bwebhooks\s*\.\s*verify\s*\(|\bcreateNodeMiddleware\s*\(\s*webhooks\b"),
    ),
    (
        "slack",
        re.compile(
            r"\bSignatureVerifier\s*\("  # slack_sdk
            r"|\.\s*is_valid_request\s*\("
            r"|\bNewSecretsVerifier\s*\("  # slack-go
            r"|\bverifySlackRequest\s*\("  # @slack/bolt helper
        ),
    ),
    (
        "twilio",
        re.compile(
            r"\bvalidateRequest(?:WithBody)?\s*\("
            r"|\btwilio\s*\.\s*webhook\s*\("
            r"|\bRequestValidator\s*\("
            r"|\bvalidate_twilio_request\b"
        ),
    ),
    ("shopify", re.compile(r"\bwebhooks\s*\.\s*validate\s*\(|\bshopify\w*\s*\.\s*validateHmac\s*\(")),
    ("sns", re.compile(r"\bMessageValidator\s*\(|\bSNSMessageValidator\b|\bvalidate_sns_message\s*\(")),
)

# Verifiers whose call is too generic to trust on its own (`wh.verify(...)`,
# `validator.validate(...)`): they count only when the library is imported.
_IMPORTED_VERIFIERS: tuple[tuple[str, re.Pattern[str], re.Pattern[str]], ...] = (
    (
        "svix",
        re.compile(r"""["'](?:svix|standardwebhooks)["']|\bfrom\s+(?:svix|standardwebhooks)\b|\bimport\s+(?:svix|standardwebhooks)\b"""),
        re.compile(r"\.\s*verify\s*\("),
    ),
    ("sns", re.compile(r"""["']sns-validator["']"""), re.compile(r"\.\s*validate\s*\(")),
)

# Provider, by the signature header the handler reads.
_SIGNATURE_HEADERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("github", re.compile(r"x-hub-signature", re.IGNORECASE)),
    ("slack", re.compile(r"x-slack-signature", re.IGNORECASE)),
    ("shopify", re.compile(r"x-shopify-hmac-sha256", re.IGNORECASE)),
    ("stripe", re.compile(r"stripe-signature", re.IGNORECASE)),
    ("svix", re.compile(r"(?:svix|webhook)-signature", re.IGNORECASE)),
    ("twilio", re.compile(r"x-twilio-signature", re.IGNORECASE)),
    ("hmac", re.compile(r"x-[\w-]*signature", re.IGNORECASE)),
)

# Schemes whose signature covers a timestamp the receiver must check.
_TIMESTAMPED = frozenset({"slack", "stripe", "svix"})

# --- manual HMAC -------------------------------------------------------------

_HMAC = re.compile(
    r"\bcreateHmac\s*\("
    r"|\bhmac\s*\.\s*(?:new|New|digest)\s*\("
    r"|\bhash_hmac\s*\("
    r"|\bOpenSSL::HMAC\b"
    r"|\bMac\s*\.\s*getInstance\s*\("
    r"|\bcrypto\s*\.\s*subtle\s*\.\s*(?:sign|importKey)\s*\("
)
_CONSTANT_TIME = re.compile(
    r"\btimingSafeEqual\s*\("
    r"|\bcompare_digest\s*\("
    r"|\bhmac\s*\.\s*Equal\s*\("
    r"|\bConstantTimeCompare\s*\("
    r"|\bhash_equals\s*\("
    r"|\bMessageDigest\s*\.\s*isEqual\s*\("
    r"|\bsecure_compare\s*\("
    r"|\b(?:safe|secure|constantTime)Compare\s*\("
    r"|\btsscmp\s*\("
    r"|\bcrypto\s*\.\s*subtle\s*\.\s*verify\s*\("
)
# A signature-ish operand on a line.
_SIG_WORD = re.compile(r"(?i:signature|digest|hmac|expected|computed|calculated)|\bsig(?![a-z])|Sig(?![a-z])")
# An equality test: `==`, `!=`, `===`, `!==` (not `<=`/`>=`/`=>`/`=`), or a
# non-constant-time equality call.
_EQUALITY = re.compile(r"(?<![<>=!])(?:===?|!==?)(?!=)|\bbytes\s*\.\s*Equal\s*\(|\.\s*equals\s*\(|\bstrcmp\s*\(")
# Presence tests aren't signature comparisons: `sig == null`, `sig !== undefined`,
# `signature == ""`, `x.length !== y.length`.
_PRESENCE = re.compile(
    r"[!=]==?\s*(?:null|undefined|None|nil|0)\b|[!=]==?\s*(?:''|\"\")|\blength\s*[!=]==?|\blen\s*\("
)

# --- replay protection -------------------------------------------------------

_REPLAY_GUARD = re.compile(
    r"\bDate\s*\.\s*now\s*\("
    r"|\bnew\s+Date\s*\(\s*\)"
    r"|\btime\s*\.\s*time\s*\("
    r"|\btime\s*\.\s*Now\s*\("
    r"|\btime\s*\.\s*Since\s*\("
    r"|\b(?:datetime|timezone)\s*\.\s*(?:now|utcnow)\s*\("
    r"|(?<![\w.$])time\s*\(\s*\)"  # PHP time()
    r"|\btolerance\b"
    r"|idempoten"
    r"|x-github-delivery"
    r"|\b(?:processed|seen)_?(?:events?|ids?|deliveries)\b",
    re.IGNORECASE,
)

# A signature over a re-serialized body, not the raw bytes that were signed.
_RESERIALIZED_BODY = re.compile(r"\bJSON\s*\.\s*stringify\s*\(\s*req\w*\s*\.\s*body\b|\bjson\s*\.\s*dumps\s*\(\s*request\b")

# JS middleware mounted for the whole app or a path: `app.use(verifySig)`,
# `router.use('/webhooks', verifyGithub)`.
_USE_LINE = re.compile(r"\.\s*use\s*\(")
_USE_PATH = re.compile(r"""\.\s*use\s*\(\s*["'`]([^"'`]*)["'`]""")

_COMMENT_LINE = re.compile(r"^\s*(?://|#|/?\*)")

_MUTATING = frozenset({"POST", "PUT", "PATCH", "DELETE", "ANY"})


class _Line:
    __slots__ = ("file", "line", "text")

    def __init__(self, file: str, line: int, text: str):
        self.file = file
        self.line = line
        self.text = text

    def where(self) -> str:
        return f"{self.file}:{self.line}"


def _lines_of(file: str, start: int, text: str) -> list[_Line]:
    return [
        _Line(file, start + i, t)
        for i, t in enumerate(text.splitlines())
        if t.strip() and not _COMMENT_LINE.match(t)
    ]


def _first(lines: list[_Line], pattern: re.Pattern[str]) -> _Line | None:
    return next((ln for ln in lines if pattern.search(ln.text)), None)


def _provider_by_header(lines: list[_Line]) -> str | None:
    for name, pattern in _SIGNATURE_HEADERS:
        if _first(lines, pattern):
            return name
    return None


def _weak_compare(lines: list[_Line]) -> _Line | None:
    for ln in lines:
        text = ln.text
        if _EQUALITY.search(text) and _SIG_WORD.search(text) and not _PRESENCE.search(text):
            return ln
    return None


def classify(lines: list[_Line], *, imported: frozenset[str] = frozenset()) -> WebhookVerification:
    """Decide the verification state from the lines a handler reaches.
    ``imported`` names the providers whose library the handler's files import."""
    for provider, pattern in _SDK_VERIFIERS:
        hit = _first(lines, pattern)
        if hit:
            return WebhookVerification(state="verified", provider=provider, evidence=hit.where())
    for provider, _, call in _IMPORTED_VERIFIERS:
        hit = _first(lines, call) if provider in imported else None
        if hit:
            return WebhookVerification(state="verified", provider=provider, evidence=hit.where())

    hmac = _first(lines, _HMAC)
    header_provider = _provider_by_header(lines)
    if hmac is None:
        if header_provider is not None:
            # The signature is read but handed to something we can't see.
            hit = _first(lines, dict(_SIGNATURE_HEADERS)[header_provider])
            return WebhookVerification(
                state="unknown",
                provider=header_provider,
                evidence=hit.where() if hit else None,
                notes=["the signature header is read, but no verification was found in reach"],
            )
        return WebhookVerification(state="absent")

    provider = header_provider or "hmac"
    notes: list[str] = []
    reserialized = _first(lines, _RESERIALIZED_BODY)
    if reserialized:
        notes.append(
            f"the signature is computed over a re-serialized body at {reserialized.where()}, "
            "not the raw request bytes; verification will fail on valid events"
        )
    replay_guarded = _first(lines, _REPLAY_GUARD) is not None
    if provider in _TIMESTAMPED and not replay_guarded:
        notes.append("the signed timestamp is never checked against the current time")

    good = _first(lines, _CONSTANT_TIME)
    if good is None:
        weak = _weak_compare(lines)
        if weak is not None:
            return WebhookVerification(state="weak_compare", provider=provider, evidence=weak.where(), notes=notes)
        return WebhookVerification(
            state="unknown",
            provider=provider,
            evidence=hmac.where(),
            notes=[*notes, "an HMAC is computed, but no comparison was found in reach"],
        )
    if provider in _TIMESTAMPED and not replay_guarded:
        return WebhookVerification(state="no_replay_guard", provider=provider, evidence=good.where(), notes=notes)
    return WebhookVerification(state="verified", provider=provider, evidence=good.where(), notes=notes)


class _Assessor:
    def __init__(self, scan: ScanResult, root: Path):
        self.root = root
        self.cache: dict[str, str | None] = {}
        self.hop = _HopResolver(root, self.cache)
        self.route_lines: dict[str, list[int]] = {}
        for r in scan.routes:
            if r.line is not None:
                self.route_lines.setdefault(r.file, []).append(r.line)

    def assess(self, surface: AttackSurface) -> WebhookVerification:
        content = _read_file_content(surface.file, self.root, self.cache)
        if not content:
            return WebhookVerification(state="unknown", notes=["the handler's source could not be read"])
        file_lines = content.splitlines()
        if surface.line is not None:
            start, end = span_bounds(surface.line, file_lines, self.route_lines.get(surface.file, []))
        else:
            start, end = 0, len(file_lines)
        handler = "\n".join(file_lines[start:end])
        reach = _lines_of(surface.file, start + 1, handler)
        located: list[tuple[str, int, str]] = []
        self.hop.delegated_text(surface.file, content, handler, located)
        if Path(surface.file).suffix.lower() in JS_TS_SUFFIXES:
            for i, text in enumerate(file_lines):
                if (start <= i < end) or not _USE_LINE.search(text) or _COMMENT_LINE.match(text):
                    continue
                mount = _USE_PATH.search(text)
                if mount and not _mount_covers(mount.group(1), surface.route):
                    continue
                reach.append(_Line(surface.file, i + 1, text))
                self.hop.delegated_text(surface.file, content, text, located)
        for file, line, body in located:
            reach.extend(_lines_of(file, line, body))

        sources = [content, *(self.cache.get(f) or "" for f in {f for f, _, _ in located})]
        imported = frozenset(
            provider for provider, lib, _ in _IMPORTED_VERIFIERS if any(lib.search(text) for text in sources)
        )
        result = classify(reach, imported=imported)
        if result.state == "absent":
            # Verification code elsewhere in the file that we can't connect to
            # this handler (a decorator, a framework hook): don't call it absent.
            whole = _lines_of(surface.file, 1, content)
            if classify(whole, imported=imported).state != "absent":
                return WebhookVerification(
                    state="unknown",
                    notes=["verification code exists in the file but the handler doesn't visibly reach it"],
                )
            where = f"{surface.file}:{surface.line}" if surface.line is not None else surface.file
            result.evidence = where
        return result


def _mount_covers(mount: str, route: str) -> bool:
    mount = mount.rstrip("/")
    return not mount or route.startswith(mount) or "webhook" in mount.lower() or "hook" in mount.lower()


def assess_webhook_surfaces(scan: ScanResult, surfaces: list[AttackSurface], root: str | Path | None = None) -> None:
    """Set ``webhook_verification`` on every webhook surface, in place."""
    webhooks = [s for s in surfaces if s.category == "webhook"]
    if not webhooks:
        return
    assessor = _Assessor(scan, Path(root or scan.root).resolve())
    for surface in webhooks:
        surface.webhook_verification = assessor.assess(surface)


def is_mutating(surface: AttackSurface) -> bool:
    return surface.method.upper() in _MUTATING


def describe(surface: AttackSurface) -> str:
    """One evidence line: the route and what its verification state rests on."""
    v = surface.webhook_verification
    route = f"{surface.method} {surface.route} in {surface.location()}"
    if v is None or v.state == "unknown":
        detail = "; ".join(v.notes) if v is not None and v.notes else "verification could not be determined"
        return f"{route} — {detail}"
    provider = f"{v.provider} " if v.provider and v.provider != "hmac" else ""
    if v.state == "absent":
        return f"{route} — no signature verification found in the handler"
    if v.state == "weak_compare":
        return f"{route} — {provider}HMAC signature compared with a non-constant-time equality at {v.evidence}"
    if v.state == "no_replay_guard":
        return f"{route} — {provider}signature verified at {v.evidence}, but the signed timestamp is never checked"
    return f"{route} — {provider}signature verified at {v.evidence}"


__all__ = ["assess_webhook_surfaces", "classify", "describe", "is_mutating"]

