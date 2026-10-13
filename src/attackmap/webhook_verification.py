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


# --- inbound receivers vs. webhook management (#365) -------------------------
#
# A path containing `webhook` is usually an inbound receiver, but apps that send
# webhooks also expose CRUD for their own webhook configuration
# (`/settings/webhooks`, `/v2/webhooks/:webhookId`, a DRF `WebhookViewSet`).
# Those are ordinary application routes, not receivers of provider events.
# Precision first: a route is management only on a structural signal, and a
# candidate whose handler reaches signature verification stays a receiver.

_WEBHOOK_SEGMENT = re.compile(r"web-?hooks?", re.IGNORECASE)
# A route parameter in any framework's syntax: `{id}`, `:id`, `<int:pk>`, `[id]`, `(?P<id>…)`.
_PARAM_SEGMENT = re.compile(r"^(?:\{([^{}]*)\}|:([\w-]+)\??|<(?:[\w]+:)?([^<>]*)>|\[{1,2}(?:\.\.\.)?([^\[\]]*)\]{1,2}|\(\?P<([\w]+)>.*\))$")
# Parameter names that identify a stored record (a webhook's own id), as opposed
# to a provider name (`:provider`, `[source]`) that routes inbound events.
_ID_PARAM = re.compile(r"^(?:id|pk|uuid|hook|webhook|webhook_?id|webhook_?uuid|\w*(?:Id|_id|ID|Uuid|_uuid|_pk))$")
# An id that scopes a tenant, not a stored webhook: `/webhooks/:accountId` may
# route a provider's events to a tenant.
_TENANT_PARAM = re.compile(
    r"^(?:account|tenant|org|organization|organisation|workspace|team|project|user|customer|shop|store|site"
    r"|merchant|app|application|client|company|integration|installation|instance|space|channel|provider|source)"
    r"_?(?:id|uuid|key|slug)?$",
    re.IGNORECASE,
)
# Guards that are a user or session login, as opposed to a shared secret,
# signature or token header a plugin may also declare `required`.
_USER_GUARD = re.compile(r"(?i)session|login|user|jwt|permission|role|admin|member|apiauth|authenticated|isauth|auth_?required|login_?required")
_SECRET_GUARD = re.compile(r"(?i)webhook|signature|secret|hmac|token|api_?key|svix|stripe|github|slack|twilio|shopify|verif|sig\b|basic")
# A receiver's subscription handshake: Meta/WhatsApp `hub.challenge`, Twitter `crc_token`.
_HANDSHAKE = re.compile(r"hub[._]challenge|hub[._]mode|hub[._]verify_token|crc_token")
_ID_CONVERTERS = re.compile(r"^<(?:int|uuid|pk):", re.IGNORECASE)
# Words that, fused with `webhook` in one segment, name a management page or
# sub-resource: `add_webhook`, `webhooklogs`, `edit-webhook`.
# Fused with `webhook` in one segment, only words that can't be an inbound
# event name: `webhooklogs`, `add_webhook`, `webhook_settings`, `edit-webhook`.
# Event-ish words (`subscription-webhook`, `new-order-webhook`,
# `update-webhook`, `delivery_webhook`) stay receivers, and a POST never counts.
_MANAGEMENT_WORDS = frozenset({"add", "edit", "delete", "list", "log", "logs", "setting", "settings"})
# Actions on a stored webhook (`POST /webhooks/:id/test`). A POST to
# `/webhooks/:id[/:token]` without one may be an incoming-webhook receiver
# (Discord/Slack style, authenticated by the id/token in the URL), so it isn't
# management on the id alone.
_MANAGEMENT_ACTIONS = frozenset(
    {
        "test", "ping", "redeliver", "redeliveries", "deliveries", "logs", "rotate", "secret", "enable",
        "disable", "edit", "delete", "retry", "resend", "links", "folders", "attempts", "history",
    }
)
_READ_WRITE_METHODS = frozenset({"GET", "HEAD", "PUT", "PATCH", "DELETE"})
_SETTINGS_SEGMENTS = frozenset({"settings", "preferences"})
# CRUD actions in a settings path: `POST /settings/webhooks/create`.
_CRUD_ACTIONS = frozenset({"create", "new", "store", "edit", "update", "delete", "destroy"})
# `router.register(r"webhooks", WebhookViewSet)`: group 1 the prefix, group 2 the ViewSet.
_DRF_VIEWSET_REGISTRATION = re.compile(
    r"""\.register\(\s*r?["']([^"'\n]{0,200})["']\s*,\s*([\w.]{1,120})"""
)
_PY_CLASS_BASES = r"^[ \t]*class[ \t]+{name}[ \t]*\(([^)\n]{{0,400}})\)"
# A POST that creates a stored webhook: the handler persists a target URL with
# a secret or event list (`subscriberUrl`, `payload_url`, `events`, `secret`).
_CONFIG_URL_FIELD = re.compile(r"(?i:subscriber_?url|payload_?url|target_?url|callback_?url|endpoint_?url)|\burl\s*[:=]")
_CONFIG_OTHER_FIELD = re.compile(r"\b(?:secret|events|event_?types|eventTriggers|active)\b")
_PERSIST_CALL = re.compile(r"\b(?:create|save|insert|upsert|persist|add)\w{0,40}\s*\(|\.objects\.create\s*\(")


def _segments(path: str) -> list[str]:
    return [seg for seg in path.split("?", 1)[0].strip("/").split("/") if seg]


def _param_name(segment: str) -> str | None:
    match = _PARAM_SEGMENT.match(segment)
    if match is None:
        return None
    return next((g for g in match.groups() if g is not None), "")


def _is_id_param(segment: str) -> bool:
    name = _param_name(segment)
    if name is None:
        return False
    bare = name.split(":", 1)[-1].strip()
    if _TENANT_PARAM.match(bare):
        return False
    if _ID_CONVERTERS.match(segment):
        return True
    return _ID_PARAM.match(bare) is not None


def _drf_model_viewset(base: Path, cache: dict[str, str | None], hop: _HopResolver, route, line: str) -> bool:  # noqa: ANN001
    """`router.register('webhooks', WebhookViewSet)` where the prefix names the
    webhook collection itself (not a provider: `webhooks/stripe`) and the
    ViewSet is model CRUD (`ModelViewSet`, `NetBoxModelViewSet`, `ModelCrudViewSet`)."""
    match = _DRF_VIEWSET_REGISTRATION.search(line)
    if match is None:
        return False
    prefix = [seg.lower() for seg in match.group(1).strip("^$/").split("/") if seg]
    if not prefix or not _WEBHOOK_SEGMENT.fullmatch(prefix[-1].replace("logs", "").replace("log", "") or "x"):
        return False
    ref = match.group(2)
    module_name, _, class_name = ref.rpartition(".")
    content = _read_file_content(route.file, base, cache) or ""
    candidates = [route.file]
    imports = hop._import_map(route.file, content)
    if module_name and module_name in imports:
        candidates = [imports[module_name]]
    elif class_name in imports:
        candidates = [imports[class_name], route.file]
    pattern = re.compile(_PY_CLASS_BASES.format(name=re.escape(class_name)), re.MULTILINE)
    for module in candidates:
        source = _read_file_content(module, base, cache) or ""
        found = pattern.search(source)
        if found:
            bases = [b.strip().rsplit(".", 1)[-1] for b in found.group(1).split(",")]
            return any("Model" in b and b.endswith("ViewSet") for b in bases)
    return False


def _handler_text(base: Path, cache: dict[str, str | None], route, route_lines: list[int]) -> str:  # noqa: ANN001
    content = _read_file_content(route.file, base, cache) or ""
    lines = content.splitlines()
    if route.line is None or not lines:
        return ""
    start, end = span_bounds(route.line, lines, route_lines)
    return "\n".join(lines[start:end])


def _persists_webhook_config(text: str) -> bool:
    return bool(_CONFIG_URL_FIELD.search(text) and _CONFIG_OTHER_FIELD.search(text) and _PERSIST_CALL.search(text))


def _fused_management_word(segment: str) -> bool:
    rest = _WEBHOOK_SEGMENT.sub(" ", segment.lower())
    words = [w for w in re.split(r"[\s_\-.]+", rest) if w]
    return bool(words) and any(w in _MANAGEMENT_WORDS for w in words)


def _member_management(method: str, segs: list[str], hook: int, *, collection_known: bool) -> str | None:
    """`/…/webhooks/:webhookId[/…]`: a stored webhook addressed by id.
    ``"strong"`` when it is read or deleted (GET/HEAD/DELETE), acted on
    (`POST …/:id/test`), or a method-less bare member of a known collection;
    ``"weak"`` for a PUT/PATCH, which needs other evidence; else None."""
    if hook + 1 >= len(segs) or not _is_id_param(segs[hook + 1]):
        return None
    tail = [s.lower() for s in segs[hook + 2 :]]
    if any(word in _MANAGEMENT_ACTIONS for word in tail if _param_name(word) is None):
        return "strong"
    if method in {"GET", "HEAD", "DELETE"}:
        return "strong"
    if method in {"PUT", "PATCH"}:
        return "weak"
    return "strong" if method == "ANY" and not tail and collection_known else None


def _user_authenticated(route) -> bool:  # noqa: ANN001
    """Required auth by a user/session guard. A plugin may also declare a
    shared-secret or signature check `required`; that proves nothing here."""
    if route.auth != "required" or not route.guards:
        return False
    return all(not _SECRET_GUARD.search(g) for g in route.guards) and any(_USER_GUARD.search(g) for g in route.guards)


def _route_line(root: Path, cache: dict[str, str | None], route) -> str:  # noqa: ANN001
    if route.line is None:
        return ""
    content = _read_file_content(route.file, root, cache) or ""
    lines = content.splitlines()
    return lines[route.line - 1] if 0 < route.line <= len(lines) else ""


def webhook_management_routes(scan: ScanResult, root: str | Path | None = None) -> dict[tuple[str, str, str], str]:
    """Routes whose path names webhooks but which manage the app's own webhook
    configuration, keyed ``(method, path, file)`` → the reason."""
    base = Path(root or scan.root).resolve()
    cache: dict[str, str | None] = {}
    out: dict[tuple[str, str, str], str] = {}
    # Collections that have an id-addressed member somewhere: `/v2/webhooks`
    # when `/v2/webhooks/:webhookId` exists.
    collections: set[str] = set()
    # Members (`/webhooks/:id`) that something reads, deletes or acts on.
    members_read: set[str] = set()
    member_reads: list[tuple[str, object]] = []
    parsed = []
    for route in scan.routes:
        segs = _segments(route.path)
        hook = next((i for i, seg in enumerate(segs) if _WEBHOOK_SEGMENT.search(seg)), None)
        parsed.append((route, segs, hook))
        if hook is not None and _member_management(route.method.upper(), segs, hook, collection_known=True) == "strong":
            collections.add("/".join(s.lower() for s in segs[: hook + 1]))
            member_reads.append(("/".join(s.lower() for s in segs[: hook + 2]), route))
    collections_paths = {"/".join(s.lower() for s in segs) for _, segs, hook in parsed if hook is not None and hook + 1 == len(segs)}
    hop = _HopResolver(base, cache)
    route_lines: dict[str, list[int]] = {}
    for r in scan.routes:
        if r.line is not None:
            route_lines.setdefault(r.file, []).append(r.line)
    for member, route in member_reads:
        # A receiver's subscription handshake (`hub.challenge`, `crc_token`)
        # on the member is no evidence that the member is managed.
        if route.method.upper() in {"GET", "HEAD", "ANY"} and _HANDSHAKE.search(
            _handler_text(base, cache, route, route_lines.get(route.file, []))
        ):
            continue
        members_read.add(member)
    for route, segs, hook in parsed:
        if hook is None:
            continue
        method = route.method.upper()
        lowered = [s.lower() for s in segs]
        after = lowered[hook + 1 :]
        authenticated = _user_authenticated(route)
        reason = None
        if any(s in _SETTINGS_SEGMENTS for s in lowered[:hook]) and (
            method in _READ_WRITE_METHODS
            or any(s in _CRUD_ACTIONS for s in after)
            or (after and _is_id_param(segs[hook + 1]))
            or authenticated
        ):
            # `POST /settings/integrations/slack/webhook` stays a receiver.
            reason = "a settings page for the app's webhooks"
        elif "trpc" in lowered[:hook]:
            reason = "a tRPC procedure endpoint"
        elif method != "POST" and _fused_management_word(segs[hook]):
            reason = f"`{segs[hook]}` names a management page"
        elif (
            member := _member_management(
                method, segs, hook, collection_known="/".join(lowered[: hook + 1]) in collections_paths
            )
        ) is not None:
            if member == "strong":
                reason = f"`{segs[hook + 1]}` addresses a stored webhook"
            elif (
                "/".join(lowered[: hook + 2]) in members_read
                or authenticated
                or _persists_webhook_config(_handler_text(base, cache, route, route_lines.get(route.file, [])))
            ):
                # A PUT/PATCH alone isn't management: a provider may PUT events.
                reason = f"`{segs[hook + 1]}` updates a stored webhook"
        elif hook + 1 == len(segs) and "/".join(lowered) in collections:
            # The collection of id-addressed webhooks. Listing it is management;
            # a POST (or a method-less route) may be a receiver beside an
            # event log, so it needs positive evidence.
            if method in _READ_WRITE_METHODS:
                reason = "the collection of a webhook resource with id-addressed members"
            elif authenticated:
                reason = "an authenticated create on a webhook collection"
            elif _persists_webhook_config(_handler_text(base, cache, route, route_lines.get(route.file, []))):
                reason = "a create that persists a webhook's URL and settings"
        if reason is None and _drf_model_viewset(base, cache, hop, route, _route_line(base, cache, route)):
            reason = "a model CRUD ViewSet over the app's webhooks"
        if reason is not None and method in {"GET", "HEAD", "ANY"} and _HANDSHAKE.search(
            _handler_text(base, cache, route, route_lines.get(route.file, []))
        ):
            reason = None  # a receiver's subscription handshake (`hub.challenge`, `crc_token`)
        if reason is not None:
            out[(route.method, route.path, route.file)] = reason
    return out


def reclaim_receivers(scan: ScanResult, candidates: list[AttackSurface], root: str | Path | None = None) -> list[AttackSurface]:
    """Of the management candidates, the ones whose handler reaches signature
    verification after all: those are receivers and stay webhooks."""
    if not candidates:
        return []
    assessor = _Assessor(scan, Path(root or scan.root).resolve())
    reclaimed = []
    for surface in candidates:
        result = assessor.assess(surface)
        if result.state != "absent" and "the handler's source could not be read" not in result.notes:
            reclaimed.append(surface)
    return reclaimed


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


__all__ = [
    "assess_webhook_surfaces",
    "classify",
    "describe",
    "is_mutating",
    "reclaim_receivers",
    "webhook_management_routes",
]

