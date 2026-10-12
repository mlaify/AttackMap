"""Declarative taint sink registry (#240).

Sinks live in ``taint_sinks.yaml`` next to this module — one entry per
signature with its kind, languages, regex, gate, dangerous argument(s) and a
**required** CWE id — and are loaded and validated once at import. The same
table feeds the taint pass (:mod:`attackmap.taint`), the per-kind labels and
exploitability base points, and the CWE of each sink.

Analyzer plugins contribute sinks through the ``attackmap.taint_sinks``
entry-point group (documented in :mod:`attackmap.sdk`). The entry point may
resolve to a list of entry dicts, a callable returning one, or a path to a
YAML file with a ``sinks:`` list. Plugin entries go through the same
validation; an invalid plugin entry is skipped with a warning rather than
failing the scan. Plugins can only use the kinds declared here — the findings,
taxonomy and exploitability tables are keyed on them.
"""

from __future__ import annotations

import functools
import re
import sys
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any, NamedTuple

import yaml

from .taint_flow import RECEIVER, REST
from .taint_sources import CSHARP, GO, JAVA, JS, PHP, PY, RUBY

REGISTRY_PATH = Path(__file__).with_name("taint_sinks.yaml")
PLUGIN_GROUP = "attackmap.taint_sinks"

LANGS: dict[str, str] = {
    "python": PY, "js": JS, "go": GO, "php": PHP, "java": JAVA, "csharp": CSHARP, "ruby": RUBY,
}
GATES = ("any", "tainted")
_ARG_WORDS: dict[str, tuple[int, ...] | None] = {"all": None, "receiver": RECEIVER, "rest": REST}
_FLAGS = {"ignorecase": re.IGNORECASE, "dotall": re.DOTALL}

_REQUIRED = ("id", "kind", "langs", "regex", "cwe")
_OPTIONAL = (
    "gate", "args", "when", "unless", "receiver_unless", "requires", "flags", "token_gate", "base_score", "note",
)
_ID_RE = re.compile(r"[a-z0-9]+(?:[-_.][a-z0-9]+)*")


class SinkRegistryError(ValueError):
    """A sink entry failed validation."""


class KindMeta(NamedTuple):
    label: str
    cwe: int
    base_score: int
    alias_of: str | None = None


class SinkSpec(NamedTuple):
    id: str
    kind: str
    pattern: re.Pattern[str]
    langs: frozenset[str]
    cwe: int
    gate: str = "any"
    args: tuple[int, ...] | None = (0,)
    when: re.Pattern[str] | None = None
    unless: re.Pattern[str] | None = None
    requires: re.Pattern[str] | None = None
    token_gate: bool = True
    base_score: int | None = None
    source: str = "core"
    receiver_unless: re.Pattern[str] | None = None


def _compile(value: Any, field: str, where: str, flags: int = 0) -> re.Pattern[str]:
    if not isinstance(value, str) or not value:
        raise SinkRegistryError(f"{where}: `{field}` must be a non-empty regex string")
    try:
        return re.compile(value, flags)
    except re.error as exc:
        raise SinkRegistryError(f"{where}: `{field}` does not compile: {exc}") from exc


def _cwe(value: Any, where: str) -> int:
    if isinstance(value, str) and value.upper().startswith("CWE-"):
        value = value[4:]
    try:
        n = int(value)
    except (TypeError, ValueError):
        n = 0
    if isinstance(value, bool) or n <= 0:
        raise SinkRegistryError(f"{where}: `cwe` must be a positive CWE id (e.g. 89 or 'CWE-89')")
    return n


def validate_sink_entry(
    entry: Any, kinds: dict[str, KindMeta] | None = None, *, source: str = "core"
) -> SinkSpec:
    """Validate one registry entry and compile it. Raises SinkRegistryError.

    Every sink must name a known ``kind``, at least one language, a compiling
    ``regex`` and a ``cwe`` — a sink without a CWE can't be tagged or mapped,
    so it is rejected outright."""
    kinds = KINDS if kinds is None else kinds
    if not isinstance(entry, dict):
        raise SinkRegistryError(f"{source}: sink entry must be a mapping, got {type(entry).__name__}")
    where = f"{source}: sink {entry.get('id', '<no id>')!r}"
    missing = [k for k in _REQUIRED if k not in entry]
    if missing:
        raise SinkRegistryError(f"{where}: missing required field(s) {', '.join(missing)}")
    unknown = sorted(set(entry) - set(_REQUIRED) - set(_OPTIONAL))
    if unknown:
        raise SinkRegistryError(f"{where}: unknown field(s) {', '.join(unknown)}")
    sid = entry["id"]
    if not isinstance(sid, str) or not _ID_RE.fullmatch(sid):
        raise SinkRegistryError(f"{where}: `id` must be a lowercase slug")
    kind = entry["kind"]
    if kind not in kinds:
        raise SinkRegistryError(f"{where}: unknown kind {kind!r} (known: {', '.join(sorted(kinds))})")
    langs = entry["langs"]
    if not isinstance(langs, list) or not langs or any(lang not in LANGS for lang in langs):
        raise SinkRegistryError(f"{where}: `langs` must be a non-empty list of {', '.join(LANGS)}")
    flags = 0
    for flag in entry.get("flags", []) or []:
        if flag not in _FLAGS:
            raise SinkRegistryError(f"{where}: unknown flag {flag!r}")
        flags |= _FLAGS[flag]
    gate = entry.get("gate", "any")
    if gate not in GATES:
        raise SinkRegistryError(f"{where}: `gate` must be one of {', '.join(GATES)}")
    raw_args = entry.get("args", [0])
    if isinstance(raw_args, str):
        if raw_args not in _ARG_WORDS:
            raise SinkRegistryError(f"{where}: `args` must be a list of ints or one of {', '.join(_ARG_WORDS)}")
        args = _ARG_WORDS[raw_args]
    elif isinstance(raw_args, list) and raw_args and all(isinstance(i, int) and not isinstance(i, bool) and i >= 0 for i in raw_args):
        args = tuple(raw_args)
    else:
        raise SinkRegistryError(f"{where}: `args` must be a non-empty list of argument indexes")
    token_gate = entry.get("token_gate", True)
    if not isinstance(token_gate, bool):
        raise SinkRegistryError(f"{where}: `token_gate` must be a boolean")
    base = entry.get("base_score")
    if base is not None and (not isinstance(base, int) or isinstance(base, bool) or not 0 <= base <= 100):
        raise SinkRegistryError(f"{where}: `base_score` must be an int in 0..100")
    return SinkSpec(
        id=sid,
        kind=kind,
        pattern=_compile(entry["regex"], "regex", where, flags),
        langs=frozenset(LANGS[lang] for lang in langs),
        cwe=_cwe(entry["cwe"], where),
        gate=gate,
        args=args,
        when=_compile(entry["when"], "when", where) if entry.get("when") else None,
        unless=_compile(entry["unless"], "unless", where) if entry.get("unless") else None,
        requires=_compile(entry["requires"], "requires", where) if entry.get("requires") else None,
        token_gate=token_gate,
        base_score=base,
        source=source,
        receiver_unless=(
            _compile(entry["receiver_unless"], "receiver_unless", where) if entry.get("receiver_unless") else None
        ),
    )


_RECEIVER_SCAN_LIMIT = 400
_ASSIGN_SCAN_LIMIT = 64
# How far back from the call `_assigned_value` looks for the receiver's
# assignment. A fixed window keeps a file with many calls linear.
_ASSIGN_WINDOW = 4000
_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]{0,63}")
_IDENT_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$")
_CLOSERS = {"(": ")", "[": "]", "{": "}"}
_QUOTES = frozenset("'\"`")


def call_receiver(content: str, dot: int) -> str:
    """The receiver of the method call whose `.` is at ``dot``, with every
    call's or subscript's arguments elided and whitespace dropped:
    `crypto.createHmac()` for `crypto.createHmac('sha256', k).update(x)`,
    across line breaks in a chain. Elision keeps a pattern anchored at the end
    (`…createHmac()$`) to the receiver's own calls, never to a call nested in
    an argument (`db.doc(crypto.createHash(…).digest())`). When the receiver
    is a bare name, the right-hand side of its nearest earlier declarator is
    appended (`h=crypto.createHash()`), so a pattern can see what the variable
    holds. Bounded: ``_RECEIVER_SCAN_LIMIT`` characters back for the receiver,
    ``_ASSIGN_WINDOW`` characters and ``_ASSIGN_SCAN_LIMIT`` mentions for the
    assignment."""
    lo = max(0, dot - _RECEIVER_SCAN_LIMIT)
    i = dot
    while i > lo and content[i - 1] in " \t\r\n":
        i -= 1
    end = i
    while i > lo:
        c = content[i - 1]
        if c in ")]":
            opener = "(" if c == ")" else "["
            depth = 0
            j = i - 1
            while j >= lo:
                if content[j] == c:
                    depth += 1
                elif content[j] == opener:
                    depth -= 1
                    if depth == 0:
                        break
                j -= 1
            if j < lo:
                break
            i = j
        elif c in _IDENT_CHARS or c == ".":
            i -= 1
        elif c in " \t\r\n":
            # Whitespace inside a chain only before a `.`: `crypto\n  .createHmac(…)`.
            k = i
            while k > lo and content[k - 1] in " \t\r\n":
                k -= 1
            if content[i] != "." and (k == 0 or content[k - 1] != "."):
                break
            i = k
        else:
            break
    receiver = content[i:end].strip()
    if _IDENT_RE.fullmatch(receiver):
        rhs = _assigned_value(content, receiver, i)
        if rhs:
            return f"{receiver}={_elide(rhs)}"
    return _elide(receiver)


def _elide(text: str) -> str:
    """``text`` with the contents of every top-level (), [] and {} group
    dropped (quotes respected) and whitespace removed."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in _CLOSERS:
            j = _group_end(text, i)
            out.append(c + _CLOSERS[c])
            i = j + 1
            continue
        if not c.isspace():
            out.append(c)
        i += 1
    return "".join(out)


def _group_end(text: str, start: int) -> int:
    """Index of the bracket closing the one at ``start`` (or the last index)."""
    depth = 0
    quote = ""
    i = start
    while i < len(text):
        c = text[i]
        if quote:
            if c == "\\":
                i += 1
            elif c == quote:
                quote = ""
        elif c in _QUOTES:
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return len(text) - 1


def _assigned_value(content: str, name: str, before: int) -> str:
    """The right-hand side of the nearest `name = …` declarator before
    ``before``: up to a top-level `,` or `;` or the end of the line, so
    `const User = require('m'), sig = crypto.createHmac(…)` gives `require('m')`
    for `User`."""
    floor = max(0, before - _ASSIGN_WINDOW)
    pos = before
    for _ in range(_ASSIGN_SCAN_LIMIT):
        pos = content.rfind(name, floor, pos)
        if pos < 0:
            return ""
        after = pos + len(name)
        if (pos > 0 and (content[pos - 1] in _IDENT_CHARS or content[pos - 1] == ".")) or (
            after < len(content) and content[after] in _IDENT_CHARS
        ):
            continue
        k = after
        while k < len(content) and content[k] in " \t":
            k += 1
        if content.startswith("=", k) and not content.startswith(("==", "=>"), k):
            return _declarator(content, k + 1)
    return ""


def _declarator(content: str, start: int) -> str:
    depth = 0
    quote = ""
    i = start
    stop = min(len(content), start + _RECEIVER_SCAN_LIMIT)
    while i < stop:
        c = content[i]
        if quote:
            if c == "\\":
                i += 1
            elif c == quote:
                quote = ""
            elif c == "\n":
                break
        elif c in _QUOTES:
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif depth <= 0 and c in ",;\n":
            break
        i += 1
    return content[start:i].strip()


def _load_kinds(data: dict) -> dict[str, KindMeta]:
    raw = data.get("kinds")
    if not isinstance(raw, dict) or not raw:
        raise SinkRegistryError("registry: `kinds` must be a non-empty mapping")
    out: dict[str, KindMeta] = {}
    for kind, meta in raw.items():
        where = f"registry: kind {kind!r}"
        if not isinstance(meta, dict) or not isinstance(meta.get("label"), str):
            raise SinkRegistryError(f"{where}: needs a `label`")
        out[kind] = KindMeta(
            label=meta["label"],
            cwe=_cwe(meta.get("cwe"), where),
            base_score=int(meta.get("base_score", 15)),
            alias_of=meta.get("alias_of"),
        )
    return out


def load_registry(path: Path = REGISTRY_PATH) -> tuple[dict[str, KindMeta], tuple[SinkSpec, ...]]:
    """Load and validate a registry file: ``(kinds, sinks)``."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SinkRegistryError(f"{path.name}: top level must be a mapping")
    kinds = _load_kinds(data)
    raw = data.get("sinks")
    if not isinstance(raw, list) or not raw:
        raise SinkRegistryError(f"{path.name}: `sinks` must be a non-empty list")
    sinks = tuple(validate_sink_entry(e, kinds, source=path.name) for e in raw)
    seen: set[str] = set()
    for s in sinks:
        if s.id in seen:
            raise SinkRegistryError(f"{path.name}: duplicate sink id {s.id!r}")
        seen.add(s.id)
    return kinds, sinks


KINDS, SINKS = load_registry()
SINK_KINDS: tuple[str, ...] = tuple(KINDS)


def kind_label(kind: str) -> str:
    meta = KINDS.get(kind)
    return meta.label if meta else kind


def kind_base_score(kind: str, default: int = 15) -> int:
    meta = KINDS.get(kind)
    return meta.base_score if meta else default


def canonical_kind(kind: str) -> str:
    """``dynamic_open`` is kept as a schema-compatible alias of
    ``path_traversal`` (#200); everything else maps to itself."""
    meta = KINDS.get(kind)
    return meta.alias_of if meta and meta.alias_of else kind


def _plugin_entries(ep_name: str, obj: Any) -> list[Any]:
    if callable(obj):
        obj = obj()
    if isinstance(obj, (str, Path)):
        data = yaml.safe_load(Path(obj).read_text(encoding="utf-8"))
        obj = data.get("sinks", []) if isinstance(data, dict) else data
    if not isinstance(obj, list):
        raise SinkRegistryError(f"plugin {ep_name}: expected a list of sink entries")
    return obj


def _warn(msg: str) -> None:
    print(f"attackmap: {msg}", file=sys.stderr)


@functools.lru_cache(maxsize=1)
def plugin_sinks() -> tuple[SinkSpec, ...]:
    """Sinks contributed by installed plugins (``attackmap.taint_sinks``
    entry points), validated; invalid entries are skipped with a warning."""
    out: list[SinkSpec] = []
    seen = {s.id for s in SINKS}
    try:
        eps = entry_points()
        candidates = list(eps.select(group=PLUGIN_GROUP)) if hasattr(eps, "select") else list(eps.get(PLUGIN_GROUP, ()))
    except Exception as exc:  # noqa: BLE001 - discovery must never break a scan
        _warn(f"taint sink plugin discovery failed: {exc}")
        return ()
    for ep in candidates:
        try:
            entries = _plugin_entries(ep.name, ep.load())
        except Exception as exc:  # noqa: BLE001
            _warn(f"taint sink plugin {ep.name!r} skipped: {exc}")
            continue
        for entry in entries:
            try:
                spec = validate_sink_entry(entry, source=f"plugin {ep.name}")
            except SinkRegistryError as exc:
                _warn(f"{exc} — skipped")
                continue
            if spec.id in seen:
                _warn(f"plugin {ep.name}: duplicate sink id {spec.id!r} — skipped")
                continue
            seen.add(spec.id)
            out.append(spec)
    return tuple(out)


def all_sinks() -> tuple[SinkSpec, ...]:
    """Core registry + plugin contributions."""
    return SINKS + plugin_sinks()
