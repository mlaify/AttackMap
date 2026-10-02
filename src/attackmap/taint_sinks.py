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
_OPTIONAL = ("gate", "args", "when", "unless", "requires", "flags", "token_gate", "base_score", "note")
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
    )


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
