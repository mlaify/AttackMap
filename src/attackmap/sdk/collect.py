"""Plugin helpers (#382, #384): O(1) first-wins dedup and the plugin's version."""

from __future__ import annotations

from collections.abc import Callable
from importlib.metadata import PackageNotFoundError, version

from ..recon_models import AuthHint, DatabaseHint, EntrypointHint, ExternalCall, FrameworkHint, Route, ScanResult, SecretHint

# Record type -> (ScanResult field, identity). The identities are the ones the
# official plugins dedup on: one route per (path, method, file), one hint per
# (name, file).
_KEYS: dict[type, tuple[str, Callable[[object], tuple]]] = {
    Route: ("routes", lambda r: (r.path, r.method, r.file)),
    DatabaseHint: ("databases", lambda d: (d.kind, d.file)),
    AuthHint: ("auth_hints", lambda h: (h.hint, h.file)),
    SecretHint: ("secret_hints", lambda h: (h.name, h.file)),
    ExternalCall: ("external_calls", lambda c: (c.target, c.file)),
    FrameworkHint: ("framework_hints", lambda h: (h.hint, h.file)),
    EntrypointHint: ("entrypoint_hints", lambda h: (h.hint, h.file)),
}


class SignalCollector:
    """Append records to ``result`` once per identity; the first one wins.

    ``add(Route(...))`` returns whether the record was new. Lookups are set
    based, so a plugin adding thousands of records stays linear (a scan of
    the result list per append is quadratic)::

        signals = SignalCollector(result)
        signals.add(Route(path="/users", method="GET", file=rel, line=12))
    """

    def __init__(self, result: ScanResult) -> None:
        self.result = result
        self._seen: dict[str, set[tuple]] = {
            field: {key(item) for item in getattr(result, field)} for field, key in _KEYS.values()
        }

    def add(self, record: object) -> bool:
        entry = _KEYS.get(type(record))
        if entry is None:
            raise TypeError(f"SignalCollector doesn't collect {type(record).__name__}")
        field, key = entry
        identity = key(record)
        if identity in self._seen[field]:
            return False
        self._seen[field].add(identity)
        getattr(self.result, field).append(record)
        return True


def plugin_version(distribution: str, default: str = "0+unknown") -> str:
    """The installed version of ``distribution`` (your plugin's PyPI name),
    for ``AnalyzerMetadata.version``, so it can't drift from ``pyproject.toml``.
    ``default`` when it isn't installed (running from a source tree)."""
    try:
        return version(distribution)
    except PackageNotFoundError:
        return default


__all__ = ["SignalCollector", "plugin_version"]
