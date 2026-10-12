"""Deployable detection-rule templates (#251).

Each ``*.yml`` file next to this module holds Sigma rule templates keyed by
template id, plus the data the generator needs to fill them (payload markers
per rule id, provider signature headers). :func:`render_rule` fills a
template with a route, method, parameter and file and returns a structurally
valid Sigma rule (and, for templates that define one, a correlation rule)
with its log source, the fields it needs, false-positive notes and sample
positive/negative events.

Rule ids are deterministic: a UUIDv5 over the template id, the AttackMap rule
id and a per-instance key (method + route, or the file), so re-running a scan
yields the same Sigma ``id`` and SIEM imports update in place.
"""

from __future__ import annotations

import functools
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..taxonomy import attack_url, cwe_url, taxonomy_for

TEMPLATE_DIR = Path(__file__).parent
AUTHOR = "AttackMap"
STATUS = "experimental"
# Fixed namespace so rule ids are stable across machines and releases.
NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/mlaify/AttackMap/detections")

_PLACEHOLDER = re.compile(r"\$\{([a-z_][a-z0-9_]{0,40})\}")
_REQUIRED = ("date", "title", "description", "logsource", "detection", "falsepositives", "level", "test_events")


class TemplateError(ValueError):
    """A template file or entry is malformed, or a placeholder has no value."""


@dataclass
class RenderedRule:
    sigma: dict[str, Any]
    logsource: dict[str, str]
    fields_required: list[str]
    false_positive_notes: list[str]
    test_events: dict[str, list[dict[str, Any]]]
    correlation: dict[str, Any] | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@functools.lru_cache(maxsize=1)
def _library() -> tuple[dict[str, dict], dict[str, dict]]:
    templates: dict[str, dict] = {}
    data: dict[str, dict] = {}
    for path in sorted(TEMPLATE_DIR.glob("*.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(doc, dict):
            raise TemplateError(f"{path.name}: top level must be a mapping")
        for tid, tpl in (doc.get("templates") or {}).items():
            if tid in templates:
                raise TemplateError(f"{path.name}: duplicate template id {tid!r}")
            missing = [k for k in _REQUIRED if k not in tpl]
            if missing:
                raise TemplateError(f"{path.name}: template {tid!r} lacks {missing}")
            templates[tid] = tpl
        data[path.stem] = doc.get("data") or {}
    return templates, data


def templates() -> dict[str, dict]:
    """All templates, keyed by template id."""
    return _library()[0]


def template_data(name: str) -> dict:
    """The ``data:`` block of ``<name>.yml``."""
    return _library()[1].get(name, {})


def _fill(node: Any, params: dict[str, Any]) -> Any:
    """Substitute ``${name}`` placeholders. A string that is exactly one
    placeholder becomes the parameter's value (any type); otherwise values are
    interpolated as text, in one pass, so text from the scanned repository is
    never re-expanded. Mapping entries whose key or value fills to ``None``
    are dropped, as are ``None`` list items."""
    if isinstance(node, str):
        whole = _PLACEHOLDER.fullmatch(node)
        if whole:
            return _param(params, whole.group(1))
        return _PLACEHOLDER.sub(lambda m: str(_param(params, m.group(1))), node)
    if isinstance(node, dict):
        out: dict[Any, Any] = {}
        for key, value in node.items():
            k = _fill(key, params)
            v = _fill(value, params)
            if k is not None and v is not None:
                out[k] = v
        return out
    if isinstance(node, list):
        return [v for v in (_fill(item, params) for item in node) if v is not None]
    return node


def _param(params: dict[str, Any], name: str) -> Any:
    if name not in params:
        raise TemplateError(f"no value for placeholder ${{{name}}}")
    return params[name]


def rule_uuid(template_id: str, rule_id: str, key: str) -> str:
    return str(uuid.uuid5(NAMESPACE, f"{template_id}|{rule_id}|{key}"))


def taxonomy_tags(rule_ids: list[str]) -> list[str]:
    """Sigma tags for the rules' ATT&CK techniques (``attack.t1190``),
    deduplicated in order. CWE has no Sigma tag namespace (pySigma's
    namespace validator rejects ``cwe.*``), so CWEs go in ``references``."""
    tags: list[str] = []
    for rule_id in rule_ids:
        entry = taxonomy_for(rule_id)
        if entry is None:
            continue
        for tag in [f"attack.{t.lower()}" for t in entry.attack]:
            if tag not in tags:
                tags.append(tag)
    return tags


def taxonomy_references(rule_ids: list[str]) -> list[str]:
    refs: list[str] = []
    for rule_id in rule_ids:
        entry = taxonomy_for(rule_id)
        if entry is None:
            continue
        for ref in [cwe_url(c) for c in entry.cwe] + [attack_url(t) for t in entry.attack]:
            if ref not in refs:
                refs.append(ref)
    return refs


def render_rule(
    template_id: str,
    *,
    rule_ids: list[str],
    key: str,
    params: dict[str, Any],
    extra_falsepositives: list[str] | None = None,
) -> RenderedRule:
    """Fill ``template_id`` and assemble the Sigma rule. ``rule_ids`` are the
    AttackMap rules it detects (tags, references, the id hash); ``key``
    distinguishes instances of the same template and rule (method + route)."""
    try:
        tpl = templates()[template_id]
    except KeyError:
        raise TemplateError(f"unknown template {template_id!r}") from None
    filled = _fill({k: v for k, v in tpl.items() if k != "correlation"}, params)
    falsepositives = [*filled["falsepositives"], *(extra_falsepositives or [])]
    fields_required = [f for f in filled.get("fields_required", []) if isinstance(f, str) and f]
    logsource = {k: str(v) for k, v in filled["logsource"].items()}
    primary = rule_ids[0]
    sigma: dict[str, Any] = {"title": filled["title"], "id": rule_uuid(template_id, primary, key)}
    if filled.get("name"):
        sigma["name"] = filled["name"]
    sigma.update(
        {
            "status": STATUS,
            "description": " ".join(str(filled["description"]).split()),
            "references": taxonomy_references(rule_ids),
            "author": AUTHOR,
            "date": str(filled["date"]),
            "tags": taxonomy_tags(rule_ids),
            "logsource": logsource,
            "detection": filled["detection"],
            "fields": fields_required,
            "falsepositives": falsepositives,
            "level": filled["level"],
        }
    )
    if not sigma["references"]:
        del sigma["references"]
    correlation = None
    if "correlation" in tpl:
        correlation = _correlation(template_id, primary, key, sigma, _fill(tpl["correlation"], params))
    test_events = {
        "positive": list(filled["test_events"].get("positive", [])),
        "negative": list(filled["test_events"].get("negative", [])),
    }
    return RenderedRule(
        sigma=sigma,
        logsource=logsource,
        fields_required=fields_required,
        false_positive_notes=list(falsepositives) + (list(correlation["falsepositives"]) if correlation else []),
        test_events=test_events,
        correlation=correlation,
    )


def _correlation(template_id: str, rule_id: str, key: str, base: dict, spec: dict) -> dict[str, Any]:
    condition: dict[str, Any] = {"gte": int(spec["threshold"])}
    if spec.get("field"):
        condition["field"] = spec["field"]
    rule: dict[str, Any] = {
        "title": spec["title"],
        "id": rule_uuid(template_id, rule_id, f"{key}|correlation"),
        "status": STATUS,
        "description": " ".join(str(spec.get("description", "")).split()) or base["description"],
        **({"references": base["references"]} if "references" in base else {}),
        "author": AUTHOR,
        "date": base["date"],
        "tags": base["tags"],
        "correlation": {
            "type": spec["type"],
            "rules": [base.get("name") or base["id"]],
            "group-by": list(spec.get("group-by") or []),
            "timespan": spec["timespan"],
            "condition": condition,
            "generate": False,
        },
        "falsepositives": list(spec.get("falsepositives") or []),
        "level": spec.get("level", base["level"]),
    }
    return rule


# ---------------------------------------------------------------- routes

# In-segment parameter syntaxes: <id>, {id}, [id] / [[...path]], and `*`.
# `:name` counts only at the start of a segment (`/v1/things:batchGet` is a
# literal), optionally with a `(regex)` constraint and an optional-marker `?`.
_INLINE_PARAM = re.compile(r"<[^<>/]{1,80}>|\{[^{}/]{1,80}\}|\[{1,2}[^\[\]/]{1,80}\]{1,2}|\*+")
_COLON_HEAD = re.compile(r"\A:[A-Za-z_][A-Za-z0-9_]{0,63}(?:\([^()/]{0,80}\))?(\?)?")
_WORD = re.compile(r"[A-Za-z0-9]{2}")
_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
MAX_ROUTE_CHARS = 160
# Limits that keep generated regexes small and rules narrow.
MAX_ROUTE_PARAMS = 8
MAX_OPTIONAL_SEGMENTS = 2

_PARAM = "\x00"  # a parameter part inside a segment
_REST = "\x01"  # a final catch-all `*`


@dataclass(frozen=True)
class _Segment:
    parts: tuple[str, ...]  # literal strings and _PARAM / _REST markers
    optional: bool = False


@functools.lru_cache(maxsize=4096)
def _parse(path: str) -> tuple[_Segment, ...]:
    """Split a route template into segments of literal and parameter parts.
    Adjacent parameters merge into one; a `*` that ends the route is a
    catch-all (`_REST`), anywhere else it is one parameter."""
    raw = (path or "/").lstrip("/").split("/")
    segments: list[_Segment] = []
    for index, text in enumerate(raw):
        parts: list[str] = []
        optional = False
        head = _COLON_HEAD.match(text)
        if head:
            parts.append(_PARAM)
            optional = bool(head.group(1)) and head.end() == len(text)
            text = text[head.end():]
        pos = 0
        for match in _INLINE_PARAM.finditer(text):
            if match.start() > pos:
                parts.append(text[pos:match.start()])
            parts.append(_PARAM)
            pos = match.end()
        if pos < len(text):
            parts.append(text[pos:])
        merged: list[str] = []
        for part in parts:
            if part == _PARAM and merged and merged[-1] == _PARAM:
                continue
            merged.append(part)
        if index == len(raw) - 1 and merged and merged[-1] == _PARAM and text.endswith("*"):
            merged[-1] = _REST
        segments.append(_Segment(tuple(merged), optional))
    return tuple(segments)


def _is_marker(part: str) -> bool:
    return part in (_PARAM, _REST)


def _param_count(segments: tuple[_Segment, ...]) -> int:
    return sum(1 for seg in segments for part in seg.parts if _is_marker(part))


def has_path_params(path: str) -> bool:
    return _param_count(_parse(path or "")) > 0


def route_scopable(path: str) -> bool:
    """Whether a rule can be scoped to this route. Refused:

    - routes longer than ``MAX_ROUTE_CHARS`` (never truncated into a dead
      exact match) or with non-printable / non-ASCII characters;
    - parameterized routes without a literal word of at least two letters or
      digits (``/``, ``*``, ``/:id``, ``/:a.:b``, ``*.*``), whose rule would
      match nearly any request; an exact route needs one letter or digit;
    - routes with more than ``MAX_ROUTE_PARAMS`` parameters or
      ``MAX_OPTIONAL_SEGMENTS`` optional segments.
    """
    if not path or len(path) > MAX_ROUTE_CHARS or not path.isascii() or not path.isprintable():
        return False
    segments = _parse(path)
    literal = "".join(part for seg in segments for part in seg.parts if not _is_marker(part))
    params = _param_count(segments)
    if params == 0:
        return any(ch.isalnum() for ch in literal)
    return (
        _WORD.search(literal) is not None
        and params <= MAX_ROUTE_PARAMS
        and sum(seg.optional for seg in segments) <= MAX_OPTIONAL_SEGMENTS
    )


def regex_literal(text: str) -> str:
    """Escape every character outside ``[A-Za-z0-9_/-]``: safe in PCRE,
    Python, RE2 and Lucene-style regex dialects (which treat ``~ # & @ <
    > "`` as operators)."""
    return "".join(ch if (ch.isascii() and ch.isalnum()) or ch in "_/-" else "\\" + ch for ch in text)


def _segment_body(seg: _Segment) -> str:
    r"""One segment's regex. A parameter excludes `/` and the first character
    of the literal that follows it (`<a>.<b>` -> `[^/.]+\.[^/]+`), so no two
    pieces can match the same characters and matching stays linear. Only a
    final catch-all is `.*`."""
    out: list[str] = []
    for i, part in enumerate(seg.parts):
        if part == _REST:
            out.append(".*")
        elif part == _PARAM:
            nxt = seg.parts[i + 1] if i + 1 < len(seg.parts) else None
            stop = regex_literal(nxt[0]) if nxt and not _is_marker(nxt) else ""
            out.append(f"[^/{stop}]+")
        else:
            out.append(regex_literal(part))
    return "".join(out)


def _route_regex(path: str) -> str:
    """Unanchored regex body for a route (see `_segment_body`); optional
    segments become `(?:/...)?`."""
    out: list[str] = []
    for seg in _parse(path):
        body = "/" + _segment_body(seg)
        out.append(f"(?:{body})?" if seg.optional else body)
    return "".join(out)


def _sigma_literal(text: str) -> str:
    return text.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")


def route_glob(path: str) -> str:
    """Display form of a route: parameters become ``*``."""
    segs = ["".join("*" if _is_marker(p) else p for p in seg.parts) for seg in _parse(path or "/")]
    return "/" + "/".join(segs)


def route_selector(path: str) -> tuple[str, str] | None:
    """``(field, value)`` matching the request path of a route on
    ``cs-uri-stem``: the exact path when it has no parameters, otherwise a
    ``|re`` anchored at both ends in which each parameter matches within one
    segment and only a final ``*`` spans segments. ``None`` when the route
    can't be scoped (:func:`route_scopable`)."""
    if not route_scopable(path):
        return None
    if not has_path_params(path):
        value = path if path.startswith("/") else f"/{path}"
        return "cs-uri-stem", _sigma_literal(value)
    return "cs-uri-stem|re", f"^{_route_regex(path)}$"


def stem_selector(paths: list[str]) -> tuple[str, object] | None:
    """One ``cs-uri-stem`` selection for several routes: a list of exact
    paths, or one anchored alternation regex if any route has parameters.
    Unscopable routes are left out; ``None`` if none remain."""
    kept = [p for p in paths if route_scopable(p)]
    if not kept:
        return None
    if not any(has_path_params(p) for p in kept):
        return "cs-uri-stem", [_sigma_literal(p if p.startswith("/") else f"/{p}") for p in kept]
    return "cs-uri-stem|re", "^(?:" + "|".join(_route_regex(p) for p in kept) + ")$"


def route_example(path: str, value: str = "1001") -> str:
    """A concrete URI path that matches :func:`route_selector` (parameters
    and wildcards filled with ``value``, optional segments included)."""
    segs = ["".join(value if _is_marker(p) else p for p in seg.parts) for seg in _parse(path or "/")]
    return "/" + "/".join(segs)


def sigma_method(method: str | None) -> str | None:
    """The HTTP verb to match, or ``None`` (any verb) for ANY/ALL/RPC kinds."""
    upper = (method or "").upper()
    return upper if upper in _HTTP_METHODS else None


__all__ = [
    "RenderedRule",
    "TemplateError",
    "has_path_params",
    "render_rule",
    "route_example",
    "regex_literal",
    "route_glob",
    "route_scopable",
    "route_selector",
    "stem_selector",
    "rule_uuid",
    "sigma_method",
    "taxonomy_references",
    "taxonomy_tags",
    "template_data",
    "templates",
]
