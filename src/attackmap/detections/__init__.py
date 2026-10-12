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

_ANGLE_PARAM = re.compile(r"<[^<>/]{1,80}>")
_COLON_PARAM = re.compile(r":[A-Za-z_][A-Za-z0-9_]{0,63}(?:\([^()/]{0,80}\))?\??")
_BRACE_PARAM = re.compile(r"\{[^{}/]{1,80}\}")
_BRACKET_PARAM = re.compile(r"\[{1,2}[^\[\]/]{1,80}\]{1,2}")
_PARAM_TOKEN = "\x00"
_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
MAX_ROUTE_CHARS = 160


def _tokenize_params(path: str) -> str:
    path = path[:MAX_ROUTE_CHARS]
    for pattern in (_ANGLE_PARAM, _BRACE_PARAM, _BRACKET_PARAM, _COLON_PARAM):
        path = pattern.sub(_PARAM_TOKEN, path)
    return path


def route_glob(path: str) -> str:
    """Sigma wildcard pattern for a route template: path parameters
    (``<id>``, ``:id``, ``{id}``, ``[id]``) become ``*``; literal ``?`` and
    ``\\`` are escaped. A ``*`` already in the route stays a wildcard."""
    tokenized = _tokenize_params(path or "/")
    escaped = tokenized.replace("\\", "\\\\").replace("?", "\\?")
    glob = escaped.replace(_PARAM_TOKEN, "*")
    return glob if glob.startswith(("/", "*")) else f"*{glob}"


def route_selector(path: str) -> tuple[str, str]:
    """``(field, value)`` matching the request path of a route on
    ``cs-uri-stem``: an exact path, ``|startswith`` when the only wildcard is
    a trailing parameter (pySigma prefers the modifier), else a wildcard."""
    glob = route_glob(path)
    head = glob[:-1]
    # `route_glob` never escapes `*`, so any `*` left in `head` is a wildcard.
    if glob.endswith("*") and head and "*" not in head:
        return "cs-uri-stem|startswith", head
    return "cs-uri-stem", glob


def route_example(path: str, value: str = "1001") -> str:
    """A concrete URI path that matches :func:`route_glob` (parameters and
    wildcards filled with ``value``)."""
    tokenized = _tokenize_params(path or "/").replace("*", _PARAM_TOKEN)
    example = tokenized.replace(_PARAM_TOKEN, value)
    return example if example.startswith("/") else f"/{example}"


def has_path_params(path: str) -> bool:
    return _PARAM_TOKEN in _tokenize_params(path or "")


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
    "route_glob",
    "route_selector",
    "rule_uuid",
    "sigma_method",
    "taxonomy_references",
    "taxonomy_tags",
    "template_data",
    "templates",
]
