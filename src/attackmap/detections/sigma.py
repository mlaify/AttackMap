"""Structural Sigma checks and a small event matcher (#251).

AttackMap generates Sigma rules but does not depend on pySigma. This module
holds what the generator and its tests need without it:

- :func:`sigma_problems` / :func:`correlation_problems` check a rule dict
  against the Sigma specification (required keys, value formats, tag syntax,
  and that the condition only names search identifiers the rule defines).
- :func:`sigma_matches` evaluates a rule against one flat or nested event, so
  each rule's ``test_events`` can be checked: positives must match, negatives
  must not. It supports the subset of Sigma the templates use: field maps and
  lists of maps, ``null``, wildcards, the ``contains`` / ``startswith`` /
  ``endswith`` / ``all`` / ``re`` / ``cidr`` modifiers, and conditions built
  from ``and`` / ``or`` / ``not`` / parentheses / ``1 of`` / ``all of``.
- :func:`correlation_fires` evaluates a ``value_count`` or ``event_count``
  correlation over a list of events (no time window: the caller passes the
  events of one window).

None of this raises on malformed input: problems are returned as strings and
an expression that can't be parsed simply doesn't match.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
import uuid
from typing import Any

STATUSES = ("stable", "test", "experimental", "deprecated", "unsupported")
LEVELS = ("informational", "low", "medium", "high", "critical")
MODIFIERS = frozenset({"contains", "startswith", "endswith", "all", "re", "cidr", "i", "exists"})
CORRELATION_TYPES = ("event_count", "value_count", "temporal", "temporal_ordered")

# Used with fullmatch only; the \A anchors keep a stray search() linear.
_TAG = re.compile(r"\A[a-z0-9_-]+\.[a-z0-9._-]+")
_ATTACK_TAG = re.compile(r"\Aattack\.[a-z0-9-]+(?:\.\d{3})?")
_CWE_TAG = re.compile(r"\Acwe\.\d{1,5}")
_DATE = re.compile(r"\A\d{4}-\d{2}-\d{2}")
_TIMESPAN = re.compile(r"\A\d{1,6}[smhdwMy]")
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9_]+")
_NAME = re.compile(r"\A[a-z0-9_]{1,128}")
# A condition token, or any other non-space character (which is an error).
_CONDITION_TOKEN = re.compile(r"[()]|[A-Za-z0-9_*]+|\S")
_WORDS = frozenset({"and", "or", "not", "of", "them", "1", "all"})
_MAX_CONDITION_TOKENS = 200


# ---------------------------------------------------------------- validation


def _is_uuid(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    return True


def _str_list(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(v, str) and v for v in value)


def _search_problems(name: str, search: object) -> list[str]:
    if isinstance(search, dict):
        maps = [search]
    elif isinstance(search, list) and search and all(isinstance(m, dict) for m in search):
        maps = search
    else:
        return [f"detection.{name} must be a field map or a list of field maps"]
    problems: list[str] = []
    for field_map in maps:
        if not field_map:
            problems.append(f"detection.{name} has an empty field map")
        for key, value in field_map.items():
            if not isinstance(key, str) or not key:
                problems.append(f"detection.{name} has a non-string field name")
                continue
            field, *mods = key.split("|")
            if not field:
                problems.append(f"detection.{name}: empty field name in {key!r}")
            unknown = [m for m in mods if m not in MODIFIERS]
            if unknown:
                problems.append(f"detection.{name}: unknown modifier(s) {unknown} in {key!r}")
            values = value if isinstance(value, list) else [value]
            if isinstance(value, list) and not value:
                problems.append(f"detection.{name}.{key} is an empty list")
            for v in values:
                if v is not None and not isinstance(v, (str, int, float, bool)):
                    problems.append(f"detection.{name}.{key} has a non-scalar value")
                    break
                if "re" in mods and isinstance(v, str):
                    try:
                        re.compile(v)
                    except re.error as exc:
                        problems.append(f"detection.{name}.{key}: regex does not compile ({exc})")
                if "cidr" in mods and isinstance(v, str):
                    try:
                        ipaddress.ip_network(v, strict=False)
                    except ValueError:
                        problems.append(f"detection.{name}.{key}: {v!r} is not a CIDR range")
    return problems


def sigma_problems(rule: object) -> list[str]:
    """Problems that make ``rule`` an invalid Sigma detection rule; empty when
    it is structurally valid."""
    if not isinstance(rule, dict):
        return ["rule is not a mapping"]
    problems: list[str] = []
    for key in ("title", "id", "status", "description", "author", "date", "logsource", "detection", "level"):
        if key not in rule:
            problems.append(f"missing required key {key!r}")
    title = rule.get("title")
    if "title" in rule and (not isinstance(title, str) or not title or len(title) > 256):
        problems.append("title must be a non-empty string of at most 256 characters")
    if "id" in rule and not _is_uuid(rule.get("id")):
        problems.append("id must be a UUID")
    if "name" in rule and not (isinstance(rule["name"], str) and _NAME.fullmatch(rule["name"])):
        problems.append("name must be lower-case letters, digits and underscores")
    if "status" in rule and rule.get("status") not in STATUSES:
        problems.append(f"status must be one of {STATUSES}")
    if "level" in rule and rule.get("level") not in LEVELS:
        problems.append(f"level must be one of {LEVELS}")
    for key in ("description", "author"):
        if key in rule and not (isinstance(rule[key], str) and rule[key]):
            problems.append(f"{key} must be a non-empty string")
    if "date" in rule and not (isinstance(rule["date"], str) and _DATE.fullmatch(rule["date"])):
        problems.append("date must be YYYY-MM-DD")
    for key in ("references", "falsepositives", "fields"):
        if key in rule and not _str_list(rule[key]):
            problems.append(f"{key} must be a list of non-empty strings")
    tags = rule.get("tags", [])
    if not _str_list(tags):
        problems.append("tags must be a list of strings")
    else:
        for tag in tags:
            if not _TAG.fullmatch(tag):
                problems.append(f"malformed tag {tag!r}")
            elif tag.startswith("attack.") and not _ATTACK_TAG.fullmatch(tag):
                problems.append(f"malformed ATT&CK tag {tag!r}")
            elif tag.startswith("cwe.") and not _CWE_TAG.fullmatch(tag):
                problems.append(f"malformed CWE tag {tag!r}")
    logsource = rule.get("logsource")
    if "logsource" in rule:
        if not isinstance(logsource, dict) or not any(logsource.get(k) for k in ("product", "service", "category")):
            problems.append("logsource needs at least one of product, service, category")
        elif not all(isinstance(v, str) and v for v in logsource.values()):
            problems.append("logsource values must be non-empty strings")
    detection = rule.get("detection")
    if "detection" in rule:
        problems += _detection_problems(detection)
    return problems


def _detection_problems(detection: object) -> list[str]:
    if not isinstance(detection, dict):
        return ["detection must be a mapping"]
    condition = detection.get("condition")
    searches = {k: v for k, v in detection.items() if k not in ("condition", "timeframe")}
    problems: list[str] = []
    if not searches:
        problems.append("detection defines no search identifiers")
    for name, search in searches.items():
        if not isinstance(name, str) or not _IDENTIFIER.fullmatch(name):
            problems.append(f"bad search identifier {name!r}")
            continue
        problems += _search_problems(name, search)
    conditions = condition if isinstance(condition, list) else [condition]
    if condition is None or not all(isinstance(c, str) and c.strip() for c in conditions):
        problems.append("detection.condition must be a non-empty string")
        return problems
    for text in conditions:
        names = _condition_names(text)
        if names is None:
            problems.append(f"condition {text!r} does not parse")
            continue
        for name in names:
            if "*" in name:
                if not any(fnmatch.fnmatchcase(s, name) for s in searches):
                    problems.append(f"condition pattern {name!r} matches no search identifier")
            elif name not in searches:
                problems.append(f"condition names undefined search identifier {name!r}")
    return problems


def correlation_problems(rule: object, base_rules: list[dict] | None = None) -> list[str]:
    """Problems with a Sigma correlation rule. ``base_rules`` are the rules it
    may reference (by ``name`` or ``id``)."""
    if not isinstance(rule, dict):
        return ["correlation rule is not a mapping"]
    problems: list[str] = []
    for key in ("title", "id", "status", "correlation"):
        if key not in rule:
            problems.append(f"missing required key {key!r}")
    if "id" in rule and not _is_uuid(rule.get("id")):
        problems.append("id must be a UUID")
    if "status" in rule and rule.get("status") not in STATUSES:
        problems.append(f"status must be one of {STATUSES}")
    if "level" in rule and rule.get("level") not in LEVELS:
        problems.append(f"level must be one of {LEVELS}")
    corr = rule.get("correlation")
    if not isinstance(corr, dict):
        return problems + ["correlation must be a mapping"]
    ctype = corr.get("type")
    if ctype not in CORRELATION_TYPES:
        problems.append(f"correlation.type must be one of {CORRELATION_TYPES}")
    refs = corr.get("rules")
    if not _str_list(refs):
        problems.append("correlation.rules must list the referenced rules")
    elif base_rules is not None:
        known = {r.get("name") for r in base_rules} | {r.get("id") for r in base_rules}
        problems += [f"correlation references unknown rule {ref!r}" for ref in refs if ref not in known]
    if "group-by" in corr and not _str_list(corr["group-by"]):
        problems.append("correlation.group-by must be a list of field names")
    if not (isinstance(corr.get("timespan"), str) and _TIMESPAN.fullmatch(corr["timespan"])):
        problems.append("correlation.timespan must look like 10m / 1h / 1d")
    cond = corr.get("condition")
    if ctype in ("event_count", "value_count"):
        ops = {"gt", "gte", "lt", "lte", "eq"}
        if not isinstance(cond, dict) or not ops & set(cond):
            problems.append("correlation.condition needs one of gt/gte/lt/lte/eq")
        elif not all(isinstance(cond[o], int) and not isinstance(cond[o], bool) for o in ops & set(cond)):
            problems.append("correlation.condition thresholds must be integers")
        if ctype == "value_count" and not (isinstance(cond, dict) and isinstance(cond.get("field"), str)):
            problems.append("value_count correlation.condition needs a field")
    return problems


# ---------------------------------------------------------------- condition


def _tokens(text: str) -> list[str] | None:
    out: list[str] = []
    for m in _CONDITION_TOKEN.finditer(text):
        token = m.group(0)
        if len(token) == 1 and not (token in "()" or token.isalnum() or token in "_*"):
            return None
        out.append(token)
        if len(out) > _MAX_CONDITION_TOKENS:
            return None
    return out


class _Parser:
    """Recursive-descent parser for the Sigma condition subset. Produces a
    nested tuple AST: ("and", a, b), ("or", a, b), ("not", a),
    ("of", "1"|"all", pattern), ("id", name)."""

    def __init__(self, tokens: list[str]) -> None:
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self) -> str | None:
        tok = self.peek()
        self.pos += 1
        return tok

    def parse(self) -> tuple | None:
        node = self.or_expr()
        return node if node is not None and self.peek() is None else None

    def or_expr(self) -> tuple | None:
        left = self.and_expr()
        while left is not None and self.peek() == "or":
            self.take()
            right = self.and_expr()
            left = ("or", left, right) if right is not None else None
        return left

    def and_expr(self) -> tuple | None:
        left = self.not_expr()
        while left is not None and self.peek() == "and":
            self.take()
            right = self.not_expr()
            left = ("and", left, right) if right is not None else None
        return left

    def not_expr(self) -> tuple | None:
        if self.peek() == "not":
            self.take()
            inner = self.not_expr()
            return ("not", inner) if inner is not None else None
        return self.atom()

    def atom(self) -> tuple | None:
        tok = self.take()
        if tok is None:
            return None
        if tok == "(":
            inner = self.or_expr()
            return inner if inner is not None and self.take() == ")" else None
        if tok in ("1", "all") and self.peek() == "of":
            self.take()
            target = self.take()
            if target is None or target in ("(", ")") or (target in _WORDS and target != "them"):
                return None
            return ("of", tok, target)
        if tok in _WORDS or tok == ")":
            return None
        return ("id", tok)


def _parse_condition(text: str) -> tuple | None:
    tokens = _tokens(text)
    if not tokens:
        return None
    return _Parser(tokens).parse()


def _condition_names(text: str) -> list[str] | None:
    """Search identifiers (and ``x*`` patterns) a condition refers to, or
    ``None`` when it doesn't parse. ``them`` refers to every identifier."""
    ast = _parse_condition(text)
    if ast is None:
        return None
    names: list[str] = []

    def walk(node: tuple) -> None:
        if node[0] == "id":
            names.append(node[1])
        elif node[0] == "of":
            if node[2] != "them":
                names.append(node[2])
        else:
            for child in node[1:]:
                walk(child)

    walk(ast)
    return names


# ---------------------------------------------------------------- matching


def _lookup(event: dict, field: str) -> Any:
    if field in event:
        return event[field]
    node: Any = event
    for part in field.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _value_matches(actual: Any, expected: Any, mods: list[str]) -> bool:
    if expected is None:
        return actual is None or actual == ""
    if actual is None:
        return False
    if "cidr" in mods:
        try:
            return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(str(expected), strict=False)
        except ValueError:
            return False
    if "re" in mods:
        try:
            return re.search(str(expected), str(actual)) is not None
        except re.error:
            return False
    if isinstance(expected, bool) or isinstance(actual, bool):
        return str(actual).lower() == str(expected).lower()
    if isinstance(expected, (int, float)) and not isinstance(expected, bool):
        try:
            return float(actual) == float(expected)
        except (TypeError, ValueError):
            return False
    pattern = str(expected).lower()
    text = str(actual).lower()
    if "contains" in mods:
        pattern = f"*{pattern}*"
    elif "startswith" in mods:
        pattern = f"{pattern}*"
    elif "endswith" in mods:
        pattern = f"*{pattern}"
    return _wildcard(text, pattern)


def _wildcard(text: str, pattern: str) -> bool:
    """Sigma wildcards: ``*`` any run, ``?`` one character, ``\\`` escapes."""
    parts: list[str] = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern) and pattern[i + 1] in "*?\\":
            parts.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        parts.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
        i += 1
    return re.fullmatch("".join(parts), text, re.DOTALL) is not None


def _field_map_matches(field_map: dict, event: dict) -> bool:
    for key, expected in field_map.items():
        field, *mods = str(key).split("|")
        actual = _lookup(event, field)
        if "exists" in mods:
            if (actual is not None) != bool(expected):
                return False
            continue
        values = expected if isinstance(expected, list) else [expected]
        if "all" in mods:
            if not all(_value_matches(actual, v, mods) for v in values):
                return False
        elif not any(_value_matches(actual, v, mods) for v in values):
            return False
    return True


def _search_matches(search: Any, event: dict) -> bool:
    if isinstance(search, dict):
        return _field_map_matches(search, event)
    if isinstance(search, list):
        return any(isinstance(m, dict) and _field_map_matches(m, event) for m in search)
    return False


def _eval(node: tuple, results: dict[str, bool]) -> bool:
    op = node[0]
    if op == "id":
        return results.get(node[1], False)
    if op == "not":
        return not _eval(node[1], results)
    if op == "and":
        return _eval(node[1], results) and _eval(node[2], results)
    if op == "or":
        return _eval(node[1], results) or _eval(node[2], results)
    # "of"
    quantifier, target = node[1], node[2]
    names = list(results) if target == "them" else [n for n in results if fnmatch.fnmatchcase(n, target)]
    if not names:
        return False
    hits = [results[n] for n in names]
    return all(hits) if quantifier == "all" else any(hits)


def sigma_matches(rule: dict, event: dict) -> bool:
    """Whether ``event`` satisfies ``rule``'s detection. Unparseable rules
    never match."""
    detection = rule.get("detection") if isinstance(rule, dict) else None
    if not isinstance(detection, dict) or not isinstance(event, dict):
        return False
    condition = detection.get("condition")
    conditions = condition if isinstance(condition, list) else [condition]
    results = {
        name: _search_matches(search, event)
        for name, search in detection.items()
        if name not in ("condition", "timeframe")
    }
    for text in conditions:
        if not isinstance(text, str):
            continue
        ast = _parse_condition(text)
        if ast is not None and _eval(ast, results):
            return True
    return False


def correlation_fires(correlation_rule: dict, base_rule: dict, events: list[dict]) -> bool:
    """Evaluate an ``event_count`` / ``value_count`` correlation over
    ``events`` (taken to fall in one ``timespan`` window)."""
    corr = correlation_rule.get("correlation") if isinstance(correlation_rule, dict) else None
    if not isinstance(corr, dict):
        return False
    cond = corr.get("condition") or {}
    group_by = corr.get("group-by") or []
    groups: dict[tuple, list[dict]] = {}
    for event in events:
        if sigma_matches(base_rule, event):
            key = tuple(_lookup(event, f) for f in group_by)
            groups.setdefault(key, []).append(event)
    for grouped in groups.values():
        if corr.get("type") == "value_count":
            count = len({_lookup(e, str(cond.get("field"))) for e in grouped})
        elif corr.get("type") == "event_count":
            count = len(grouped)
        else:
            return False
        if _threshold(count, cond):
            return True
    return False


def _threshold(count: int, cond: dict) -> bool:
    checks = {
        "gt": lambda n: count > n,
        "gte": lambda n: count >= n,
        "lt": lambda n: count < n,
        "lte": lambda n: count <= n,
        "eq": lambda n: count == n,
    }
    applied = [checks[op](cond[op]) for op in checks if isinstance(cond.get(op), int)]
    return bool(applied) and all(applied)


__all__ = [
    "correlation_fires",
    "correlation_problems",
    "sigma_matches",
    "sigma_problems",
]
