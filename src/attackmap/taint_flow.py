"""Intra-procedural def-use taint propagation (#239).

The import-graph walk in :mod:`attackmap.taint` decides *which* sinks a route
can reach. This module decides, for one sink call, whether a request-derived
value actually flows into the dangerous argument **inside the enclosing
function**, so the overwhelmingly common two-line shape is caught::

    target = request.args.get("url")     # source
    r = requests.get(target, timeout=3)  # sink — fires, source_line = 1st line

How it works:

- **Enclosing function.** Python via the stdlib ``ast``; JS/TS, Go, PHP and
  Java via a single linear brace-balance pass over the file with string
  literals and comments blanked out (interpolations such as ``${x}`` and PHP
  ``"$x"`` are kept, because they carry data).
- **Def-use map.** Simple assignments in source order — ``x = <expr>``,
  tuple targets, JS destructuring (``const {u} = req.query``), Go ``:=`` and
  ``&out`` decode targets, PHP ``$x = …`` / ``.=``, Java ``Type x = …`` — plus
  container mutators (``parts.append(x)``). A variable is tainted when its
  right-hand side matches the per-language source catalog
  (:mod:`attackmap.taint_sources`) or references a tainted variable, so taint
  follows f-strings, ``+``, ``.format``, ``%``, ``path.join`` and any other
  expression to the sink. Framework-bound handler parameters (Flask/FastAPI
  route params, Spring ``@RequestParam``, NestJS ``@Query()``) are sources.
- **Argument-aware sinks.** Only the dangerous argument counts: the URL of an
  HTTP call (not its JSON body), the query of an ``execute`` (not its bound
  params). A URL whose literal prefix pins scheme and host
  (``f"https://api.example.com/{id}"``) is not SSRF.
- **Flow-bound sanitizers.** A sanitizer counts only when the tainted value
  passes through it on the way to the sink (``u = secure_filename(u)``), and a
  guard only when it checks a value derived from the same source and dominates
  the sink — an early exit before it (``if ip.is_private: abort(400)``) or an
  ``if`` that encloses it. Nothing is file-granular any more.

Documented limits (precision-first, heuristic — evidence, not proof):

- **Intra-procedural only.** Taint does not cross a call boundary: a value
  passed to a helper that runs the sink is not followed into the helper (the
  helper's own parameters are treated as *unknown*, never as request input).
  Cross-file reach is still the file-granular import walk in ``taint.py``;
  there is no function-level call graph. Cross-repo taint is #196.
- **Flow-insensitive within a function.** Assignments are replayed in source
  order up to the sink; branches are not distinguished, loops are a single
  pass, and a guard's polarity (``if ok`` vs ``if not ok``) is not checked —
  an early-exit or enclosing ``if`` on a derived value counts as a guard.
- **Only simple names propagate.** Attribute stores (``self.x = …``,
  ``obj.prop = …``), aliasing through containers other than the listed
  mutators, closures, generators and ``global`` state are not tracked.
- **Regex languages are approximate.** JS/Go/PHP/Java use a brace-balance pass,
  not a parser: braceless arrow bodies, heredocs, regex literals containing
  braces, and statements split across lines without a trailing operator can
  be mis-scoped. When the enclosing function can't be found the caller falls
  back to the legacy same-call request-token gate.
- **Raising validators are not guards.** A bare ``validate_url(u)`` statement
  that raises on bad input is not recognized; only ``if``/``assert`` checks.
"""

from __future__ import annotations

import ast
import bisect
import re
from dataclasses import dataclass, field

from .srcpaths import line_number
from .taint_sources import (
    ALL_SANITIZER_KINDS,
    CAST_SANITIZERS,
    EARLY_EXIT,
    GO,
    JAVA,
    JS,
    PARAM_ANNOTATIONS,
    PHP,
    PY,
    PY_PLUMBING_PARAMS,
    PY_ROUTE_DECORATOR_NAMES,
    PY_SAFE_ANNOTATION,
    PY_SAFE_DEFAULT,
    PY_SCALAR_ANNOTATION,
    SANITIZERS,
    SOURCES,
    guard_patterns,
    lang_for_suffix,
)

_MAX_STEPS = 8          # flow steps kept per value
_MAX_ATOMS = 6          # distinct sources tracked per variable
_MAX_RHS = 1500         # chars scanned for one right-hand side
_MAX_ARGS = 4000        # chars scanned for one sink call's arguments
_MAX_HEADER = 600       # chars scanned back for a block's header
_MAX_EVAL_DEPTH = 60    # Python expression recursion bound

Step = tuple[int, str, str]  # (line, kind, note); kind: source|propagation|sanitizer|guard|sink

# `args_spec` value meaning "the call's receiver" (`url.openStream()`).
RECEIVER: tuple[int, ...] = (-1,)


@dataclass(frozen=True)
class Atom:
    """One source-derived value: where it came from, the steps it took, and
    the sink kinds a sanitizer/guard on its path has neutralized."""

    kind: str
    line: int
    weight: str  # "high" (request input) | "low" (env/argv) | "param" (unknown helper arg)
    label: str
    sanitized: tuple[tuple[str, str], ...] = ()  # (sink_kind, sanitizer label)
    steps: tuple[Step, ...] = ()

    @property
    def ident(self) -> tuple[str, int, str]:
        return (self.kind, self.line, self.label)

    def sanitizer_for(self, kind: str) -> str | None:
        for k, label in self.sanitized:
            if k == kind:
                return label
        return None

    def with_step(self, line: int, kind: str, note: str) -> "Atom":
        steps = self.steps
        if len(steps) < _MAX_STEPS and (not steps or steps[-1][:2] != (line, kind)):
            steps = steps + ((line, kind, note[:120]),)
        return Atom(self.kind, self.line, self.weight, self.label, self.sanitized, steps)

    def with_sanitizer(self, kinds: frozenset[str] | tuple[str, ...], label: str, line: int, step_kind: str = "sanitizer") -> "Atom":
        have = {k for k, _ in self.sanitized}
        add = tuple((k, label) for k in kinds if k not in have)
        if not add:
            return self
        a = Atom(self.kind, self.line, self.weight, self.label, self.sanitized + add, self.steps)
        return a.with_step(line, step_kind, label)


def _dedupe(atoms: list[Atom]) -> list[Atom]:
    seen: set[tuple] = set()
    out: list[Atom] = []
    for a in atoms:
        key = (a.ident, a.sanitized)
        if key in seen:
            continue
        seen.add(key)
        out.append(a)
        if len(out) >= _MAX_ATOMS:
            break
    return out


@dataclass
class SinkFlow:
    """Flow verdict for one sink call."""

    tainted: bool = False          # a request (high-weight) value reaches the dangerous arg unsanitized
    source_kind: str | None = None
    source_line: int | None = None
    sanitized: bool = False        # every source-derived value reaching the arg passed a sanitizer/guard
    sanitizer: str | None = None
    steps: list[Step] = field(default_factory=list)
    span: tuple[int, int] | None = None  # enclosing function (start_line, end_line), decorators included


def _verdict(kind: str, atoms: list[Atom], sink_line: int, sink_note: str, span: tuple[int, int]) -> SinkFlow:
    flow = SinkFlow(span=span)
    live = [a for a in atoms if a.weight == "high" and a.sanitizer_for(kind) is None]
    if live:
        top = min(live, key=lambda a: a.line)
        flow.tainted = True
        flow.source_kind, flow.source_line = top.kind, top.line
        flow.steps = sorted(top.steps, key=lambda st: st[0]) + [(sink_line, "sink", sink_note[:120])]
        return flow
    neutral = [a for a in atoms if a.sanitizer_for(kind) is not None]
    unknown = [a for a in atoms if a.sanitizer_for(kind) is None and a.weight != "low"]
    if neutral and not unknown:
        top = min(neutral, key=lambda a: (a.weight != "high", a.line))
        flow.sanitized = True
        flow.sanitizer = top.sanitizer_for(kind)
        if top.weight == "high":
            flow.source_kind, flow.source_line = top.kind, top.line
        flow.steps = sorted(top.steps, key=lambda st: st[0]) + [(sink_line, "sink", sink_note[:120])]
    return flow


# --- shared literal-prefix checks --------------------------------------------

# A URL literal that pins scheme + host before any interpolation: tainted data
# after it only controls the path/query, which is not SSRF.
# The leading lookbehind pins match starts to a scheme boundary (linear, #236).
_FIXED_HOST_RE = re.compile(r"(?<![\w+.-])[A-Za-z][\w+.-]*://[^/\s?#{}$`'\"%]+/")
# A redirect literal that pins a same-site path ("/orders/…", not "//evil").
_FIXED_PATH_RE = re.compile(r"/[^/\\\s{}$`'\"%]")


def _fixed_prefix(kind: str, literal: str | None) -> bool:
    if not literal:
        return False
    if kind == "ssrf":
        return _FIXED_HOST_RE.match(literal) is not None
    if kind == "open_redirect":
        return _FIXED_PATH_RE.match(literal) is not None
    return False


def _sanitizer_table() -> list[tuple[frozenset[str], str, re.Pattern[str]]]:
    table: list[tuple[frozenset[str], str, re.Pattern[str]]] = []
    for kind, entries in SANITIZERS.items():
        for label, pat in entries:
            table.append((frozenset({kind}), label, pat))
    every = frozenset(ALL_SANITIZER_KINDS)
    for label, pat in CAST_SANITIZERS:
        table.append((every, label, pat))
    return table


_SANITIZER_TABLE = _sanitizer_table()


# =============================================================================
# Python (ast)
# =============================================================================

_PY_MUTATORS = frozenset({"append", "extend", "insert", "add", "update", "appendleft", "write", "setdefault"})
_PY_ARG_KEYWORDS = frozenset(
    {
        "url", "sql", "query", "statement", "stmt", "operation", "cmd", "command", "args",
        "path", "file", "filename", "source", "template", "location", "string", "expression", "filter",
    }
)
_PY_EXIT_CALLS = frozenset({"abort", "exit", "quit", "_exit", "fail", "deny"})
_FLASK_PATH_PARAM_RE = re.compile(r"<(?:(\w+):)?(\w+)>")
_BRACE_PATH_PARAM_RE = re.compile(r"\{(\w+)(?::[^}]*)?\}")
_SAFE_CONVERTERS = frozenset({"int", "float", "uuid"})


class _PyFlow:
    def __init__(self, content: str) -> None:
        self.content = content
        self.tree = ast.parse(content)
        self.blines = content.encode("utf-8", "surrogatepass").split(b"\n")
        self.funcs: list[tuple[int, int, ast.AST]] = []
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start = min([d.lineno for d in node.decorator_list] + [node.lineno])
                self.funcs.append((start, node.end_lineno or node.lineno, node))
        self._fn: dict[int, tuple[list, dict]] = {}

    # -- text helpers --
    def seg(self, node: ast.AST, cap: int = 2000) -> str:
        l1, c1 = node.lineno, node.col_offset  # type: ignore[attr-defined]
        l2, c2 = node.end_lineno or l1, node.end_col_offset or c1  # type: ignore[attr-defined]
        try:
            if l1 == l2:
                b = self.blines[l1 - 1][c1:c2]
            else:
                if l2 - l1 > 40:
                    l2, c2 = l1 + 40, len(self.blines[l1 + 39])
                parts = [self.blines[l1 - 1][c1:]] + self.blines[l1 : l2 - 1] + [self.blines[l2 - 1][:c2]]
                b = b"\n".join(parts)
        except IndexError:
            return ""
        return b[:cap].decode("utf-8", "replace")

    def _enclosing(self, line: int) -> ast.AST | None:
        best = None
        best_start = -1
        for start, end, node in self.funcs:
            if start <= line <= end and start > best_start:
                best, best_start = node, start
        return best

    # -- sources --
    def _source(self, text: str) -> tuple[str, str] | None:
        for kind, pat, weight in SOURCES[PY]:
            if pat.match(text):
                return kind, weight
        return None

    def _eval(self, node: ast.AST, env: dict[str, list[Atom]], depth: int = 0) -> list[Atom]:
        if depth > _MAX_EVAL_DEPTH or isinstance(node, (ast.Constant, ast.Lambda)):
            return []
        if isinstance(node, (ast.Attribute, ast.Subscript, ast.Call, ast.Await)):
            text = self.seg(node, cap=300)
            hit = self._source(text)
            if hit is not None:
                kind, weight = hit
                label = text.split("\n", 1)[0][:80]
                return [Atom(kind, node.lineno, weight, label, (), ((node.lineno, "source", f"{kind}: {label}"),))]  # type: ignore[attr-defined]
        if isinstance(node, ast.Name):
            return list(env.get(node.id, ()))
        if isinstance(node, ast.Call):
            inner: list[Atom] = []
            if isinstance(node.func, ast.Attribute):
                inner += self._eval(node.func.value, env, depth + 1)
            for a in node.args:
                inner += self._eval(a, env, depth + 1)
            for kw in node.keywords:
                inner += self._eval(kw.value, env, depth + 1)
            ftxt = self.seg(node.func, cap=200) + "("
            for kinds, label, pat in _SANITIZER_TABLE:
                if any(m.end() == len(ftxt) for m in pat.finditer(ftxt)):
                    inner = [a.with_sanitizer(kinds, label, node.lineno) for a in inner]
            return _dedupe(inner)
        if isinstance(node, ast.Subscript):
            # `MAP[user]` is a lookup keyed by the value, not the value itself.
            return self._eval(node.value, env, depth + 1)
        if isinstance(node, ast.Attribute):
            return self._eval(node.value, env, depth + 1)
        out: list[Atom] = []
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                out += self._eval(child, env, depth + 1)
            elif isinstance(child, ast.comprehension):
                out += self._eval(child.iter, env, depth + 1)
        return _dedupe(out)

    # -- function setup --
    def _handler_params(self, fn: ast.AST) -> dict[str, list[Atom]]:
        env: dict[str, list[Atom]] = {}
        route_path = None
        is_handler = False
        for dec in fn.decorator_list:  # type: ignore[attr-defined]
            if not isinstance(dec, ast.Call):
                continue
            f = dec.func
            name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else None
            if name in PY_ROUTE_DECORATOR_NAMES:
                is_handler = True
                if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
                    route_path = dec.args[0].value
        path_params: dict[str, str | None] = {}
        if route_path:
            for conv, pname in _FLASK_PATH_PARAM_RE.findall(route_path):
                path_params[pname] = conv or None
            for pname in _BRACE_PATH_PARAM_RE.findall(route_path):
                path_params.setdefault(pname, None)
        args = fn.args  # type: ignore[attr-defined]
        params = list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)
        defaults: dict[str, ast.AST] = {}
        pos = list(args.posonlyargs) + list(args.args)
        for p, d in zip(pos[len(pos) - len(args.defaults):], args.defaults):
            defaults[p.arg] = d
        for p, d in zip(args.kwonlyargs, args.kw_defaults):
            if d is not None:
                defaults[p.arg] = d
        line = fn.lineno  # type: ignore[attr-defined]
        for p in params:
            if p.arg in ("self", "cls"):
                continue
            ann = self.seg(p.annotation, cap=200) if p.annotation is not None else ""
            dflt = self.seg(defaults[p.arg], cap=200) if p.arg in defaults else ""
            if not is_handler:
                env[p.arg] = [Atom("param", line, "param", p.arg)]
                continue
            if p.arg in PY_PLUMBING_PARAMS or PY_SAFE_ANNOTATION.search(ann) or PY_SAFE_DEFAULT.search(dflt):
                continue
            if p.arg in path_params:
                if path_params[p.arg] in _SAFE_CONVERTERS:
                    continue
                kind = "path_param"
            elif not ann or PY_SCALAR_ANNOTATION.search(ann):
                kind = "query"
            else:
                kind = "body"
            label = f"handler parameter `{p.arg}`"
            env[p.arg] = [Atom(kind, line, "high", label, (), ((line, "source", f"{kind}: {label}"),))]
        return env

    def _names(self, target: ast.AST) -> tuple[list[str], list[str]]:
        """(rebound names, names a subscript store merges into)."""
        if isinstance(target, ast.Name):
            return [target.id], []
        if isinstance(target, (ast.Tuple, ast.List)):
            bound: list[str] = []
            merged: list[str] = []
            for elt in target.elts:
                b, m = self._names(elt)
                bound += b
                merged += m
            return bound, merged
        if isinstance(target, ast.Starred):
            return self._names(target.value)
        if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
            return [], [target.value.id]
        return [], []

    def _stmts(self, body: list[ast.stmt]):
        for st in body:
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            yield st
            for attr in ("body", "orelse", "finalbody"):
                sub = getattr(st, attr, None)
                if isinstance(sub, list) and sub and isinstance(sub[0], ast.stmt):
                    yield from self._stmts(sub)
            for h in getattr(st, "handlers", ()) or ():
                yield from self._stmts(h.body)
            for case in getattr(st, "cases", ()) or ():
                yield from self._stmts(case.body)

    def _function_state(self, fn: ast.AST) -> tuple[list, dict]:
        key = id(fn)
        if key in self._fn:
            return self._fn[key]
        base = self._handler_params(fn)
        env = {k: list(v) for k, v in base.items()}
        history: list[tuple[int, str, list[Atom]]] = []

        def bind(line: int, names: list[str], merged: list[str], atoms: list[Atom], note: str, aug: bool = False) -> None:
            for n in names:
                new = [a.with_step(line, "propagation", note) for a in atoms]
                if aug:
                    new = _dedupe(env.get(n, []) + new)
                env[n] = new
                history.append((line, n, new))
            for n in merged:
                new = _dedupe(env.get(n, []) + [a.with_step(line, "propagation", note) for a in atoms])
                env[n] = new
                history.append((line, n, new))

        for st in self._stmts(fn.body):  # type: ignore[attr-defined]
            line = st.lineno
            if isinstance(st, ast.Assign):
                atoms = self._eval(st.value, env)
                note = self.seg(st, cap=120).split("\n", 1)[0]
                for t in st.targets:
                    b, m = self._names(t)
                    bind(line, b, m, atoms, note)
            elif isinstance(st, ast.AnnAssign) and st.value is not None:
                b, m = self._names(st.target)
                bind(line, b, m, self._eval(st.value, env), self.seg(st, cap=120).split("\n", 1)[0])
            elif isinstance(st, ast.AugAssign):
                b, m = self._names(st.target)
                bind(line, b, m, self._eval(st.value, env), self.seg(st, cap=120).split("\n", 1)[0], aug=True)
            elif isinstance(st, (ast.For, ast.AsyncFor)):
                b, m = self._names(st.target)
                bind(line, b, m, self._eval(st.iter, env), f"for … in {self.seg(st.iter, cap=80)}")
            elif isinstance(st, (ast.With, ast.AsyncWith)):
                for item in st.items:
                    if item.optional_vars is not None:
                        b, m = self._names(item.optional_vars)
                        bind(line, b, m, self._eval(item.context_expr, env), f"with … as {self.seg(item.optional_vars, cap=40)}")
            elif (
                isinstance(st, ast.Expr)
                and isinstance(st.value, ast.Call)
                and isinstance(st.value.func, ast.Attribute)
                and st.value.func.attr in _PY_MUTATORS
                and isinstance(st.value.func.value, ast.Name)
            ):
                call = st.value
                atoms: list[Atom] = []
                for a in call.args:
                    atoms += self._eval(a, env)
                for kw in call.keywords:
                    atoms += self._eval(kw.value, env)
                if atoms:
                    bind(line, [], [call.func.value.id], atoms, self.seg(st, cap=120).split("\n", 1)[0])
        state = (history, base)
        self._fn[key] = state
        return state

    def _env_at(self, fn: ast.AST, line: int) -> dict[str, list[Atom]]:
        history, base = self._function_state(fn)
        env = {k: list(v) for k, v in base.items()}
        for hline, name, atoms in history:
            if hline < line:
                env[name] = atoms
        return env

    # -- sink --
    def _find_call(self, fn: ast.AST, paren: int) -> ast.Call | None:
        content = self.content
        line_start = content.rfind("\n", 0, paren) + 1
        lp = line_number(content, paren)
        bcol = len(content[line_start:paren].encode("utf-8", "surrogatepass"))
        best: ast.Call | None = None
        best_col = -1
        for node in ast.walk(fn):
            if isinstance(node, ast.Call):
                f = node.func
                if f.end_lineno == lp and f.end_col_offset is not None and best_col < f.end_col_offset <= bcol:
                    best, best_col = node, f.end_col_offset
        return best

    def _leading_literal(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr) and node.values:
            first = node.values[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                return first.value
            return None
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return self._leading_literal(node.left)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return self._leading_literal(node.func.value)
        return None

    def _stmt_path(self, body: list[ast.stmt], line: int) -> list[tuple[list[ast.stmt], int]]:
        path: list[tuple[list[ast.stmt], int]] = []
        current = body
        while True:
            for i, st in enumerate(current):
                if st.lineno <= line <= (st.end_lineno or st.lineno):
                    path.append((current, i))
                    break
            else:
                return path
            st = current[path[-1][1]]
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                return path
            subs: list[list[ast.stmt]] = []
            for attr in ("body", "orelse", "finalbody"):
                sub = getattr(st, attr, None)
                if isinstance(sub, list) and sub and isinstance(sub[0], ast.stmt):
                    subs.append(sub)
            subs += [h.body for h in getattr(st, "handlers", ()) or ()]
            subs += [c.body for c in getattr(st, "cases", ()) or ()]
            nxt = None
            for sub in subs:
                if sub[0].lineno <= line <= (sub[-1].end_lineno or sub[-1].lineno):
                    nxt = sub
                    break
            if nxt is None:
                return path
            current = nxt

    def _terminates(self, body: list[ast.stmt]) -> bool:
        if not body:
            return False
        last = body[-1]
        if isinstance(last, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
            return True
        if isinstance(last, ast.Expr) and isinstance(last.value, ast.Call):
            f = last.value.func
            name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""
            return name in _PY_EXIT_CALLS
        return False

    def _guard_tests(self, fn: ast.AST, line: int) -> list[ast.expr]:
        tests: list[ast.expr] = []
        for lst, i in self._stmt_path(fn.body, line):  # type: ignore[attr-defined]
            for prior in lst[:i]:
                if isinstance(prior, ast.If) and self._terminates(prior.body):
                    tests.append(prior.test)
                elif isinstance(prior, ast.Assert):
                    tests.append(prior.test)
            st = lst[i]
            if isinstance(st, ast.If) and st.body and st.body[0].lineno <= line <= (st.body[-1].end_lineno or 0):
                tests.append(st.test)
        return tests

    def sink_flow(
        self, kind: str, paren: int, args_spec: tuple[int, ...] | None, snippet: str, match_start: int
    ) -> SinkFlow | None:
        line = line_number(self.content, paren)
        fn = self._enclosing(line)
        if fn is None:
            return None
        call = self._find_call(fn, paren)
        if call is None:
            return None
        env = self._env_at(fn, call.lineno)
        if args_spec is None:
            nodes: list[ast.AST] = list(call.args) + [kw.value for kw in call.keywords]
        elif args_spec == RECEIVER:
            nodes = [call.func.value] if isinstance(call.func, ast.Attribute) else []
        else:
            nodes = [call.args[i] for i in args_spec if 0 <= i < len(call.args)]
            nodes += [kw.value for kw in call.keywords if kw.arg in _PY_ARG_KEYWORDS]
            if not nodes:
                nodes = [kw.value for kw in call.keywords]
        atoms: list[Atom] = []
        for node in nodes:
            if _fixed_prefix(kind, self._leading_literal(node)):
                continue
            atoms += self._eval(node, env)
        atoms = _dedupe(atoms)
        atoms = self._apply_guards(kind, fn, call.lineno, env, atoms)
        start = min([d.lineno for d in fn.decorator_list] + [fn.lineno])  # type: ignore[attr-defined]
        return _verdict(kind, atoms, call.lineno, snippet, (start, fn.end_lineno or start))  # type: ignore[attr-defined]

    def _apply_guards(self, kind: str, fn: ast.AST, line: int, env: dict, atoms: list[Atom]) -> list[Atom]:
        live = {a.ident for a in atoms if a.sanitizer_for(kind) is None}
        if not live:
            return atoms
        for test in self._guard_tests(fn, line):
            text = self.seg(test, cap=400)
            label = next((lbl for lbl, pat in guard_patterns(kind) if pat.search(text)), None)
            if label is None:
                continue
            bound = {a.ident for a in self._eval(test, env)} & live
            if bound:
                atoms = [
                    a.with_sanitizer((kind,), label, test.lineno, "guard") if a.ident in bound else a
                    for a in atoms
                ]
        return atoms


# =============================================================================
# JS/TS, Go, PHP, Java (masked text + brace balance)
# =============================================================================

_MASK_SPECIAL = {
    JS: re.compile(r"[\"'`/]"),
    GO: re.compile(r"[\"'`/]"),
    JAVA: re.compile(r"[\"'/]"),
    PHP: re.compile(r"[\"'/#]"),
}
_PHP_VAR_RE = re.compile(r"\$[A-Za-z_]\w*")
# String-literal bodies (unambiguous alternation → linear).
_QUOTED_BODY = {
    ('"', False): re.compile(r'(?:[^"\\\n]|\\.)*'),
    ("'", False): re.compile(r"(?:[^'\\\n]|\\.)*"),
    ('"', True): re.compile(r'(?:[^"\\]|\\.)*', re.S),
    ("'", True): re.compile(r"(?:[^'\\]|\\.)*", re.S),
}
_BRACES_RE = re.compile(r"[{}]")
_PARENS_RE = re.compile(r"[()]")
_STMT_SPECIAL_RE = re.compile(r"[()\[\]{};\n]")
_COMMA_SPECIAL_RE = re.compile(r"[()\[\]{},]")
_ASSIGN_OP = {
    JS: re.compile(r"\+=|(?<![=!<>+\-*/%&|^:~?])=(?![=>~])"),
    JAVA: re.compile(r"\+=|(?<![=!<>+\-*/%&|^:~?])=(?![=>~])"),
    GO: re.compile(r":=|\+=|(?<![=!<>+\-*/%&|^:~])=(?![=>~])"),
    PHP: re.compile(r"\.=|\+=|\?\?=|(?<![=!<>+\-*/%&|^:~.?])=(?![=>~])"),
}
_IDENT_RE = {
    JS: re.compile(r"(?<![\w$.])[A-Za-z_$][\w$]*"),
    JAVA: re.compile(r"(?<![\w$.])[A-Za-z_$][\w$]*"),
    GO: re.compile(r"(?<![\w.])[A-Za-z_]\w*"),
    PHP: re.compile(r"\$[A-Za-z_]\w*"),
}
_GO_OUTPARAM_RE = re.compile(r"&\s*([A-Za-z_]\w*)")
_IF_RE = re.compile(r"\bif\b")
_FN_KEYWORD_RE = re.compile(r"\b(?:function|func)\b")
_NEW_CLASS_RE = re.compile(r"\bnew\s+[\w.<>]+\s*$")
_TRAILING_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*$")
_FMT_SPRINTF_RE = re.compile(r"(?:fmt\.Sprintf|String\.format|sprintf)\s*\(\s*")
_CONTROL = frozenset(
    {
        "if", "for", "while", "switch", "catch", "with", "foreach", "elseif", "synchronized",
        "using", "lock", "return", "typeof", "await", "yield", "else", "do", "try", "case", "in", "of",
        "and", "or", "not", "sizeof", "defer", "go", "select", "range",
    }
)
_KEYWORDS = frozenset(
    {
        "const", "let", "var", "final", "static", "public", "private", "protected", "if", "for", "range",
        "return", "new", "this", "true", "false", "null", "nil", "undefined", "await", "async", "typeof",
        "instanceof", "in", "of", "else", "string", "int", "bool", "byte", "error", "func", "go", "defer",
    }
)


def _mask(src: str, lang: str) -> str:
    """Blank string-literal contents and comments (offsets and newlines kept).

    Interpolations stay visible: JS template ``${…}`` and PHP double-quoted
    ``$var`` carry data into the string."""
    out = list(src)
    n = len(src)
    special = _MASK_SPECIAL[lang]

    def blank(a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    def quoted(i: int, q: str, multiline: bool) -> int:
        # Index of the closing quote (or the newline / EOF ending an
        # unterminated single-line literal).
        return _QUOTED_BODY[(q, multiline)].match(src, i + 1).end()  # type: ignore[union-attr]

    def template(i: int) -> int:
        # JS template literal starting at backtick i; returns index of closing backtick.
        j = i + 1
        lit_start = j
        while j < n:
            c = src[j]
            if c == "\\":
                j += 2
                continue
            if c == "`":
                blank(lit_start, j)
                return j
            if c == "$" and j + 1 < n and src[j + 1] == "{":
                blank(lit_start, j)
                j = code(j + 2, stop_on_brace=True)
                lit_start = j + 1
            j += 1
        blank(lit_start, n)
        return n

    def code(i: int, stop_on_brace: bool = False) -> int:
        depth = 0
        while i < n:
            if stop_on_brace:
                # Track braces only inside an interpolation; scan char-wise.
                c = src[i]
                if c == "{":
                    depth += 1
                elif c == "}":
                    if depth == 0:
                        return i
                    depth -= 1
                elif c in "\"'`/":
                    i = handle(i)
                i += 1
                continue
            m = special.search(src, i)
            if m is None:
                return n
            i = handle(m.start()) + 1
        return n

    def handle(i: int) -> int:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/" or (c == "#" and lang == PHP and nxt != "["):
            j = src.find("\n", i)
            j = n if j == -1 else j
            blank(i, j)
            return j - 1 if j < n else n
        if c == "/" and nxt == "*":
            j = src.find("*/", i + 2)
            j = n if j == -1 else j + 2
            blank(i, j)
            return j - 1
        if c == "/":
            return i
        if c == "`" and lang == JS:
            return template(i)
        if c == "`" and lang == GO:
            j = src.find("`", i + 1)
            j = n if j == -1 else j
            blank(i + 1, j)
            return j
        if c == '"' and lang == JAVA and src.startswith('"""', i):
            j = src.find('"""', i + 3)
            j = n if j == -1 else j
            blank(i + 3, j)
            return j + 2
        if c in "\"'":
            j = quoted(i, c, multiline=(lang == PHP))
            blank(i + 1, j)
            if lang == PHP and c == '"':
                for m in _PHP_VAR_RE.finditer(src, i + 1, j):
                    out[m.start() : m.end()] = src[m.start() : m.end()]
            return j
        return i

    code(0)
    return "".join(out)


class _TextFlow:
    def __init__(self, content: str, lang: str) -> None:
        self.raw = content
        self.lang = lang
        self.m = _mask(content, lang)
        opens: list[int] = []
        closes: list[int] = []
        parent: list[int] = []
        stack: list[int] = []
        for mt in _BRACES_RE.finditer(self.m):
            if mt.group() == "{":
                parent.append(stack[-1] if stack else -1)
                opens.append(mt.start())
                closes.append(len(self.m))
                stack.append(len(opens) - 1)
            elif stack:
                closes[stack.pop()] = mt.start()
        self.opens, self.closes, self.parent = opens, closes, parent
        self.open_index = {o: k for k, o in enumerate(opens)}
        self._is_fn: dict[int, tuple[int, int, int] | None] = {}
        self._fn_state: dict[int, tuple[list, dict]] = {}

    # -- structure --
    def _innermost(self, off: int) -> int:
        k = bisect.bisect_right(self.opens, off) - 1
        while k >= 0 and not (self.opens[k] < off < self.closes[k]):
            k = self.parent[k]
        return k

    def _function_header(self, k: int) -> tuple[int, int, int] | None:
        """(header_start, params_open, params_close) when block ``k`` is a
        function body, else None. params_* are -1 when not located."""
        if k in self._is_fn:
            return self._is_fn[k]
        o = self.opens[k]
        lo = max(0, o - _MAX_HEADER)
        seg = self.m[lo:o]
        cut = max(seg.rfind(";"), seg.rfind("{"), seg.rfind("}"))
        start = lo + cut + 1
        header = self.m[start:o]
        h = header.rstrip()
        result: tuple[int, int, int] | None = None
        hs = start + (len(header) - len(header.lstrip()))
        p = h.rfind(")")
        po = -1
        if p != -1:
            depth = 0
            for q in range(p, -1, -1):
                ch = h[q]
                if ch == ")":
                    depth += 1
                elif ch == "(":
                    depth -= 1
                    if depth == 0:
                        po = q
                        break
        params = (start + po, start + p) if po != -1 else (-1, -1)
        if h.endswith("=>") or h.endswith("->") or _FN_KEYWORD_RE.search(h):
            result = (hs, *params)
        elif p != -1 and po != -1:
            tail = h[p + 1 :].strip()
            before = h[:po].rstrip()
            word = _TRAILING_IDENT_RE.search(before)
            if (
                (tail == "" or tail.startswith(":") or tail.startswith("throws"))
                and word is not None
                and word.group() not in _CONTROL
                and not _NEW_CLASS_RE.search(before)
            ):
                result = (hs, *params)
        self._is_fn[k] = result
        return result

    def _enclosing_fn(self, off: int) -> tuple[int, tuple[int, int, int]] | None:
        k = self._innermost(off)
        while k >= 0:
            hdr = self._function_header(k)
            if hdr is not None:
                return k, hdr
            k = self.parent[k]
        return None

    def _match_paren(self, open_idx: int, cap: int) -> int:
        depth = 0
        end = min(len(self.m), open_idx + cap)
        for mt in _PARENS_RE.finditer(self.m, open_idx, end):
            if mt.group() == "(":
                depth += 1
            else:
                depth -= 1
                if depth == 0:
                    return mt.start()
        return end

    def _stmt_end(self, i: int, limit: int) -> int:
        m = self.m
        depth = 0
        end = min(limit, i + _MAX_RHS)
        pos = i
        while True:
            mt = _STMT_SPECIAL_RE.search(m, pos, end)
            if mt is None:
                return end
            c = mt.group()
            j = mt.start()
            if c in "([{":
                depth += 1
            elif c in ")]}":
                if depth == 0:
                    return j
                depth -= 1
            elif c == ";" and depth == 0:
                return j
            elif c == "\n" and depth == 0:
                prev = m[max(i, j - 200) : j].rstrip()
                rest = m[j + 1 : min(end, j + 200)].lstrip()
                cont_prev = bool(prev) and prev[-1] in "+,(.=?:&|[{-*/%"
                cont_next = bool(rest) and rest[0] in ".+?:&|-*/%" and not rest.startswith("//")
                if not (cont_prev or cont_next) and prev:
                    return j
            pos = j + 1

    def _split_args(self, a: int, b: int) -> list[tuple[int, int]]:
        regions: list[tuple[int, int]] = []
        depth = 0
        start = a
        for mt in _COMMA_SPECIAL_RE.finditer(self.m, a, b):
            c = mt.group()
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
            elif depth == 0:
                regions.append((start, mt.start()))
                start = mt.end()
        regions.append((start, b))
        return [(s, e) for s, e in regions if self.m[s:e].strip()]

    # -- evaluation --
    def _is_code(self, off: int) -> bool:
        return self.m[off] == self.raw[off]

    def _eval(self, a: int, b: int, env: dict[str, list[Atom]]) -> list[Atom]:
        if b <= a:
            return []
        spans: list[tuple[int, int, frozenset[str], str]] = []
        for kinds, label, pat in _SANITIZER_TABLE:
            for mt in pat.finditer(self.m, a, b):
                if self.m[mt.end() - 1] == "(":
                    close = self._match_paren(mt.end() - 1, _MAX_RHS)
                else:  # PHP `(int)$x` cast: covers the following variable
                    tail = re.match(r"\w*", self.m[mt.end() : mt.end() + 64])
                    close = mt.end() + (tail.end() if tail else 0)
                spans.append((mt.start(), close, kinds, label))

        def sanitize(atom: Atom, off: int) -> Atom:
            for s, e, kinds, label in spans:
                if s <= off <= e:
                    atom = atom.with_sanitizer(kinds, label, line_number(self.raw, s))
            return atom

        atoms: list[Atom] = []
        for kind, pat, weight in SOURCES[self.lang]:
            for mt in pat.finditer(self.raw, a, b):
                if not self._is_code(mt.start()) and "php:" not in pat.pattern:
                    continue
                line = line_number(self.raw, mt.start())
                label = self.raw[mt.start() : min(b, mt.end() + 24)].split("\n", 1)[0].strip()[:80]
                atom = Atom(kind, line, weight, label, (), ((line, "source", f"{kind}: {label}"),))
                atoms.append(sanitize(atom, mt.start()))
        for mt in _IDENT_RE[self.lang].finditer(self.m, a, b):
            got = env.get(mt.group())
            if got:
                atoms += [sanitize(x, mt.start()) for x in got]
        return _dedupe(atoms)

    def _param_env(self, hdr: tuple[int, int, int]) -> dict[str, list[Atom]]:
        env: dict[str, list[Atom]] = {}
        _, po, pc = hdr
        if po < 0 or self.lang == GO:
            return env
        line = line_number(self.raw, po)
        annotations = PARAM_ANNOTATIONS.get(self.lang, ())
        for s, e in self._split_args(po + 1, pc):
            raw_seg = self.raw[s:e]
            kind = next((k for k, pat in annotations if pat.search(raw_seg)), None)
            masked = self.m[s:e]
            if self.lang == PHP:
                names = _PHP_VAR_RE.findall(masked)
                name = names[-1] if names else None
            else:
                # strip annotations/decorators and their arguments
                cleaned = re.sub(r"@\w+(?:\s*\([^()]*\))?", " ", masked)
                cleaned = cleaned.split("=", 1)[0]
                if self.lang == JS:
                    cleaned = cleaned.split(":", 1)[0]
                ids = [x for x in _IDENT_RE[self.lang].findall(cleaned) if x not in _KEYWORDS]
                name = ids[-1] if ids else None
            if not name:
                continue
            if kind is not None:
                label = f"handler parameter `{name}`"
                env[name] = [Atom(kind, line, "high", label, (), ((line, "source", f"{kind}: {label}"),))]
            else:
                env[name] = [Atom("param", line, "param", name)]
        return env

    def _lhs_names(self, op: int, floor: int) -> tuple[list[str], list[str]]:
        m = self.m
        back = m[max(floor, op - 200) : op].rstrip()
        if not back:
            return [], []
        if back[-1] in "}]":
            closer = back[-1]
            opener = "{" if closer == "}" else "["
            depth = 0
            q = len(back) - 1
            while q >= 0:
                if back[q] == closer:
                    depth += 1
                elif back[q] == opener:
                    depth -= 1
                    if depth == 0:
                        break
                q -= 1
            if q < 0:
                return [], []
            before = back[:q].rstrip()
            inner = back[q + 1 : -1]
            if closer == "]" and before and (before[-1].isalnum() or before[-1] in "_$)]"):
                # subscript store: `x[k] = v` merges into x
                base = _IDENT_RE[self.lang].findall(before[-80:])
                return [], base[-1:] if base else []
            if self.lang == PHP:
                return _PHP_VAR_RE.findall(inner), []
            names = []
            for part in inner.split(","):
                part = part.split("=", 1)[0]
                ids = _IDENT_RE[self.lang].findall(part)
                if ids:
                    names.append(ids[-1])
            return [n for n in names if n not in _KEYWORDS], []
        cut_chars = ";{}(\n" if self.lang == GO else ";{}(\n,"
        cut = max(back.rfind(c) for c in cut_chars)
        lhs = back[cut + 1 :]
        if lhs.rstrip().endswith((".", ")")):
            return [], []
        if self.lang == PHP:
            names = _PHP_VAR_RE.findall(lhs)
            if "->" in lhs or "::" in lhs:
                return [], []
            return names[-1:], []
        ids = [x for x in _IDENT_RE[self.lang].findall(lhs) if x not in _KEYWORDS]
        if not ids:
            return [], []
        # member store `obj.prop = v` → not a local
        last = lhs.rstrip()
        if re.search(r"\.\s*[A-Za-z_$][\w$]*$", last):
            return [], []
        if self.lang == GO:
            return ids, []
        return ids[-1:], []

    def _function_state(self, k: int, hdr: tuple[int, int, int]) -> tuple[list, dict]:
        if k in self._fn_state:
            return self._fn_state[k]
        base = self._param_env(hdr)
        env = {n: list(v) for n, v in base.items()}
        body_lo, body_hi = self._body(k)
        events: list[tuple[int, str, int, int, int]] = []  # (offset, type, a, b, extra)
        for mt in _ASSIGN_OP[self.lang].finditer(self.m, body_lo, body_hi):
            events.append((mt.start(), "assign", mt.start(), mt.end(), 0))
        if self.lang == GO:
            for mt in _GO_OUTPARAM_RE.finditer(self.m, body_lo, body_hi):
                events.append((mt.start(), "out", mt.start(1), mt.end(1), 0))
        events.sort()
        history: list[tuple[int, str, list[Atom]]] = []
        for off, typ, a, b, _ in events:
            if typ == "assign":
                op_text = self.m[a:b]
                names, merged = self._lhs_names(a, body_lo)
                if not names and not merged:
                    continue
                rhs_end = self._stmt_end(b, body_hi)
                atoms = self._eval(b, rhs_end, env)
                line = line_number(self.raw, a)
                stmt_start = self.raw.rfind("\n", 0, a) + 1
                note = self.raw[stmt_start:rhs_end].strip().split("\n", 1)[0]
                aug = op_text in ("+=", ".=", "??=")
                for n in names:
                    new = [x.with_step(line, "propagation", note) for x in atoms]
                    if aug:
                        new = _dedupe(env.get(n, []) + new)
                    env[n] = new
                    history.append((a, n, new))
                for n in merged:
                    new = _dedupe(env.get(n, []) + [x.with_step(line, "propagation", note) for x in atoms])
                    env[n] = new
                    history.append((a, n, new))
            else:  # Go out-param: Decode(&x) / BindJSON(&x) / Unmarshal(data, &x)
                name = self.m[a:b]
                s = max(body_lo, self.m.rfind("\n", 0, off) + 1)
                e = self._stmt_end(s, body_hi)
                atoms = [x for x in self._eval(s, e, env) if x.label != name]
                if atoms:
                    line = line_number(self.raw, off)
                    note = self.raw[s:e].strip().split("\n", 1)[0]
                    new = _dedupe(env.get(name, []) + [x.with_step(line, "propagation", note) for x in atoms])
                    env[name] = new
                    history.append((off, name, new))
        state = (history, base)
        self._fn_state[k] = state
        return state

    def _env_at(self, k: int, hdr: tuple[int, int, int], off: int) -> dict[str, list[Atom]]:
        history, base = self._function_state(k, hdr)
        env = {n: list(v) for n, v in base.items()}
        for hoff, name, atoms in history:
            if hoff < off:
                env[name] = atoms
        return env

    def _leading_literal(self, s: int, e: int) -> str | None:
        text = self.raw[s:e].strip()
        fm = _FMT_SPRINTF_RE.match(text)
        if fm:
            text = text[fm.end() :]
        if not text or text[0] not in "\"'`":
            return None
        q = text[0]
        body = text[1:]
        stop = len(body)
        for marker in (q, "${") if q == "`" else (q, "$") if self.lang == PHP and q == '"' else (q,):
            idx = body.find(marker)
            if idx != -1:
                stop = min(stop, idx)
        return body[:stop]

    def _guards(self, kind: str, k: int, hdr: tuple[int, int, int], sink: int, env: dict, atoms: list[Atom]) -> list[Atom]:
        live = {a.ident for a in atoms if a.sanitizer_for(kind) is None}
        if not live:
            return atoms
        body_lo = self._body(k)[0]
        for mt in _IF_RE.finditer(self.m, body_lo, sink):
            p = mt.end()
            while p < sink and self.m[p] in " \t\r\n":
                p += 1
            if self.lang == GO:
                q = p
                depth = 0
                while q < sink:
                    c = self.m[q]
                    if c in "([":
                        depth += 1
                    elif c in ")]":
                        depth -= 1
                    elif c == "{" and depth == 0:
                        break
                    q += 1
                cond = (p, q)
                after = q
            else:
                if p >= sink or self.m[p] != "(":
                    continue
                close = self._match_paren(p, _MAX_RHS)
                cond = (p + 1, close)
                after = close + 1
                while after < len(self.m) and self.m[after] in " \t\r\n":
                    after += 1
            if after < len(self.m) and self.m[after] == "{" and after in self.open_index:
                bk = self.open_index[after]
                blk = (self.opens[bk], self.closes[bk])
            else:
                blk = (after, self._stmt_end(after, len(self.m)))
            if blk[1] < sink:
                if not EARLY_EXIT.search(self.m, blk[0], blk[1] + 1):
                    continue
                encl = self._innermost(mt.start())
                if encl >= 0 and not (self.opens[encl] < sink < self.closes[encl]):
                    continue
            elif not (blk[0] < sink < blk[1]):
                continue
            text = self.raw[cond[0] : cond[1]]
            label = next((lbl for lbl, pat in guard_patterns(kind) if pat.search(text)), None)
            if label is None:
                continue
            bound = {a.ident for a in self._eval(cond[0], cond[1], env)} & live
            if bound:
                gl = line_number(self.raw, mt.start())
                atoms = [a.with_sanitizer((kind,), label, gl, "guard") if a.ident in bound else a for a in atoms]
        return atoms

    def _receiver(self, end: int) -> tuple[int, int]:
        """Region of the receiver expression ending just before ``end``
        (``url`` in ``url.openStream()``, ``new URL(u)`` in ``new URL(u).openStream()``)."""
        m = self.m
        e = end
        while e > 0 and m[e - 1] in " \t\r\n":
            e -= 1
        s = e
        floor = max(0, e - 300)
        while s > floor:
            c = m[s - 1]
            if c == ")" or c == "]":
                opener = "(" if c == ")" else "["
                depth = 0
                q = s - 1
                while q >= floor:
                    if m[q] == c:
                        depth += 1
                    elif m[q] == opener:
                        depth -= 1
                        if depth == 0:
                            break
                    q -= 1
                if q < floor:
                    break
                s = q
            elif c.isalnum() or c in "_$.":
                s -= 1
            elif c == " " and m[max(floor, s - 4) : s - 1].endswith("new"):
                s -= 1
            else:
                break
        return s, e

    def _body(self, k: int) -> tuple[int, int]:
        if k < 0:  # PHP top-level script scope
            return 0, len(self.m)
        return self.opens[k] + 1, self.closes[k]

    def sink_flow(
        self, kind: str, paren: int, args_spec: tuple[int, ...] | None, snippet: str, match_start: int
    ) -> SinkFlow | None:
        found = self._enclosing_fn(paren)
        if found is None:
            if self.lang != PHP:
                return None
            # A plain PHP script is its own handler: its top level is the scope.
            found = (-1, (0, -1, -1))
        k, hdr = found
        env = self._env_at(k, hdr, paren)
        close = self._match_paren(paren, _MAX_ARGS)
        if args_spec == RECEIVER:
            regions = [self._receiver(match_start)]
        else:
            regions = self._split_args(paren + 1, close)
            if args_spec is not None:
                regions = [regions[i] for i in args_spec if 0 <= i < len(regions)]
        atoms: list[Atom] = []
        for s, e in regions:
            if _fixed_prefix(kind, self._leading_literal(s, e)):
                continue
            atoms += self._eval(s, e, env)
        atoms = self._guards(kind, k, hdr, paren, env, _dedupe(atoms))
        line = line_number(self.raw, paren)
        body_lo, body_hi = self._body(k)
        span = (line_number(self.raw, hdr[0]), line_number(self.raw, body_hi))
        return _verdict(kind, atoms, line, snippet, span)


# =============================================================================
# Public entry point
# =============================================================================


class FileFlow:
    """Lazily-built, per-file flow context. Build one per file and reuse it for
    every sink in that file — the parse / mask / brace index are cached."""

    def __init__(self, content: str, suffix: str) -> None:
        self.content = content
        self.lang = lang_for_suffix(suffix)
        self._impl: _PyFlow | _TextFlow | None = None
        self._failed = self.lang is None

    def _get(self) -> _PyFlow | _TextFlow | None:
        if self._failed:
            return None
        if self._impl is None:
            try:
                self._impl = _PyFlow(self.content) if self.lang == PY else _TextFlow(self.content, self.lang or JS)
            except (SyntaxError, ValueError, RecursionError, MemoryError):
                self._failed = True
                return None
        return self._impl

    def sink_flow(
        self,
        kind: str,
        paren: int,
        args_spec: tuple[int, ...] | None,
        snippet: str = "",
        match_start: int | None = None,
    ) -> SinkFlow | None:
        """Flow verdict for the sink call whose argument list opens at
        ``paren``; None when the enclosing function can't be determined (the
        caller then keeps its legacy same-call gate)."""
        impl = self._get()
        if impl is None or paren < 0 or paren >= len(self.content) or self.content[paren] != "(":
            return None
        try:
            return impl.sink_flow(kind, paren, args_spec, snippet, paren if match_start is None else match_start)
        except RecursionError:
            return None
