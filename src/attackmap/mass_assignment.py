"""Field-level mass assignment (#242, part 2).

``weaknesses.py`` catches the wholesale bind of a request object
(``Model(**request.json)``, ``.create(req.body)``, ``permit!``). This pass
catches binds that look scoped but still let a client set a privileged
column, which needs the model's field list from another file:

    Django REST Framework serializer / ModelForm with ``fields = '__all__'``
    (or an ``exclude`` denylist) on a model with privileged fields
    Django ``CreateView`` / ``UpdateView`` with ``fields = '__all__'``
    a SQLModel ``table=True`` model used as a FastAPI write-endpoint body
    a Spring ``@Entity`` bound by ``@ModelAttribute`` / ``@RequestBody``

Precision-first: a bind is flagged only when the bound model has a field from
``PRIVILEGED_FIELDS`` (or inherits Django's ``is_staff`` / ``is_superuser``)
that the binder doesn't mark read-only or exclude. An explicit field list is
never flagged, even if it names a privileged field: that's a choice, not an
accident.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from .models import CodeWeakness
from .safe_fs import is_oversized, walk_repo
from .srcpaths import is_skipped_dir, is_test_file, is_vendored_file

# Privileged column names, normalized (lowercase, no `_`), so `is_admin`,
# `isAdmin` and `IsAdmin` all match.
PRIVILEGED_FIELDS = frozenset({
    "isstaff", "isadmin", "admin", "issuperuser", "superuser",
    "role", "roles", "userrole", "permissions", "userpermissions", "privileges",
    "balance", "accountbalance", "credits",
    "verified", "isverified", "emailverified",
    "tenantid", "tenant", "orgid", "organizationid",
})

# Fields Django's auth base classes add to a subclass.
_DJANGO_USER_FIELDS = frozenset({"is_staff", "is_superuser", "groups", "user_permissions"})
_DJANGO_BUILTIN_BASES = {
    "AbstractUser": _DJANGO_USER_FIELDS,
    "User": _DJANGO_USER_FIELDS,
    "PermissionsMixin": frozenset({"is_superuser", "groups", "user_permissions"}),
}
_DJANGO_AUTH_MODULES = ("django.contrib.auth.models", "django.contrib.auth")

# Binder base classes: DRF serializers and Django forms. FilterSets, graphene
# types and mutations (whose input type, not `Meta.model`, sets the writable
# fields) and tables also carry `Meta.model`, and don't match.
_BINDER_BASE_RE = re.compile(r"(?:Serializer|Form)$")
_WRITE_VIEW_BASE_RE = re.compile(r"(?:CreateView|UpdateView)$")
# Django admin classes: a form wired in as `form = X` is only reachable by
# staff, who are meant to edit privileged fields.
_ADMIN_BASE_RE = re.compile(r"(?:Admin|Inline)$")
_ADMIN_FORM_ATTRS = ("form", "add_form")
_READ_ONLY_SERIALIZER_FIELDS = frozenset({"ReadOnlyField", "SerializerMethodField", "HiddenField"})
_FASTAPI_WRITE_METHODS = frozenset({"post", "put", "patch"})
_FASTAPI_INJECTED = frozenset({"Depends", "Security"})

# Cheap gates so most files skip the parse: Python files need a class (a
# model or binder) or a write-route decorator.
_PY_GATE_RE = re.compile(r"^\s*class\s|\.(?:post|put|patch)\s*\(", re.MULTILINE)
_JVM_GATE_RE = re.compile(r"@(?:Entity|ModelAttribute|RequestBody)\b")

# Spring: an `@Entity` class header and the binding of a handler parameter.
_JVM_ENTITY_RE = re.compile(r"@(?:jakarta\.persistence\.|javax\.persistence\.)?Entity\b")
_JVM_CLASS_RE = re.compile(r"\bclass\s+([A-Z]\w*)")
_JVM_ANNOTATION_RE = re.compile(r"@[\w.]+(?:\s*\([^()\n]*\))?")
_KOTLIN_PROPERTY_RE = re.compile(r"\b(?:val|var)\s+(\w+)\s*:")
_SPRING_BIND_RE = re.compile(
    r"@(ModelAttribute|RequestBody)\b(?:\s*\([^()\n]*\))?\s+"
    r"(?:@[\w.]+(?:\s*\([^()\n]*\))?\s+)*"
    r"(?:(?:final\s+)?([A-Z]\w*)\s+(\w+)|(\w+)\s*:\s*([A-Z]\w*)\??)\s*[,)]"
)
_SPRING_MAPPING_RE = re.compile(r"@(Get|Post|Put|Patch|Delete|Request)Mapping\b")
_SPRING_ALLOWED_FIELDS_RE = re.compile(r"\.setAllowedFields\s*\(")
_SPRING_DISALLOWED_FIELDS_RE = re.compile(r"\.setDisallowedFields\s*\(([^)]*)\)")
_QUOTED_RE = re.compile(r"\"([^\"\n]{1,80})\"")
_JSON_READ_ONLY_RE = re.compile(r"@JsonIgnore\b|READ_ONLY|@JsonProperty\s*\([^)]*access")

_JVM_SUFFIXES = frozenset({".java", ".kt"})
_SUFFIXES = frozenset({".py"}) | _JVM_SUFFIXES


def _norm(name: str) -> str:
    return name.replace("_", "").lower()


def _privileged(fields: set[str] | frozenset[str]) -> list[str]:
    return sorted(f for f in fields if _norm(f) in PRIVILEGED_FIELDS or f in _DJANGO_USER_FIELDS)


@dataclass
class _ModelDef:
    name: str
    file: str
    fields: set[str]
    bases: list[str]
    # JVM fields a JSON body can't set (`@JsonIgnore`, `READ_ONLY`).
    json_read_only: set[str] = field(default_factory=set)
    table: bool = False


@dataclass
class _Binder:
    file: str
    line: int
    label: str  # "UserSerializer", "POST create_hero(hero)", …
    model: str  # model class name, or "" for Django's own User
    imported_from: str | None
    excluded: set[str] = field(default_factory=set)
    read_only: set[str] = field(default_factory=set)
    builtin_user: bool = False
    json_body: bool = False
    # A FastAPI body is only a mass-assignment risk when it's the DB model
    # itself; a plain pydantic model is the DTO that prevents it.
    requires_table: bool = False


class _Index:
    def __init__(self) -> None:
        self.models: dict[str, list[_ModelDef]] = {}
        self.binders: list[_Binder] = []
        self.admin_forms: set[str] = set()

    # --- Python --------------------------------------------------------

    def add_python(self, rel: str, text: str) -> None:
        if not _PY_GATE_RE.search(text):
            return
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            return
        imports = _python_imports(tree)
        user_aliases = {
            name for name, module in imports.items() if module in _DJANGO_AUTH_MODULES and name == "User"
        }
        for node in tree.body:
            # `User = get_user_model()` at module level.
            if isinstance(node, ast.Assign) and _is_get_user_model(node.value):
                user_aliases.update(t.id for t in node.targets if isinstance(t, ast.Name))
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                self._python_class(rel, node, imports, user_aliases)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._fastapi_handler(rel, node, imports)

    def _python_class(self, rel: str, node: ast.ClassDef, imports: dict[str, str], user_aliases: set[str]) -> None:
        bases = [_terminal_name(b) for b in node.bases]
        table = any(
            kw.arg == "table" and isinstance(kw.value, ast.Constant) and kw.value.value is True
            for kw in node.keywords
        )
        fields: set[str] = set()
        read_only: set[str] = set()
        meta: ast.ClassDef | None = None
        class_attrs: dict[str, ast.AST] = {}
        for stmt in node.body:
            if isinstance(stmt, ast.ClassDef) and stmt.name == "Meta":
                meta = stmt
            elif isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        class_attrs[target.id] = stmt
                        if isinstance(stmt.value, ast.Call):
                            fields.add(target.id)
                            if _is_read_only_serializer_field(stmt.value):
                                read_only.add(target.id)
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                fields.add(stmt.target.id)
        self.models.setdefault(node.name, []).append(
            _ModelDef(name=node.name, file=rel, fields=fields, bases=bases, table=table)
        )
        if any(_ADMIN_BASE_RE.search(b) for b in bases):
            for attr in _ADMIN_FORM_ATTRS:
                stmt = class_attrs.get(attr)
                if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Name):
                    self.admin_forms.add(stmt.value.id)

        if meta is not None and any(_BINDER_BASE_RE.search(b) for b in bases):
            attrs = {
                t.id: s
                for s in meta.body
                if isinstance(s, ast.Assign)
                for t in s.targets
                if isinstance(t, ast.Name)
            }
            self._python_binder(rel, node.name, attrs, imports, user_aliases, read_only)
        elif any(_WRITE_VIEW_BASE_RE.search(b) for b in bases) and "form_class" not in class_attrs:
            self._python_binder(rel, node.name, class_attrs, imports, user_aliases, set())

    def _python_binder(
        self,
        rel: str,
        label: str,
        attrs: dict[str, ast.AST],
        imports: dict[str, str],
        user_aliases: set[str],
        read_only: set[str],
    ) -> None:
        model_stmt = attrs.get("model")
        if not isinstance(model_stmt, ast.Assign):
            return
        fields_stmt = attrs.get("fields")
        exclude_stmt = attrs.get("exclude")
        if isinstance(fields_stmt, ast.Assign):
            if not (isinstance(fields_stmt.value, ast.Constant) and fields_stmt.value.value == "__all__"):
                return  # an explicit allow-list
            anchor = fields_stmt
            excluded: set[str] = set()
        elif isinstance(exclude_stmt, ast.Assign):
            anchor = exclude_stmt
            excluded = _string_items(exclude_stmt.value)
        else:
            return
        read_only = set(read_only)
        ro_stmt = attrs.get("read_only_fields")
        if isinstance(ro_stmt, ast.Assign):
            read_only |= _string_items(ro_stmt.value)
        kw_stmt = attrs.get("extra_kwargs")
        if isinstance(kw_stmt, ast.Assign) and isinstance(kw_stmt.value, ast.Dict):
            for key, value in zip(kw_stmt.value.keys, kw_stmt.value.values):
                if isinstance(key, ast.Constant) and isinstance(key.value, str) and _dict_flag(value, "read_only"):
                    read_only.add(key.value)

        model_expr = model_stmt.value
        builtin = _is_get_user_model(model_expr)
        model = "" if builtin else _terminal_name(model_expr)
        if model in user_aliases:
            builtin, model = True, ""
        if not builtin and not model:
            return
        self.binders.append(
            _Binder(
                file=rel,
                line=anchor.lineno,
                label=label,
                model=model,
                imported_from=imports.get(model),
                excluded=excluded,
                read_only=read_only,
                builtin_user=builtin,
            )
        )

    def _fastapi_handler(self, rel: str, node: ast.FunctionDef | ast.AsyncFunctionDef, imports: dict[str, str]) -> None:
        method = ""
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and dec.func.attr in _FASTAPI_WRITE_METHODS:
                method = dec.func.attr.upper()
                break
        if not method:
            return
        positional = node.args.posonlyargs + node.args.args
        defaults: list[ast.AST | None] = [None] * (len(positional) - len(node.args.defaults))
        defaults += node.args.defaults + node.args.kw_defaults
        for arg, default in zip(positional + node.args.kwonlyargs, defaults):
            if arg.annotation is None:
                continue
            if isinstance(default, ast.Call) and _terminal_name(default.func) in _FASTAPI_INJECTED:
                continue  # `current_user: User = Depends(...)` is injected, not bound
            model = _terminal_name(arg.annotation)
            if not model:
                continue
            self.binders.append(
                _Binder(
                    file=rel,
                    line=arg.lineno,
                    label=f"{method} {node.name}({arg.arg})",
                    model=model,
                    imported_from=imports.get(model),
                    json_body=True,
                    requires_table=True,
                )
            )

    # --- Java / Kotlin -------------------------------------------------

    def add_jvm(self, rel: str, text: str) -> None:
        if not _JVM_GATE_RE.search(text):
            return
        entities = list(_JVM_ENTITY_RE.finditer(text))
        for i, match in enumerate(entities):
            end = entities[i + 1].start() if i + 1 < len(entities) else len(text)
            region = text[match.end():end]
            header = _JVM_CLASS_RE.search(region)
            if header is None:
                continue
            fields, read_only = _jvm_fields(region[header.end():], kotlin=rel.endswith(".kt"))
            self.models.setdefault(header.group(1), []).append(
                _ModelDef(
                    name=header.group(1), file=rel, fields=fields, bases=[], json_read_only=read_only, table=True
                )
            )

        if _SPRING_ALLOWED_FIELDS_RE.search(text):
            return  # an @InitBinder allow-list governs this controller's binds
        disallowed: set[str] = set()
        for match in _SPRING_DISALLOWED_FIELDS_RE.finditer(text):
            disallowed.update(_QUOTED_RE.findall(match.group(1)))
        for match in _SPRING_BIND_RE.finditer(text):
            kind = match.group(1)
            model = match.group(2) or match.group(5)
            param = match.group(3) or match.group(4)
            method = _spring_method(text, match.start())
            if method is None:
                continue
            self.binders.append(
                _Binder(
                    file=rel,
                    line=text.count("\n", 0, match.start()) + 1,
                    label=f"{method} @{kind} {param}",
                    model=model,
                    imported_from=None,
                    excluded=disallowed if kind == "ModelAttribute" else set(),
                    json_body=kind == "RequestBody",
                )
            )

    # --- resolution ----------------------------------------------------

    def findings(self) -> list[CodeWeakness]:
        out: list[CodeWeakness] = []
        for binder in self.binders:
            if binder.label in self.admin_forms:
                continue
            if binder.builtin_user:
                model_name, fields, json_ro = "User (django.contrib.auth)", set(_DJANGO_USER_FIELDS), set()
            else:
                model = self._resolve(binder.model, binder.file, binder.imported_from)
                if model is None:
                    continue
                if binder.requires_table and not model.table:
                    continue
                model_name, fields, json_ro = model.name, self._all_fields(model), model.json_read_only
            removed = binder.excluded | binder.read_only | (json_ro if binder.json_body else set())
            writable = _privileged({f for f in fields if f not in removed})
            if not writable:
                continue
            what = "binds every field of" if not binder.excluded else "binds all but the excluded fields of"
            out.append(
                CodeWeakness(
                    kind="mass_assignment",
                    file=binder.file,
                    line=binder.line,
                    evidence_text=(
                        f"{binder.label} {what} {model_name}; client-writable privileged field(s): "
                        + ", ".join(writable[:6])
                    ),
                    severity="high",
                    source_analyzer="weaknesses",
                )
            )
        return out

    def _resolve(self, name: str, from_file: str, imported_from: str | None) -> _ModelDef | None:
        # A Java binder never binds a Python class of the same name, or vice versa.
        jvm = _is_jvm(from_file)
        candidates = [c for c in self.models.get(name, []) if _is_jvm(c.file) == jvm]
        if not candidates:
            return None
        same = [c for c in candidates if c.file == from_file]
        if same:
            return same[0]
        if imported_from:
            matches = [c for c in candidates if _module_matches(c.file, from_file, imported_from)]
            if len(matches) == 1:
                return matches[0]
        return candidates[0] if len(candidates) == 1 else None

    def _all_fields(self, model: _ModelDef, depth: int = 0) -> set[str]:
        fields = set(model.fields)
        if depth >= 4:
            return fields
        for base in model.bases:
            builtin = _DJANGO_BUILTIN_BASES.get(base)
            if builtin is not None and base not in self.models:
                fields |= builtin
                continue
            parent = self._resolve(base, model.file, None)
            if parent is not None and parent is not model:
                fields |= self._all_fields(parent, depth + 1)
            elif builtin is not None:
                fields |= builtin
        return fields


# --- helpers ---------------------------------------------------------------


def _is_jvm(rel: str) -> bool:
    return rel.endswith(tuple(_JVM_SUFFIXES))


def _terminal_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _is_get_user_model(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and _terminal_name(node.func) == "get_user_model"


def _is_read_only_serializer_field(call: ast.Call) -> bool:
    if _terminal_name(call.func) in _READ_ONLY_SERIALIZER_FIELDS:
        return True
    return any(
        kw.arg == "read_only" and isinstance(kw.value, ast.Constant) and kw.value.value is True
        for kw in call.keywords
    )


def _dict_flag(node: ast.AST, key: str) -> bool:
    if not isinstance(node, ast.Dict):
        return False
    return any(
        isinstance(k, ast.Constant) and k.value == key and isinstance(v, ast.Constant) and v.value is True
        for k, v in zip(node.keys, node.values)
    )


def _string_items(node: ast.AST) -> set[str]:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return {e.value for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}
    return set()


def _python_imports(tree: ast.Module) -> dict[str, str]:
    """Name → source module for top-level `from X import Name` (relative
    imports keep their leading dots)."""
    out: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            module = "." * node.level + (node.module or "")
            for alias in node.names:
                out[alias.asname or alias.name] = module
    return out


def _module_matches(def_file: str, from_file: str, module: str) -> bool:
    """Does `from <module> import X` in ``from_file`` plausibly name ``def_file``?"""
    def_mod = def_file.replace("\\", "/").rsplit(".", 1)[0]
    def_mod = def_mod.removesuffix("/__init__").replace("/", ".")
    if module.startswith("."):
        level = len(module) - len(module.lstrip("."))
        base = from_file.replace("\\", "/").split("/")[:-1]
        base = base[: len(base) - (level - 1)] if level > 1 else base
        target = ".".join(base + ([module.lstrip(".")] if module.lstrip(".") else []))
        return def_mod == target
    return def_mod == module or def_mod.endswith("." + module)


def _jvm_fields(body: str, kotlin: bool) -> tuple[set[str], set[str]]:
    """Field names declared in a Java/Kotlin class body, and the subset a JSON
    body can't set. Line-based: a declaration ends with `;` (Java) or is a
    `val`/`var` property (Kotlin)."""
    fields: set[str] = set()
    read_only: set[str] = set()
    pending = ""
    for raw in body.splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if kotlin:
            names = _KOTLIN_PROPERTY_RE.findall(line)
            fields.update(names)
            if _JSON_READ_ONLY_RE.search(pending + line):
                read_only.update(names)
            pending = pending + line if line.startswith("@") and not names else ""
            continue
        if line.startswith("@") and not line.endswith(";"):
            pending += line
            continue
        annotations = pending + " ".join(_JVM_ANNOTATION_RE.findall(line))
        pending = ""
        decl = _JVM_ANNOTATION_RE.sub(" ", line)
        if not decl.rstrip().endswith(";"):
            continue
        decl = decl.rstrip()[:-1].split("=", 1)[0].strip()
        if "(" in decl or decl.startswith(("return", "import", "package", "throw")):
            continue
        tokens = decl.split()
        if len(tokens) < 2 or not tokens[-1].isidentifier():
            continue
        fields.add(tokens[-1])
        if _JSON_READ_ONLY_RE.search(annotations):
            read_only.add(tokens[-1])
    return fields, read_only


def _spring_method(text: str, offset: int) -> str | None:
    """The HTTP method of the mapping annotation the bound parameter belongs
    to, or None for a read (GET/DELETE) or when there's no mapping."""
    window = text[max(0, offset - 800):offset]
    mappings = list(_SPRING_MAPPING_RE.finditer(window))
    if not mappings:
        return None
    last = mappings[-1]
    verb = last.group(1).upper()
    if verb in ("GET", "DELETE"):
        return None
    if verb == "REQUEST":
        annotation = window[last.start():]
        if "RequestMethod.GET" in annotation or "RequestMethod.DELETE" in annotation:
            return None
        return "POST"
    return verb


def _iter_sources(root: Path):
    for path in walk_repo(root, prune=is_skipped_dir):
        if path.suffix not in _SUFFIXES or is_oversized(path):
            continue
        rel = path.relative_to(root).as_posix()
        if is_test_file(rel) or is_vendored_file(rel):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        yield rel, path.suffix, text


def analyze_mass_assignment(root: str | Path) -> list[CodeWeakness]:
    """Field-level mass-assignment weaknesses across the repo at ``root``."""
    index = _Index()
    for rel, suffix, text in _iter_sources(Path(root)):
        if suffix == ".py":
            index.add_python(rel, text)
        else:
            index.add_jvm(rel, text)
    return index.findings()


__all__ = ["PRIVILEGED_FIELDS", "analyze_mass_assignment"]
