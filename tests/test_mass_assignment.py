"""Field-level mass assignment (#242, part 2): binders that look scoped but
let a client write a privileged model field."""

from __future__ import annotations

from pathlib import Path

import pytest

from attackmap.mass_assignment import analyze_mass_assignment
from attackmap.scanner import scan_repo
from attackmap.threat_model import generate_findings
from attackmap.weaknesses import find_code_weaknesses

FIXTURES = Path(__file__).parent / "fixtures" / "mass_assignment"


def _flagged(case: str) -> set[tuple[str, int]]:
    return {(w.file, w.line) for w in analyze_mass_assignment(FIXTURES / case)}


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


# ---------------------------------------------------------------------------
# Django / DRF
# ---------------------------------------------------------------------------


def test_drf_all_fields_on_model_with_is_staff_is_flagged() -> None:
    # The #242 acceptance case: the model is in another file.
    weaknesses = analyze_mass_assignment(FIXTURES / "drf_all")
    serializer = [w for w in weaknesses if w.file == "accounts/serializers.py" and w.line == 10]
    assert len(serializer) == 1
    assert serializer[0].kind == "mass_assignment"
    assert "is_staff" in (serializer[0].evidence_text or "")
    assert "AccountSerializer" in (serializer[0].evidence_text or "")


def test_django_binders_flagged() -> None:
    assert _flagged("drf_all") == {
        ("accounts/serializers.py", 10),  # fields = "__all__"
        ("accounts/serializers.py", 16),  # exclude list on an AbstractUser subclass
        ("accounts/forms.py", 9),  # ModelForm on django.contrib.auth User
        ("shop/views.py", 9),  # UpdateView with fields = "__all__"
    }


def test_django_safe_binders_not_flagged() -> None:
    # Explicit field lists, read_only_fields / read_only=True / extra_kwargs,
    # exclude covering every privileged field, a model with no privileged
    # field, a FilterSet and graphene type (reads only), a graphene mutation
    # (its input type sets the fields), and a form used only
    # by a Django ModelAdmin.
    assert _flagged("drf_safe") == set()


def test_get_user_model_is_django_user(tmp_path: Path) -> None:
    root = _write(tmp_path, {
        "s.py": (
            "from django.contrib.auth import get_user_model\n"
            "from rest_framework import serializers\n"
            "User = get_user_model()\n"
            "class S(serializers.ModelSerializer):\n"
            "    class Meta:\n"
            "        model = User\n"
            "        fields = '__all__'\n"
        ),
    })
    weaknesses = analyze_mass_assignment(root)
    assert [(w.file, w.line) for w in weaknesses] == [("s.py", 7)]


def test_ambiguous_model_name_resolved_by_import(tmp_path: Path) -> None:
    root = _write(tmp_path, {
        "billing/models.py": "from django.db import models\nclass Account(models.Model):\n    balance = models.IntegerField()\n",
        "blog/models.py": "from django.db import models\nclass Account(models.Model):\n    title = models.CharField()\n",
        "blog/serializers.py": (
            "from rest_framework import serializers\n"
            "from blog.models import Account\n"
            "class S(serializers.ModelSerializer):\n"
            "    class Meta:\n"
            "        model = Account\n"
            "        fields = '__all__'\n"
        ),
        "billing/serializers.py": (
            "from rest_framework import serializers\n"
            "from .models import Account\n"
            "class S(serializers.ModelSerializer):\n"
            "    class Meta:\n"
            "        model = Account\n"
            "        fields = '__all__'\n"
        ),
    })
    assert {(w.file, w.line) for w in analyze_mass_assignment(root)} == {("billing/serializers.py", 6)}


def test_camel_case_privileged_field_matches() -> None:
    from attackmap.mass_assignment import _privileged

    assert _privileged({"isAdmin", "tenantId", "name", "title"}) == ["isAdmin", "tenantId"]


# ---------------------------------------------------------------------------
# SQLModel / FastAPI
# ---------------------------------------------------------------------------


def test_sqlmodel_table_model_as_write_body_is_flagged() -> None:
    # The table model as a POST body is flagged; a separate DTO and a GET are not.
    weaknesses = analyze_mass_assignment(FIXTURES / "sqlmodel")
    assert [(w.file, w.line) for w in weaknesses] == [("app/main.py", 10)]
    assert "is_admin" in (weaknesses[0].evidence_text or "")


def test_plain_pydantic_body_with_role_not_flagged(tmp_path: Path) -> None:
    root = _write(tmp_path, {
        "main.py": (
            "from pydantic import BaseModel\n"
            "class Invite(BaseModel):\n"
            "    email: str\n"
            "    role: str\n"
            "@app.post('/invites')\n"
            "def invite(body: Invite):\n"
            "    pass\n"
        ),
    })
    assert analyze_mass_assignment(root) == []


def test_fastapi_dependency_injected_table_model_not_flagged(tmp_path: Path) -> None:
    root = _write(tmp_path, {
        "main.py": (
            "from sqlmodel import SQLModel\n"
            "class User(SQLModel, table=True):\n"
            "    id: int\n"
            "    role: str\n"
            "@app.post('/notes')\n"
            "def create(note: str, current_user: User = Depends(get_current_user), *, me: User = Security(auth)):\n"
            "    pass\n"
            "@app.patch('/me')\n"
            "def update(patch: User, current_user: User = Depends(get_current_user)):\n"
            "    pass\n"
        ),
    })
    assert [(w.file, w.line) for w in analyze_mass_assignment(root)] == [("main.py", 9)]


# ---------------------------------------------------------------------------
# Spring
# ---------------------------------------------------------------------------


def test_spring_entity_binds_flagged() -> None:
    # @ModelAttribute and @RequestBody into an @Entity on write mappings; the
    # GET search binding is not flagged.
    assert _flagged("spring") == {
        ("src/main/java/com/example/UserController.java", 10),
        ("src/main/java/com/example/UserController.java", 15),
    }


def test_spring_safe_binds_not_flagged() -> None:
    # @JsonIgnore on the privileged field, a DTO, and an @InitBinder allow-list.
    assert _flagged("spring_safe") == set()


def test_kotlin_entity(tmp_path: Path) -> None:
    root = _write(tmp_path, {
        "User.kt": "@Entity\nclass User(@Id val id: Long, var role: String)\n",
        "UserController.kt": (
            "@RestController\nclass UserController {\n"
            "    @PostMapping(\"/users\")\n"
            "    fun create(@RequestBody user: User): User = user\n}\n"
        ),
    })
    assert [(w.file, w.line) for w in analyze_mass_assignment(root)] == [("UserController.kt", 4)]


def test_model_names_do_not_resolve_across_languages(tmp_path: Path) -> None:
    root = _write(tmp_path, {
        "py/models.py": "from sqlmodel import SQLModel\nclass Account(SQLModel, table=True):\n    role: str\n",
        "C.java": (
            "@RestController\npublic class C {\n"
            "    @PostMapping(\"/a\")\n    public Account a(@RequestBody Account account) { return account; }\n}\n"
        ),
    })
    assert analyze_mass_assignment(root) == []


def test_spring_disallowed_fields_subtracted(tmp_path: Path) -> None:
    root = _write(tmp_path, {
        "User.java": "@Entity\npublic class User {\n    private String role;\n}\n",
        "C.java": (
            "@Controller\npublic class C {\n"
            "    @InitBinder\n    void b(WebDataBinder binder) { binder.setDisallowedFields(\"role\"); }\n"
            "    @PostMapping(\"/u\")\n    public String s(@ModelAttribute User user) { return \"\"; }\n}\n"
        ),
    })
    assert analyze_mass_assignment(root) == []


# ---------------------------------------------------------------------------
# Mongoose / Sequelize (per-file patterns in weaknesses.py)
# ---------------------------------------------------------------------------


def _js_lines(rel: str) -> set[int]:
    text = (FIXTURES / "node" / rel).read_text(encoding="utf-8")
    return {w.line for w in find_code_weaknesses(text, rel) if w.kind == "mass_assignment"}


def test_mongoose_update_document_and_sequelize_without_fields_flagged() -> None:
    assert _js_lines("routes.js") == {3, 8, 13}


def test_sequelize_fields_allowlist_and_picked_fields_not_flagged() -> None:
    assert _js_lines("routes_safe.js") == set()


@pytest.mark.parametrize(
    "content",
    [
        "Post.findOneAndUpdate({ slug }, req.body)\n",
        "Doc.replaceOne(filter, request.body)\n",
        "User.updateMany(new ObjectId(id), { $set: req.body })\n",
    ],
)
def test_mongoose_variants(content: str) -> None:
    assert any(w.kind == "mass_assignment" for w in find_code_weaknesses(content, "f.js"))


def test_sequelize_fields_in_a_nested_where_still_counts_as_allowlist() -> None:
    # `fields:` anywhere in the options object is the allow-list.
    content = "Model.create(req.body, { transaction: t, fields: ['a'] })\n"
    assert not any(w.kind == "mass_assignment" for w in find_code_weaknesses(content, "f.js"))


def test_unclosed_call_is_bounded() -> None:
    content = "Model.create(req.body, " + "(" * 50_000
    assert any(w.kind == "mass_assignment" for w in find_code_weaknesses(content, "f.js"))


# ---------------------------------------------------------------------------
# Robustness and end-to-end
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "files",
    [
        {"a.py": "class A(:\n    fields = '__all__'\n"},
        {"a.py": "class " + "(" * 5000},
        {"a.py": "x = " + "[" * 200_000 + "]" * 200_000 + "\nclass A: pass\n"},
        {"A.java": "@Entity\n" + "class " * 3000},
        {"A.java": "@Entity class\n@RequestBody\n@ModelAttribute"},
        {"A.kt": "@Entity\nclass X(" + "val a: Int, " * 5000},
    ],
)
def test_malformed_input_never_raises(tmp_path: Path, files: dict[str, str]) -> None:
    analyze_mass_assignment(_write(tmp_path, files))


def test_test_files_are_skipped(tmp_path: Path) -> None:
    root = _write(tmp_path, {
        "tests/test_api.py": (
            "from django.contrib.auth.models import User\n"
            "class S(serializers.ModelSerializer):\n"
            "    class Meta:\n"
            "        model = User\n"
            "        fields = '__all__'\n"
        ),
    })
    assert analyze_mass_assignment(root) == []


def test_scan_repo_reports_field_level_mass_assignment() -> None:
    scan = scan_repo(FIXTURES / "drf_all")
    assert any(
        w.kind == "mass_assignment" and w.file == "accounts/serializers.py" for w in scan.code_weaknesses
    )
    finding = next(f for f in generate_findings(scan) if f.rule_id == "mass-assignment")
    assert any("accounts/serializers.py:10" in e for e in finding.evidence)
