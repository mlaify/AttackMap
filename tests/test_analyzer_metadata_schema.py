"""Tests for the AnalyzerMetadata schema (#8).

The schema is the public contract every analyzer plugin depends on. These
tests pin it so a refactor can't silently drop a field or loosen a
validator that the 13 published plugins rely on.
"""

from __future__ import annotations

import pytest

from attackmap.analyzer_contracts import (
    AnalyzerMetadata,
    normalize_analyzer_metadata,
)
from attackmap.analyzers import get_registered_analyzers


# ---------------------------------------------------------------------------
# Required fields exist with the documented defaults
# ---------------------------------------------------------------------------


REQUIRED_FIELDS: dict[str, object] = {
    # name has no default — every analyzer must set it.
    "name": ...,
    "display_name": "",
    "version": "0.1.0",
    "description": "",
    "scope": "",
    "targets": [],
    "languages": [],
    "priority": 100,
    "experimental": True,
    "enabled_by_default": False,
}


def test_schema_declares_every_field_the_issue_required() -> None:
    """#8 acceptance criteria list 10 required fields. Fail loud if a
    future refactor drops one."""
    declared = set(AnalyzerMetadata.model_fields.keys())
    required = set(REQUIRED_FIELDS.keys())
    missing = required - declared
    assert not missing, f"AnalyzerMetadata missing required fields: {missing}"


def test_defaults_match_documented_values() -> None:
    """`name` has no default (required); every other field has the
    documented default so plugins can omit them safely."""
    m = AnalyzerMetadata(name="example-analyzer")
    for field, expected in REQUIRED_FIELDS.items():
        if expected is ... or field == "display_name":
            # display_name gets special legacy coercion (falls back to
            # `name` when omitted) — see test_display_name_defaults_to_name.
            continue
        assert getattr(m, field) == expected, (
            f"AnalyzerMetadata.{field} default changed from {expected!r} "
            f"to {getattr(m, field)!r}"
        )


def test_every_field_has_a_description() -> None:
    """Schema is self-documenting via `.model_json_schema()`. Fail if a
    new field slips in without a description; the metadata JSON schema
    is a documented consumer of these."""
    for name, field in AnalyzerMetadata.model_fields.items():
        assert field.description, f"AnalyzerMetadata.{name} is missing a description"


def test_json_schema_output_carries_the_field_descriptions() -> None:
    """External tooling (e.g. registry pages) consumes
    `model_json_schema()`; descriptions must survive to JSON."""
    schema = AnalyzerMetadata.model_json_schema()
    props = schema["properties"]
    for field in REQUIRED_FIELDS:
        assert "description" in props[field], (
            f"AnalyzerMetadata.{field} description missing from JSON schema"
        )


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def test_name_must_be_a_slug() -> None:
    """`name` is a slug — it appears in --module flags and provenance,
    so no whitespace, no uppercase, no path separators."""
    valid_names = ["python", "attackmap-analyzer-x", "omeka-s", "c", "php-web"]
    for name in valid_names:
        AnalyzerMetadata(name=name)  # must not raise

    invalid_names = [
        "",              # empty
        "My Analyzer",   # whitespace
        "MyAnalyzer",    # uppercase
        "sub/dir",       # path separator
        "-leading",      # leading hyphen
        "trailing space ",
    ]
    for name in invalid_names:
        with pytest.raises(Exception):
            AnalyzerMetadata(name=name)


def test_version_must_not_be_empty() -> None:
    with pytest.raises(Exception):
        AnalyzerMetadata(name="ok", version="")


def test_priority_must_be_non_negative() -> None:
    AnalyzerMetadata(name="ok", priority=0)
    AnalyzerMetadata(name="ok", priority=999)
    with pytest.raises(Exception):
        AnalyzerMetadata(name="ok", priority=-1)


# ---------------------------------------------------------------------------
# ecosystems property + legacy coercion still work
# ---------------------------------------------------------------------------


def test_ecosystems_combines_languages_and_targets_deduped_lowercase() -> None:
    m = AnalyzerMetadata(
        name="mixed",
        languages=["Python", "typescript"],
        targets=["FastAPI", "python"],
    )
    # dedup + lowercase
    assert m.ecosystems == ("python", "typescript", "fastapi")


def test_legacy_ecosystems_key_coerces_into_languages() -> None:
    m = AnalyzerMetadata.model_validate({"name": "legacy", "ecosystems": ["python"]})
    assert m.languages == ["python"]


def test_display_name_defaults_to_name_when_omitted() -> None:
    m = AnalyzerMetadata.model_validate({"name": "myplug"})
    assert m.display_name == "myplug"


# ---------------------------------------------------------------------------
# normalize_analyzer_metadata handles plugin-shaped inputs
# ---------------------------------------------------------------------------


class _DuckMeta:
    name = "duck"
    display_name = "Duck"
    version = "0.3.0"
    description = "d"
    scope = "s"
    targets = ["x"]
    languages = ["y"]
    priority = 25
    experimental = False
    enabled_by_default = True


def test_normalize_reads_duck_typed_metadata_object() -> None:
    m = normalize_analyzer_metadata(_DuckMeta())
    assert isinstance(m, AnalyzerMetadata)
    assert m.name == "duck"
    assert m.priority == 25
    assert m.enabled_by_default is True


def test_normalize_passes_through_analyzer_metadata_unchanged() -> None:
    original = AnalyzerMetadata(name="x", version="1.2.3")
    assert normalize_analyzer_metadata(original) is original


# ---------------------------------------------------------------------------
# Every registered built-in analyzer validates against the schema
# ---------------------------------------------------------------------------


def test_all_registered_analyzers_have_valid_metadata() -> None:
    """Every analyzer that AttackMap discovers via entry points (built-in
    or externally installed) must expose metadata that satisfies the
    schema. Guards against a plugin shipping metadata that would silently
    fall over inside `normalize_analyzer_metadata`."""
    for analyzer in get_registered_analyzers():
        m = analyzer.metadata
        assert isinstance(m, AnalyzerMetadata), (
            f"{type(analyzer).__name__}.metadata is {type(m).__name__}, "
            f"expected AnalyzerMetadata"
        )
        # Names must be slugs (contract asserted by validator, but check
        # explicitly against the live registry to be sure).
        assert m.name
        assert m.version
