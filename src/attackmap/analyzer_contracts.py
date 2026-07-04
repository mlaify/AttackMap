from __future__ import annotations

import re
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, Field, field_validator, model_validator

from .recon_models import ScanResult

# Phase-1 shared repository analyzer contract.
# Keep AnalyzerResult mapped to ScanResult for backward compatibility.
AnalyzerResult = ScanResult

# `name` must be a slug: lowercase letters, digits, hyphens. This is the
# entry-point key AttackMap uses to identify the analyzer, so it needs
# to be safe in URLs, filesystem paths, and CLI arguments.
_ANALYZER_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]*$")


class AnalyzerMetadata(BaseModel):
    """Static, self-describing metadata every analyzer exposes.

    Every analyzer plugin ships a `metadata: AnalyzerMetadata` attribute so
    core (and future tooling) can reason about the plugin without loading
    or running it. The field set is stable: adding fields is safe on a
    minor release, removing or renaming is a major-version break.
    """

    name: str = Field(
        description="Slug identifier. Must match /[a-z0-9][a-z0-9-]*/. "
        "This is the entry-point key AttackMap uses to select the analyzer "
        "(e.g. from --module) and to attribute signals via provenance.",
    )
    display_name: str = Field(
        default="",
        description="Human-friendly name shown in `attackmap modules` output "
        "and reports. Defaults to `name` when omitted.",
    )
    version: str = Field(
        default="0.1.0",
        description="Semver of the analyzer plugin itself (not attackmap). "
        "Should match the analyzer package's pyproject.toml version.",
    )
    description: str = Field(
        default="",
        description="One-sentence summary of what the analyzer detects. "
        "Shown in module listings and matter briefings.",
    )
    scope: str = Field(
        default="",
        description="One-sentence description of the kinds of repositories "
        "this analyzer targets (e.g. 'Node/TypeScript backend service repos').",
    )
    targets: list[str] = Field(
        default_factory=list,
        description="Frameworks, protocols, or platform tokens this analyzer "
        "specializes in (e.g. ['react-native', 'expo']). Used with `languages` "
        "to compute `ecosystems`.",
    )
    languages: list[str] = Field(
        default_factory=list,
        description="Programming languages this analyzer parses (e.g. "
        "['javascript', 'typescript']). Used with `targets` to compute "
        "`ecosystems`.",
    )
    priority: int = Field(
        default=100,
        ge=0,
        description="Discovery ordering hint. Lower runs first when multiple "
        "analyzers match. Ties are broken by entry-point name. Convention: "
        "0-49 is broad language analyzers (python, node-service); 50-149 is "
        "framework analyzers (spring, laminas); 150+ is app-specific "
        "analyzers (omeka-s).",
    )
    experimental: bool = Field(
        default=True,
        description="Whether this analyzer is still stabilizing. Doesn't "
        "affect execution, just how core presents it in listings.",
    )
    enabled_by_default: bool = Field(
        default=False,
        description="Whether to run this analyzer without an explicit "
        "--module flag. Broad language analyzers set this True; specialty "
        "framework/app analyzers usually leave it False.",
    )

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        if not value:
            raise ValueError("AnalyzerMetadata.name must not be empty")
        if not _ANALYZER_NAME_PATTERN.match(value):
            raise ValueError(
                f"AnalyzerMetadata.name {value!r} must match "
                f"/{_ANALYZER_NAME_PATTERN.pattern}/ — lowercase letters, "
                f"digits, and hyphens only, starting with a letter or digit."
            )
        return value

    @field_validator("version")
    @classmethod
    def _validate_version(cls, value: str) -> str:
        if not value:
            raise ValueError("AnalyzerMetadata.version must not be empty")
        return value

    @model_validator(mode="before")
    @classmethod
    def _coerce_legacy_ecosystems(cls, value: object) -> object:
        if not isinstance(value, dict):
            return value
        payload = dict(value)
        # Backward-compat: older call sites may pass ecosystems directly.
        # Use it as a fallback source for languages when newer fields are omitted.
        ecosystems = payload.pop("ecosystems", None)
        if ecosystems and not payload.get("languages") and not payload.get("targets"):
            payload["languages"] = list(ecosystems)
        if not payload.get("display_name") and payload.get("name"):
            payload["display_name"] = str(payload["name"])
        return payload

    @property
    def ecosystems(self) -> tuple[str, ...]:
        """Deduplicated tuple of languages + targets, lowercased.

        Convenience view for callers that don't care about the language vs
        target distinction (e.g. picking analyzers by ecosystem token).
        """
        values = [*self.languages, *self.targets]
        seen: set[str] = set()
        ordered: list[str] = []
        for value in values:
            lowered = value.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            ordered.append(lowered)
        return tuple(ordered)


class AnalyzerRepositoryModule(BaseModel):
    analyzer_name: str
    repo_name: str
    web_url: str


class AnalyzerProtocol(Protocol):
    metadata: AnalyzerMetadata

    @property
    def name(self) -> str: ...

    def detect(self, root: str | Path) -> bool: ...

    def analyze(self, root: str | Path) -> AnalyzerResult: ...


__all__ = [
    "AnalyzerResult",
    "AnalyzerMetadata",
    "AnalyzerRepositoryModule",
    "AnalyzerProtocol",
    "normalize_analyzer_metadata",
]


def normalize_analyzer_metadata(value: object) -> AnalyzerMetadata:
    if isinstance(value, AnalyzerMetadata):
        return value
    if isinstance(value, dict):
        return AnalyzerMetadata.model_validate(value)

    payload: dict[str, object] = {}
    for key in (
        "name",
        "display_name",
        "version",
        "description",
        "scope",
        "targets",
        "languages",
        "priority",
        "experimental",
        "enabled_by_default",
        "ecosystems",
    ):
        if hasattr(value, key):
            payload[key] = getattr(value, key)
    return AnalyzerMetadata.model_validate(payload)
