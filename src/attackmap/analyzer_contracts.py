from __future__ import annotations

from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, Field, model_validator

from .recon_models import ScanResult

# Phase-1 shared repository analyzer contract.
# Keep AnalyzerResult mapped to ScanResult for backward compatibility.
AnalyzerResult = ScanResult


class AnalyzerMetadata(BaseModel):
    name: str
    display_name: str = ""
    version: str = "0.1.0"
    description: str = ""
    scope: str = ""
    targets: list[str] = Field(default_factory=list)
    languages: list[str] = Field(default_factory=list)
    priority: int = 100
    experimental: bool = True
    enabled_by_default: bool = False

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
