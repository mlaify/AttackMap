from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


class Route(BaseModel):
    path: str
    method: str = "ANY"
    file: str


class ExternalCall(BaseModel):
    target: str
    file: str


class DatabaseHint(BaseModel):
    kind: str
    file: str


class AuthHint(BaseModel):
    hint: str
    file: str


class SecretHint(BaseModel):
    name: str
    file: str


class Finding(BaseModel):
    title: str
    severity: Literal["low", "medium", "high"]
    evidence: list[str] = Field(default_factory=list)
    mitigation: str
    confidence: Literal["low", "medium", "high"] = "medium"


class AttackPath(BaseModel):
    name: str
    steps: list[str]
    impact: str


class ScanResult(BaseModel):
    root: str
    languages: list[str] = Field(default_factory=list)
    routes: list[Route] = Field(default_factory=list)
    external_calls: list[ExternalCall] = Field(default_factory=list)
    databases: list[DatabaseHint] = Field(default_factory=list)
    auth_hints: list[AuthHint] = Field(default_factory=list)
    secret_hints: list[SecretHint] = Field(default_factory=list)
    files_scanned: int = 0

    @property
    def root_path(self) -> Path:
        return Path(self.root)
