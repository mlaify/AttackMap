"""Public analyzer API resolves its type hints (#231).

Doc generators and the SDK contract checks (#201) call ``typing.get_type_hints``;
an annotation naming something that isn't imported raises ``NameError`` there
even though ``from __future__ import annotations`` hides it at runtime. Names in
local annotations are covered by ruff's F821 in CI instead.
"""

from __future__ import annotations

import inspect
import typing

import pytest
from pydantic import BaseModel

import attackmap.analyzers as analyzers
import attackmap.threat_model as threat_model


def _public_functions(module):
    for name, obj in vars(module).items():
        if name.startswith("_") or getattr(obj, "__module__", None) != module.__name__:
            continue
        if inspect.isfunction(obj):
            yield name, obj
        elif inspect.isclass(obj) and not issubclass(obj, BaseModel):
            for attr, member in vars(obj).items():
                if inspect.isfunction(member) and not attr.startswith("_"):
                    yield f"{name}.{attr}", member


@pytest.mark.parametrize("module", [analyzers, threat_model], ids=lambda m: m.__name__)
def test_public_functions_resolve_type_hints(module) -> None:
    failures = []
    for name, func in _public_functions(module):
        try:
            typing.get_type_hints(func)
        except NameError as exc:
            failures.append(f"{name}: {exc}")
    assert not failures
