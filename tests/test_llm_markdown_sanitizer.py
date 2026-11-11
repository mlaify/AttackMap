"""`sanitize_llm_markdown` must neutralise every link, image and tag form a
prompt-injected model could emit, and leave code untouched."""

from __future__ import annotations

import re

import pytest

from attackmap.md import sanitize_llm_markdown


@pytest.mark.parametrize(
    "payload",
    [
        '<a\nhref="//evil.example/x">text</a>',
        '<img\nsrc="//evil.example/p.png">',
        "[Fix\\]it](//evil.example/x)",
        "[Fix\nit](//evil.example/x)",
        "[a [b] c](//evil.example/x)",
        "See [text][r].\n\n[r]: //evil.example/x",
        "![pix][r]\n\n   [r]: //evil.example/p.png",
        "[text](https://evil.example/x)",
        "[text](//evil.example/x)",
    ],
    ids=["tag-newline", "img-newline", "escaped-bracket", "newline-in-text", "nested", "ref-link", "ref-image", "plain-link", "protocol-relative"],
)
def test_sanitize_llm_markdown_neutralizes_unusual_link_forms(payload: str) -> None:
    out = sanitize_llm_markdown(payload)
    assert "<a" not in out and "<img" not in out
    assert not re.search(r"(?<!\\)\]\(", out), out
    assert not re.search(r"(?m)^[ \t]{0,3}\[[^\]]*\]:", out), out  # no live reference definition
    assert re.search(r"(?<!&#8203;)//evil", out) is None, out  # every destination is defanged


def test_sanitize_llm_markdown_keeps_code_verbatim() -> None:
    doc = (
        "Use `#include <stdio.h>` and `a // b`.\n\n"
        "```c\n#include <stdio.h>\nchar *u = \"https://example.test/x\"; // [see](//host)\n```\n\n"
        "~~~\n<b>raw</b> [x](//y)\n~~~\n\nAfter: <b>bold</b> [x](//evil.example)\n"
    )
    out = sanitize_llm_markdown(doc)
    assert "`#include <stdio.h>`" in out and "`a // b`" in out
    assert "```c\n#include <stdio.h>\nchar *u = \"https://example.test/x\"; // [see](//host)\n```" in out
    assert "~~~\n<b>raw</b> [x](//y)\n~~~" in out
    assert "<b>bold</b>" not in out and "x (/&#8203;/evil.example)" in out


def test_sanitize_llm_markdown_unclosed_fence_is_code_to_the_end() -> None:
    out = sanitize_llm_markdown("text <b>x</b>\n```\n<b>kept</b>\n")
    assert out == "text x\n```\n<b>kept</b>\n"
