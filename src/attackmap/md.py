"""Markdown escaping for repo-derived text (#233, part B).

Route paths, file names, dependency names and evidence snippets come from the
repository under review and end up in Markdown that a bot posts with
repository authority (PR comments) or that reviewers open in a rendered
viewer. Interpolated raw, a route like
``/x](https://evil.example/login) <img src=…> @org/security-team`` renders as a
phishing link, a tracking pixel and a mass ping. Every untrusted value is
passed through :func:`md_text` (inline prose) or :func:`md_code` (a code span)
before it is concatenated into Markdown, and LLM-written Markdown through
:func:`sanitize_llm_markdown`.
"""

from __future__ import annotations

import re

# Bidi overrides/isolates, zero-width and other invisible format characters,
# and C0/C1 controls except tab/newline. Shown as visible \uXXXX escapes.
_INVISIBLE = re.compile(r"[\u0000-\u0008\u000b-\u001f\u007f-\u009f​-‏‪-‮⁠-⁤⁦-⁩﻿]")
_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+!|~<>])")
_MENTION = re.compile(r"@(?=[A-Za-z0-9])")
_AUTOLINK = re.compile(r"(?i)\b(https?|ftp|file|javascript|data)://")
_WWW = re.compile(r"(?i)\bwww\.")
_ZWSP = "&#8203;"  # an entity, so no raw invisible character lands in the file


def _visible(text: str) -> str:
    return _INVISIBLE.sub(lambda m: f"\\u{ord(m.group(0)):04x}", text)


def md_text(value: object) -> str:
    """Escape an untrusted value for inline Markdown prose.

    Markdown/HTML metacharacters are backslash-escaped, ``@mentions`` and
    URL autolinks are broken with a zero-width space entity, invisible and
    bidi characters are shown escaped, and newlines are flattened.
    """
    text = _visible(str(value)).replace("\r", " ").replace("\n", " ")
    text = text.replace("&", "&amp;")
    text = _MD_SPECIAL.sub(r"\\\1", text)
    text = _MENTION.sub("@" + _ZWSP, text)
    text = _AUTOLINK.sub(lambda m: f"{m.group(1)}:{_ZWSP}//", text)
    return _WWW.sub(lambda m: m.group(0)[:3] + _ZWSP + ".", text)


def md_code(value: object) -> str:
    """Render an untrusted value as a single inline code span.

    Nothing inside a code span is interpreted (no links, HTML, mentions). The
    backtick fence is made longer than any backtick run in the value, so the
    span can't be closed early.
    """
    text = _visible(str(value)).replace("\r", " ").replace("\n", " ")
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") or not text.strip() else ""
    return f"{fence}{pad}{text}{pad}{fence}"


_CODE_SPAN = re.compile(r"(`+)(.+?)\1")
_RAW_TAG_START = re.compile(r"(?<!\\)<(?=[A-Za-z!/?])")
_RAW_LINK = re.compile(r"(?<!\\)\]\(")
_RAW_IMAGE = re.compile(r"(?<!\\)!\[")
_LIVE_MENTION = re.compile(r"(?<![\w;\\])@(?=[A-Za-z0-9])")


def _defang_prose(text: str) -> str:
    text = _RAW_TAG_START.sub(r"\\<", text)
    text = _RAW_LINK.sub(r"]\\(", text)
    text = _RAW_IMAGE.sub(r"\\![", text)
    text = _LIVE_MENTION.sub("@" + _ZWSP, text)
    return _AUTOLINK.sub(lambda m: f"{m.group(1)}:{_ZWSP}//", text)


def defang_markdown(markdown: str) -> str:
    """Backstop for a whole AttackMap-generated document that contains no
    intentional links or HTML (e.g. defensive-review.md): outside code spans,
    raw HTML, links, images, mentions and autolinks are neutralized, and
    invisible/bidi characters are shown escaped everywhere. Idempotent."""
    text = _visible(markdown)
    out: list[str] = []
    pos = 0
    for match in _CODE_SPAN.finditer(text):
        out.append(_defang_prose(text[pos : match.start()]))
        out.append(match.group(0))
        pos = match.end()
    out.append(_defang_prose(text[pos:]))
    return "".join(out)


_HTML_TAG = re.compile(r"</?[A-Za-z][^>\n]*>|<!--.*?-->", re.DOTALL)
_MD_IMAGE = re.compile(r"!\[([^\]\n]*)\]\(([^)\n]*)\)")
_MD_LINK = re.compile(r"(?<!!)\[([^\]\n]+)\]\(([^)\n]*)\)")


def sanitize_llm_markdown(markdown: str, *, max_chars: int = 200_000) -> str:
    """Defang Markdown written by an LLM that read untrusted repo content.

    Raw HTML is removed, images are dropped, links become ``text (url)``
    plain text with the URL defanged, mentions are broken, and invisible
    characters are shown escaped. Headings, lists, emphasis and code are
    kept, since that is the report's structure.
    """
    text = _visible(markdown[:max_chars])
    text = _HTML_TAG.sub("", text)
    text = _MD_IMAGE.sub(lambda m: f"[image removed: {m.group(1)}]", text)
    text = _MD_LINK.sub(lambda m: f"{m.group(1)} ({m.group(2)})", text)
    text = _MENTION.sub("@" + _ZWSP, text)
    text = _AUTOLINK.sub(lambda m: f"{m.group(1)}:{_ZWSP}//", text)
    if len(markdown) > max_chars:
        text += "\n\n_[output truncated]_\n"
    return text
