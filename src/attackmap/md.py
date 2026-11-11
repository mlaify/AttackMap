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


def visible_text(value: object) -> str:
    """``value`` with control, invisible and bidi characters shown as visible
    ``\\uXXXX`` escapes (tab and newline kept), for non-Markdown outputs such
    as diagram labels: a raw ESC from a scanned repo would otherwise reach the
    terminal of whoever views the file."""
    return _visible(str(value))


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


# CommonMark allows line endings inside an HTML tag, so the tag pattern must
# not stop at a newline; a reference-link definition is `[label]: url` at the
# start of a line; a protocol-relative `//host/x` destination has no scheme
# for _AUTOLINK to break.
_HTML_TAG = re.compile(r"</?[A-Za-z][^<>]*>|<!--.*?-->", re.DOTALL)
_MD_IMAGE = re.compile(r"!\[([^\]\n]*)\]\(([^)\n]*)\)")
_MD_LINK = re.compile(r"(?<!!)\[([^\]\n]+)\]\(([^)\n]*)\)")
_REF_DEFINITION = re.compile(r"^([ \t]{0,3})\[(?=[^\]]*\]:)", re.MULTILINE)
_PROTOCOL_RELATIVE = re.compile(r"(?<![\w:/\\;])//(?=[A-Za-z0-9\[])")
_FENCE = re.compile(r"^(?P<indent>[ \t]{0,3})(?P<fence>`{3,}|~{3,})", re.MULTILINE)


def _sanitize_prose(text: str) -> str:
    """One stretch of LLM Markdown outside fenced code blocks and code spans."""
    text = _HTML_TAG.sub("", text)
    text = _MD_IMAGE.sub(lambda m: f"[image removed: {m.group(1)}]", text)
    text = _MD_LINK.sub(lambda m: f"{m.group(1)} ({m.group(2)})", text)
    # Whatever link syntax the two patterns above did not recognise (an
    # escaped `]` or a newline in the text, nested brackets, a reference
    # definition) is neutralised in place rather than parsed.
    text = _RAW_IMAGE.sub(r"\\![", text)
    text = _RAW_LINK.sub(r"]\\(", text)
    text = _REF_DEFINITION.sub(r"\1\\[", text)
    text = _MENTION.sub("@" + _ZWSP, text)
    text = _AUTOLINK.sub(lambda m: f"{m.group(1)}:{_ZWSP}//", text)
    return _PROTOCOL_RELATIVE.sub(f"/{_ZWSP}/", text)


def _sanitize_outside_code_spans(text: str) -> str:
    out: list[str] = []
    pos = 0
    for match in _CODE_SPAN.finditer(text):
        out.append(_sanitize_prose(text[pos : match.start()]))
        out.append(match.group(0))
        pos = match.end()
    out.append(_sanitize_prose(text[pos:]))
    return "".join(out)


def _split_fences(text: str) -> list[tuple[bool, str]]:
    """``(is_code, chunk)`` pairs: fenced code blocks (``` or ~~~, closed by a
    fence of the same character at least as long, or by the end of the text)
    are returned verbatim so their contents are never rewritten."""
    chunks: list[tuple[bool, str]] = []
    pos = 0
    while True:
        opening = _FENCE.search(text, pos)
        if opening is None:
            break
        fence = opening.group("fence")
        closer = re.compile(rf"^[ \t]{{0,3}}{re.escape(fence[0])}{{{len(fence)},}}[ \t]*$", re.MULTILINE)
        closing = closer.search(text, opening.end())
        end = len(text) if closing is None else closing.end()
        chunks.append((False, text[pos : opening.start()]))
        chunks.append((True, text[opening.start() : end]))
        pos = end
    chunks.append((False, text[pos:]))
    return chunks


def sanitize_llm_markdown(markdown: str, *, max_chars: int = 200_000) -> str:
    """Defang Markdown written by an LLM that read untrusted repo content.

    Outside fenced code blocks and code spans: raw HTML is removed, images
    are dropped, links become ``text (url)`` plain text with the URL
    defanged, every other link, image or reference-definition syntax is
    escaped in place, mentions are broken, and absolute and
    protocol-relative URLs are defanged. Invisible characters are shown
    escaped everywhere. Headings, lists, emphasis and code are kept, since
    that is the report's structure; code is kept verbatim.
    """
    text = _visible(markdown[:max_chars])
    text = "".join(chunk if is_code else _sanitize_outside_code_spans(chunk) for is_code, chunk in _split_fences(text))
    if len(markdown) > max_chars:
        text += "\n\n_[output truncated]_\n"
    return text
