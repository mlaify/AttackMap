"""Novel vulnerability-class detectors (#77).

Per-file finder (rides the built-in scanner's read loop) for bug classes
beyond the taint / crypto / web-hardening families. Part 1 covers:

    prototype_pollution  __proto__ writes; deep-merge of a request object
    mass_assignment      request object bound wholesale to a model
    jwt_weakness         alg=none / signature verification disabled
    xxe                  XML parser with external entities enabled

Precision-first: everything anchors on a concrete risky construct (not
absence), and request-object patterns name the request container
explicitly. ReDoS, insecure-upload, and GraphQL-exposure classes are
declared in the model but land in a follow-up.
"""

from __future__ import annotations

import re

from .models import CodeWeakness

_REQ = r"(?:req|request|body|query|params|payload)"


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE)


_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    # --- prototype pollution (JS/TS) ------------------------------------
    (
        "prototype_pollution",
        "high",
        # Literal __proto__ / constructor.prototype *write* (assignment target).
        # Requiring a trailing `=` (not `==`) avoids flagging prototype-chain
        # *reads* like `x.prototype.__proto__.constructor` (#94).
        _rx(
            r"(?:"
            r"\.__proto__"
            r"|\[\s*['\"]__proto__['\"]\s*\]"
            r"|\[\s*['\"]constructor['\"]\s*\]\s*\[\s*['\"]prototype['\"]\s*\]"
            r"|\.constructor\s*\.\s*prototype"
            r")"
            r"(?:\s*\.\s*\w+|\s*\[[^\]]*\])*"  # optional further member/subscript access
            r"\s*=(?!=)"
        ),
    ),
    (
        "prototype_pollution",
        "high",
        # Recursive merge of a request object into a target (lodash / deepmerge).
        _rx(rf"(?:_\.(?:merge|mergeWith|defaultsDeep|set|setWith)|deepmerge)\s*\([^)]*\b{_REQ}\b"),
    ),
    (
        "prototype_pollution",
        "high",
        # jQuery deep extend of a request object: $.extend(true, target, req.*)
        _rx(rf"\$\.extend\s*\(\s*true\b[^)]*\b{_REQ}\b"),
    ),
    # --- mass assignment ------------------------------------------------
    (
        "mass_assignment",
        "high",
        # Python: Model(**request.json) / .objects.create(**request.data) / .update(**req.form)
        _rx(rf"\(\s*\*\*\s*{_REQ}\.(?:json|data|POST|GET|form|args|get_json\s*\(\s*\))"),
    ),
    (
        "mass_assignment",
        "high",
        # JS: ORM-style bind of the whole body — .create(req.body) /
        # .update(req.body) / Object.assign(model, req.body).
        _rx(rf"(?:\.(?:create|update|updateOne|updateMany|insert|save|build)|Object\.assign\s*\([^,]+,)\s*\(?\s*{_REQ}\.body\b"),
    ),
    (
        "mass_assignment",
        "high",
        # JS: `new Model(req.body)` — excluding Web/std builtins that
        # legitimately take a body (Fetch Response/Request, Blob, URL, …).
        _rx(
            rf"new\s+(?!(?:Response|Request|Blob|File|FormData|Headers|URL|URLSearchParams|ReadableStream|Error|Buffer|Uint8Array|TextEncoder|TextDecoder)\b)\w+\s*\(\s*{_REQ}\.body\b"
        ),
    ),
    (
        "mass_assignment",
        "high",
        # Rails strong-params bypass.
        _rx(r"\.permit!\B|params\.permit!"),
    ),
    # --- JWT weaknesses -------------------------------------------------
    (
        "jwt_weakness",
        "high",
        # alg 'none' in an algorithms list (PyJWT + jsonwebtoken).
        _rx(r"algorithms?\s*[=:]\s*\[[^\]]*['\"]none['\"]"),
    ),
    (
        "jwt_weakness",
        "high",
        # signature verification turned off.
        _rx(r"jwt\.decode\s*\([^)]*verify\s*=\s*False|verify_signature['\"]?\s*[:=]\s*(?:false|False)|['\"]alg['\"]?\s*:\s*['\"]none['\"]"),
    ),
    # --- XXE ------------------------------------------------------------
    (
        "xxe",
        "high",
        _rx(
            r"resolve_entities\s*=\s*True"
            r"|\bload_dtd\s*=\s*True"
            r"|libxml_disable_entity_loader\s*\(\s*(?:false|0)\s*\)"
            r"|\.setExpandEntityReferences\s*\(\s*true\s*\)"
            r"|disallow-doctype-decl['\"]?\s*,\s*false"
            r"|FEATURE_SECURE_PROCESSING[^;\n]*false"
        ),
    ),
    # --- ReDoS (catastrophic backtracking) ------------------------------
    # A quantified group whose body also has a quantifier — (a+)+, (.*)*,
    # (\d+)*. Gated to a REGEX context (regex literal, re.* call, or
    # RegExp constructor) so arithmetic like `(x+1)*2` isn't flagged.
    (
        "redos",
        "medium",
        # JS regex literal: /.../ containing a nested quantifier.
        re.compile(r"/[^/\n]*\([^()\n]*[+*][^()\n]*\)[+*][^/\n]*/"),
    ),
    (
        "redos",
        "medium",
        # Python re.* with a nested-quantifier pattern string.
        re.compile(
            r"\bre\.(?:compile|match|search|fullmatch|findall|finditer|sub|subn|split)"
            r"\s*\(\s*[rbuRBU]*['\"][^'\"\n]*\([^()\n]*[+*][^()\n]*\)[+*]"
        ),
    ),
    (
        "redos",
        "medium",
        re.compile(r"\bnew\s+RegExp\s*\(\s*['\"][^'\"\n]*\([^()\n]*[+*][^()\n]*\)[+*]"),
    ),
    # --- insecure file upload -------------------------------------------
    (
        "insecure_upload",
        "high",
        # Werkzeug FileStorage saved with the client-supplied filename
        # (path traversal / overwrite), or Multer originalname into a write.
        _rx(
            r"\.save\s*\([^)]*\.filename\b"
            r"|(?:writeFile|writeFileSync|createWriteStream)\s*\([^)]*\.originalname\b"
            r"|path\.join\s*\([^)]*\.originalname\b"
        ),
    ),
    # --- GraphQL exposure -----------------------------------------------
    (
        "graphql_exposure",
        "low",
        _rx(
            r"\bintrospection\s*:\s*true"
            r"|\bgraphiql\s*[:=]\s*(?:true|True)"
            r"|\bplayground\s*:\s*true"
        ),
    ),
)


def find_code_weaknesses(content: str, rel_file: str) -> list[CodeWeakness]:
    """Return novel-class weaknesses in one file's ``content`` (deduped by
    (kind, line))."""
    seen: set[tuple[str, int]] = set()
    out: list[CodeWeakness] = []
    for kind, severity, pattern in _PATTERNS:
        for match in pattern.finditer(content):
            if _in_line_comment(content, match.start()):
                continue  # a pattern inside a `//` comment isn't real code (#94)
            line = content.count("\n", 0, match.start()) + 1
            key = (kind, line)
            if key in seen:
                continue
            seen.add(key)
            out.append(
                CodeWeakness(
                    kind=kind,  # type: ignore[arg-type]
                    file=rel_file,
                    line=line,
                    evidence_text=_snippet(content, match.start()),
                    severity=severity,  # type: ignore[arg-type]
                    source_analyzer="weaknesses",
                )
            )
    return out


def _in_line_comment(content: str, offset: int) -> bool:
    """True if ``offset`` falls after a `//` line comment on its line. Cheap
    heuristic (ignores `//` inside strings), used only to drop obvious
    comment-embedded matches like `// x.__proto__.y = z`."""
    line_start = content.rfind("\n", 0, offset) + 1
    return "//" in content[line_start:offset]


def _snippet(content: str, offset: int, radius: int = 120) -> str:
    start = max(0, content.rfind("\n", 0, offset) + 1)
    end = content.find("\n", offset)
    if end == -1:
        end = len(content)
    line = content[start:end].strip()
    return line[:radius] + ("…" if len(line) > radius else "")


__all__ = ["find_code_weaknesses"]
