"""The line range a route handler owns in its source file.

A handler's span runs from its route declaration down to just before the next
route in the same file (its own body), so one handler's decorator or body
never bleeds into a sibling's window. It is capped so a huge handler doesn't
swallow the file, and extended upward over contiguous ``@decorator`` lines for
the auth-decorator-above-``@route`` idiom.

Shared by the anomaly detector, authorization depth (#242) and webhook
verification (#243), which all need "is X present in *this* handler" rather
than "anywhere in the file".
"""

from __future__ import annotations

MAX_SPAN = 40
DECORATOR_LOOKUP = 6


def span_bounds(
    line: int, lines: list[str], route_lines: list[int], *, max_span: int = MAX_SPAN
) -> tuple[int, int]:
    """Return the 0-based [start, end) slice of ``lines`` owned by the handler
    declared at 1-based ``line``.

    ``route_lines`` are the 1-based declaration lines of every route in the
    same file (any order is fine). ``max_span`` caps the window; callers that
    must see a whole handler body (authorization depth) pass a larger cap.
    """
    ordered = sorted(route_lines)
    idx = line - 1  # 0-based route declaration line
    # End at the next route declaration in the file (its decorators/body
    # belong to it), capped so a huge handler can't swallow the file.
    next_line = next((ln for ln in ordered if ln > line), None)
    end = min(len(lines), line - 1 + max_span)
    if next_line is not None:
        end = min(end, next_line - 1)
        # The decorators stacked on the next route belong to it, not to us.
        while end - 1 > idx and lines[end - 1].lstrip().startswith("@"):
            end -= 1
    # Extend upward over contiguous decorator lines (auth decorator placed
    # above the @route decorator), but not past the previous route.
    prev_line = next((ln for ln in reversed(ordered) if ln < line), 0)
    start = idx
    limit = max(prev_line, idx - DECORATOR_LOOKUP)
    while start - 1 >= limit and lines[start - 1].lstrip().startswith("@"):
        start -= 1
    return max(0, start), max(start + 1, end)


def span_text(
    line: int | None, lines: list[str], route_lines: list[int], *, max_span: int = MAX_SPAN
) -> str:
    """The source text of the handler declared at ``line``; the whole file
    when the route has no line."""
    if line is None:
        return "\n".join(lines)
    start, end = span_bounds(line, lines, route_lines, max_span=max_span)
    return "\n".join(lines[start:end])


__all__ = ["DECORATOR_LOOKUP", "MAX_SPAN", "span_bounds", "span_text"]
