"""Business-logic and race-condition candidates (#245).

Two heuristics over each mutating route's handler span, both leads for a
human (or `--hunt --verify`) to confirm, never asserted bugs:

- **check-then-act**: a balance-like field (`balance`, `credits`, `stock`,
  `quota`, ...) is compared in an `if` and then written in the same handler,
  with no row lock or atomic update in sight (`select_for_update`,
  `FOR UPDATE`, `$inc`, `F(...)`, Redis `WATCH`/`SETNX`, advisory locks).
  Two concurrent requests both pass the check: double spend, overdraw, coupon
  reuse.
- **idempotency gap**: a POST to a redeem / checkout / transfer / withdraw /
  vote / invite / claim / purchase route with no idempotency key, uniqueness
  or rate-limit signal in the handler or its guards.
"""

from __future__ import annotations

import re
from pathlib import Path

from .handler_span import span_bounds
from .models import LogicFlawCandidate, ScanResult
from .safe_fs import contained_file

_FIELDS = r"(?:balance|credits?|stock|quantity|inventory|quota|uses|use_count|used_count|redeemed|remaining|points|wallet|seats|limit_left)"
# `if user.balance >= amount` / `if (account.balance < amt)` / `if amount <= wallet.balance`
_CHECK = re.compile(
    rf"\bif\b[ \t(]*+[^\n]{{0,200}}?[\w\]\)]\.(?P<field>{_FIELDS})\b[^\n]{{0,120}}?(?:>=|<=|>|<|==|!=)"
    rf"|\bif\b[ \t(]*+[^\n]{{0,200}}?(?:>=|<=|>|<|==|!=)[ \t]*+[\w.\[\]'\"]{{0,80}}?\.(?P<field2>{_FIELDS})\b",
    re.IGNORECASE,
)
# Atomic updates and row locks that close the race.
_LOCK = re.compile(
    r"select_for_update|with_for_update|\bFOR\s+UPDATE\b|LOCK\s+IN\s+SHARE\s+MODE|\$inc\b|\bF\s*\(\s*['\"]"
    r"|\bWATCH\b|\bSETNX\b|\bnx\s*[=:]\s*[Tt]rue|advisory_x?lock|\.lock\s*\(|\bLock\s*\(|\bMutex\b|\bincrement\s*\(|\bdecrement\s*\(",
)
_IDEMPOTENT_ROUTE = re.compile(r"(?:^|/)(?:redeem|checkout|transfer|withdraw|vote|invite|claim|purchase|payments?|pay)(?:/|$|\b)", re.IGNORECASE)
_IDEMPOTENCY_SIGNAL = re.compile(
    r"idempoten|unique|get_or_create|ON\s+CONFLICT|upsert|findOneAndUpdate|rate.?limit|throttl|limiter|\bnonce\b|already.?(?:redeemed|used|claimed)",
    re.IGNORECASE,
)
_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_MAX_FILE_BYTES = 1_000_000


def _write_of(field: str) -> re.Pattern[str]:
    # `user.balance -= amt`, `acct.balance = acct.balance - x` (not `==`).
    return re.compile(rf"\.{re.escape(field)}\s*(?:[-+*/]?=)(?!=)", re.IGNORECASE)


def find_logic_flaws(scan: ScanResult, root: str | Path) -> list[LogicFlawCandidate]:
    root_path = Path(root)
    by_file: dict[str, list[int]] = {}
    for route in scan.routes:
        if route.line is not None:
            by_file.setdefault(route.file, []).append(route.line)
    lines_cache: dict[str, list[str] | None] = {}
    out: list[LogicFlawCandidate] = []
    for route in scan.routes:
        if route.method.upper() not in _WRITE_METHODS or route.line is None:
            continue
        if route.file not in lines_cache:
            path = contained_file(root_path, route.file)
            try:
                ok = path is not None and path.stat().st_size <= _MAX_FILE_BYTES
                lines_cache[route.file] = path.read_text(encoding="utf-8", errors="ignore").split("\n") if ok else None
            except OSError:
                lines_cache[route.file] = None
        lines = lines_cache[route.file]
        if not lines:
            continue
        start, end = span_bounds(route.line, lines, by_file[route.file])
        span = "\n".join(lines[start:end])
        base = dict(route_method=route.method, route_path=route.path, route_file=route.file, route_line=route.line)
        if not _LOCK.search(span):
            for check in _CHECK.finditer(span):
                field = check.group("field") or check.group("field2")
                write = _write_of(field).search(span, check.end())
                if write is None:
                    continue
                line = start + 1 + span.count("\n", 0, write.start())
                out.append(
                    LogicFlawCandidate(
                        kind="check_then_act", field=field, file=route.file, line=line,
                        evidence_text=lines[line - 1].strip()[:200], confidence=0.5, **base,
                    )
                )
                break
        guards = " ".join(route.guards)
        if (
            route.method.upper() == "POST"
            and _IDEMPOTENT_ROUTE.search(route.path)
            and not _IDEMPOTENCY_SIGNAL.search(span)
            and not _IDEMPOTENCY_SIGNAL.search(guards)
        ):
            out.append(
                LogicFlawCandidate(
                    kind="idempotency_gap", file=route.file, line=route.line,
                    evidence_text=lines[route.line - 1].strip()[:200], confidence=0.3, **base,
                )
            )
    return out


__all__ = ["find_logic_flaws"]
