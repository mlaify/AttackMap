"""Multi-pass hunt harness — slice 147a: N-skeptic majority-vote verify (#147).

The verifier is the asset the whole unknown-bug epic (#150) leans on. `--hunt`
generates candidate vulnerability hypotheses; a single verify pass adjudicates
them, and a single wrong "CONFIRMED" ships a false positive. This module turns
verification into a jury:

1. **Generate** the hypotheses once (`hunt_generate` mode), which appends a
   machine-readable `=== HYPOTHESES ===` list we parse into a fixed, id-keyed set.
2. **N independent skeptics** (`hunt_skeptic` mode) each adjudicate that SAME
   list against the real source — no skeptic sees another's verdict.
3. **Combine by majority vote.** A lead is CONFIRMED only on a strict majority
   of confirmations; NEEDS_REVIEW only when a strict majority flags the evidence
   as insufficient; otherwise REFUTED. Ties, splits, missing votes, and
   uncertainty never confirm — confirmation is the outcome that must clear a bar.

`combine_verdicts` is a pure function (unit-tested); the LLM calls are injected
so the orchestration is testable offline.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Literal

from .review_prompts import HYPOTHESIS_MARKER

Verdict = Literal["confirmed", "refuted", "needs_review"]


@dataclass(frozen=True)
class Hypothesis:
    id: str
    title: str
    evidence: str = ""  # the `[evidence: …]` ids cited by the generation pass
    lenses: tuple[str, ...] = ()  # which failure-mode lens passes surfaced it (#147b)


@dataclass
class Consensus:
    id: str
    title: str
    verdict: Verdict
    confirmed: int = 0
    refuted: int = 0
    needs_review: int = 0
    # (verdict, reason) per skeptic that gave one, so the report can quote a
    # reason that agrees with the consensus verdict.
    reasons: list[tuple[Verdict, str]] = field(default_factory=list)


# `H1: title [evidence: …]` lines in the generation pass's marker block.
_HYP_LINE_RE = re.compile(r"^\s*(H\d+)\s*[:.\-]\s*(.+?)\s*$", re.MULTILINE)
# `VERDICT H1: CONFIRMED — reason` lines from each skeptic pass. Tolerant of
# spacing, the id in brackets, and NEEDS REVIEW / NEEDS-REVIEW spelling.
_VERDICT_RE = re.compile(
    r"VERDICT\s*\[?\s*(H\d+)\s*\]?\s*[:\-]\s*"
    r"(CONFIRMED|REFUTED|NEEDS[ _\-]?REVIEW)\b"
    r"\s*(?:[—:\-]\s*(.*))?",
    re.IGNORECASE,
)

_VERDICT_NORMALIZE = {
    "CONFIRMED": "confirmed",
    "REFUTED": "refuted",
    "NEEDS_REVIEW": "needs_review",
    "NEEDS-REVIEW": "needs_review",
    "NEEDS REVIEW": "needs_review",
}


def parse_hypotheses(markdown: str) -> list[Hypothesis]:
    """Extract the fixed, ordered hypothesis list from a generation pass. Reads
    only the text after the last ``=== HYPOTHESES ===`` marker (falls back to the
    whole text if the marker is absent). Deduplicated by id, order preserved."""
    idx = markdown.rfind(HYPOTHESIS_MARKER)
    region = markdown[idx + len(HYPOTHESIS_MARKER):] if idx != -1 else markdown
    out: list[Hypothesis] = []
    seen: set[str] = set()
    for match in _HYP_LINE_RE.finditer(region):
        hid = match.group(1).upper()
        if hid in seen:
            continue
        seen.add(hid)
        raw = match.group(2).strip()
        # Split the clean title from its "[evidence: …]" annotation, but KEEP
        # the evidence ids — the skeptics need them to locate the cited chain.
        ev_match = re.search(r"\[evidence:\s*(.*?)\]\s*$", raw, flags=re.IGNORECASE)
        evidence = ev_match.group(1).strip() if ev_match else ""
        title = re.sub(r"\s*\[evidence:.*?\]\s*$", "", raw, flags=re.IGNORECASE).strip()
        out.append(Hypothesis(id=hid, title=title, evidence=evidence))
    return out


# --- Cross-pass dedupe (#147b) --------------------------------------------

_STOPWORDS = frozenset({
    "the", "a", "an", "of", "in", "on", "to", "and", "or", "via", "with", "for",
    "at", "by", "from", "into", "that", "this", "is", "are", "reaches", "reach",
})


def _title_tokens(title: str) -> frozenset[str]:
    words = re.findall(r"[A-Za-z0-9_./]+", title.lower())
    return frozenset(w for w in words if len(w) > 2 and w not in _STOPWORDS)


def _evidence_ids(evidence: str) -> frozenset[str]:
    return frozenset(t.strip() for t in re.split(r"[,\s]+", evidence.lower()) if ":" in t)


def _jaccard(a: frozenset, b: frozenset) -> float:
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)


def _same_lead(t_a, e_a, t_b, e_b) -> bool:
    """Two hypotheses describe the same lead. Requires an identity signal — an
    identical significant-token set, or shared cited-evidence ids plus similar
    wording. Title similarity ALONE never merges: "… on /orders/{id}" and
    "… on /users/{id}" are ~0.67 similar but are distinct leads on distinct
    chains, so collapsing them would let a skeptic confirm one using the other's
    evidence (#147b)."""
    if t_a and t_a == t_b:
        return True  # identical significant tokens — same lead text
    if (e_a & e_b) and _jaccard(t_a, t_b) >= 0.4:
        return True  # same cited chain + similar wording
    return False


def dedupe_hypotheses(passes: list[list[Hypothesis]]) -> list[Hypothesis]:
    """Merge hypotheses across passes (e.g. different lenses) into one fixed,
    freshly re-numbered (H1..Hn) list. Restatements of the same lead collapse
    into a single entry that unions their evidence ids and lens tags. Pure and
    deterministic given the input order."""
    kept: list[Hypothesis] = []
    tokens: list[frozenset[str]] = []
    evsets: list[frozenset[str]] = []
    for pass_hyps in passes:
        for h in pass_hyps:
            t = _title_tokens(h.title)
            e = _evidence_ids(h.evidence)
            merged_into = None
            for i in range(len(kept)):
                if _same_lead(tokens[i], evsets[i], t, e):
                    merged_into = i
                    break
            if merged_into is not None:
                existing = kept[merged_into]
                new_ev = sorted(evsets[merged_into] | e)
                new_lenses = tuple(dict.fromkeys(existing.lenses + h.lenses))
                kept[merged_into] = replace(
                    existing,
                    evidence=", ".join(new_ev) if new_ev else existing.evidence,
                    lenses=new_lenses,
                )
                evsets[merged_into] = evsets[merged_into] | e
            else:
                kept.append(h)
                tokens.append(t)
                evsets.append(e)
    return [replace(h, id=f"H{i + 1}") for i, h in enumerate(kept)]


def parse_verdicts(markdown: str) -> dict[str, tuple[Verdict, str]]:
    """Parse ``VERDICT H<n>: <verdict> — <reason>`` lines from one skeptic pass."""
    out: dict[str, tuple[Verdict, str]] = {}
    for match in _VERDICT_RE.finditer(markdown):
        hid = match.group(1).upper()
        raw = re.sub(r"[ \-]", "_", match.group(2).upper())
        verdict = _VERDICT_NORMALIZE.get(raw)
        if verdict is None:
            continue
        reason = (match.group(3) or "").strip()
        out[hid] = (verdict, reason)  # last line for an id wins
    return out


def combine_verdicts(
    hypotheses: list[Hypothesis],
    per_pass: list[dict[str, tuple[Verdict, str]]],
) -> list[Consensus]:
    """Combine the skeptic passes into a per-hypothesis consensus:

    - **CONFIRMED** only with a *strict majority* of CONFIRMED votes.
    - **NEEDS_REVIEW** only with a *strict majority* explicitly flagging the
      excerpt as insufficient (a genuine "a human should read this" signal).
    - **REFUTED** for everything else — ties, splits, missing votes, and any
      other uncertainty. Confirmation is the thing that must clear a majority
      bar; when in doubt a lead is refuted, never confirmed.

    Pure function: no I/O, deterministic given its inputs.
    """
    total = len(per_pass)
    results: list[Consensus] = []
    for hyp in hypotheses:
        confirmed = refuted = needs = 0
        reasons: list[tuple[Verdict, str]] = []
        for votes in per_pass:
            entry = votes.get(hyp.id)
            if entry is None:
                refuted += 1  # a skeptic that didn't rule on it does not confirm it
                continue
            verdict, reason = entry
            if verdict == "confirmed":
                confirmed += 1
            elif verdict == "needs_review":
                needs += 1
            else:
                refuted += 1
            if reason:
                reasons.append((verdict, reason))
        if total and confirmed * 2 > total:
            final: Verdict = "confirmed"
        elif total and needs * 2 > total:
            final = "needs_review"
        else:
            final = "refuted"
        results.append(
            Consensus(
                id=hyp.id,
                title=hyp.title,
                verdict=final,
                confirmed=confirmed,
                refuted=refuted,
                needs_review=needs,
                reasons=reasons,
            )
        )
    return results


_VERDICT_ORDER = {"confirmed": 0, "needs_review": 1, "refuted": 2}
_VERDICT_HEADING = {
    "confirmed": "Confirmed",
    "needs_review": "Needs human review",
    "refuted": "Refuted",
}


def render_consensus_report(consensus: list[Consensus], votes: int) -> str:
    """Render the adjudicated shortlist, grouped by consensus verdict."""
    lines = [
        "# AttackMap hunt — verified hypotheses",
        "",
        f"_Majority vote of {votes} independent skeptic pass(es). A lead is "
        "CONFIRMED only on a strict majority; NEEDS_REVIEW only when a majority "
        "flags the evidence as insufficient; otherwise REFUTED — ties and "
        "uncertainty never confirm._",
        "",
    ]
    ordered = sorted(consensus, key=lambda c: (_VERDICT_ORDER[c.verdict], c.id))
    for verdict in ("confirmed", "needs_review", "refuted"):
        group = [c for c in ordered if c.verdict == verdict]
        if not group:
            continue
        lines.append(f"## {_VERDICT_HEADING[verdict]} ({len(group)})")
        lines.append("")
        for c in group:
            tally = f"{c.confirmed}/{votes} confirmed"
            if c.needs_review:
                tally += f", {c.needs_review} needs-review"
            lines.append(f"- `{c.id}` — **{c.title}** ({tally})")
            reason = _reason_for(c)
            if reason:
                lines.append(f"  - {reason}")
        lines.append("")
    return "\n".join(lines)


def _reason_for(c: Consensus) -> str:
    """Quote a skeptic reason that AGREES with the consensus verdict, so a
    Confirmed item never shows a dissenting `[refuted]` justification."""
    for verdict, reason in c.reasons:
        if verdict == c.verdict:
            return reason
    return c.reasons[0][1] if c.reasons else ""


@dataclass
class MajorityVerifyResult:
    report: str
    hypothesis_count: int
    votes: int
    consensus: list[Consensus]
    backend: str
    model: str
    usage: dict[str, int] = field(default_factory=dict)


def _add_usage(total: dict[str, int], usage: dict | None) -> None:
    for key, value in (usage or {}).items():
        if isinstance(value, int):
            total[key] = total.get(key, 0) + value


def run_majority_verify(
    scan,
    attack_surfaces,
    findings,
    attack_paths,
    *,
    votes: int,
    llm_call: Callable,
    lenses: list[str] | None = None,
) -> MajorityVerifyResult:
    """Generate hypotheses, then adjudicate them with ``votes`` independent
    skeptics and combine by majority vote.

    ``llm_call(mode, hypotheses=None, lens=None)`` runs one LLM pass and returns
    an ``LlmReviewResult`` — injected so the orchestration is testable offline
    and so the caller owns model/backend/provider selection. With ``lenses``
    (more than one), generation fans out one specialised pass per lens and the
    results are deduped into a single list (#147b).
    """
    usage_total: dict[str, int] = {}
    gen_backend = gen_model = ""
    last_markdown = ""

    if lenses and len(lenses) > 1:
        passes: list[list[Hypothesis]] = []
        for lens in lenses:
            g = llm_call("hunt_generate", lens=lens)
            _add_usage(usage_total, g.usage)
            gen_backend, gen_model, last_markdown = g.backend, g.model, g.markdown
            passes.append([replace(h, lenses=(lens,)) for h in parse_hypotheses(g.markdown)])
        hypotheses = dedupe_hypotheses(passes)
    else:
        g = llm_call("hunt_generate")
        _add_usage(usage_total, g.usage)
        gen_backend, gen_model, last_markdown = g.backend, g.model, g.markdown
        hypotheses = parse_hypotheses(g.markdown)

    if not hypotheses:
        # Nothing parseable to vote on — hand back the generation output as-is.
        report = last_markdown if last_markdown.strip() else "_No hypotheses were surfaced._\n"
        return MajorityVerifyResult(
            report=report, hypothesis_count=0, votes=votes,
            consensus=[], backend=gen_backend, model=gen_model, usage=usage_total,
        )

    hyp_dicts = [{"id": h.id, "title": h.title, "evidence": h.evidence} for h in hypotheses]
    per_pass: list[dict[str, tuple[Verdict, str]]] = []
    for _ in range(votes):
        sk = llm_call("hunt_skeptic", hypotheses=hyp_dicts)
        _add_usage(usage_total, sk.usage)
        per_pass.append(parse_verdicts(sk.markdown))

    consensus = combine_verdicts(hypotheses, per_pass)
    report = render_consensus_report(consensus, votes)
    return MajorityVerifyResult(
        report=report,
        hypothesis_count=len(hypotheses),
        votes=votes,
        consensus=consensus,
        backend=gen_backend,
        model=gen_model,
        usage=usage_total,
    )
