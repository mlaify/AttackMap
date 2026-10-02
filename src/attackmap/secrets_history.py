"""Opt-in git-history secret scan (#252, ``--secrets-history N``).

Most leaked credentials live in history, not the working tree: a key is
committed, noticed, and "removed" in a later commit while every clone keeps
it. This pass runs the same detectors as the working-tree scan over the
lines *added* by the last ``N`` commits (all refs), and reports for each
secret the commit that introduced it and whether it is still in ``HEAD``.

Safety:
- Off by default; only ``--secrets-history`` runs it.
- Bounded: at most ``MAX_COMMITS`` commits, ``MAX_OUTPUT_BYTES`` of patch
  text, ``MAX_LINE_CHARS`` per line and a wall-clock timeout. Hitting a bound
  is recorded as a scan limitation, never silently.
- Git is invoked through ``gitref.hardened_git_command``: no hooks, pager,
  fsmonitor, external diff, textconv or lazy fetch, and system/global config
  ignored, so a hostile repo can't execute code through its git config.
- Raw secret values exist only in memory while matching (to fingerprint and
  test ``still_in_head``); every emitted record is masked (#235).
"""

from __future__ import annotations

import hashlib
import subprocess
import time
from pathlib import Path

from .gitref import hardened_git_command, hardened_git_env
from .models import SecretHistoryHit
from .redact import mask_secret
from .scanner import _line_snippet, iter_secret_matches
from .srcpaths import in_skipped_dir, is_test_file, is_vendored_file

DEFAULT_COMMITS = 100
MAX_COMMITS = 5000
MAX_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_LINE_CHARS = 4096
TIMEOUT_SECONDS = 120.0
_COMMIT_MARKER = "\x1ecommit "


def _run(root: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        hardened_git_command(root, *args),
        capture_output=True,
        check=False,
        stdin=subprocess.DEVNULL,
        env=hardened_git_env(),
        timeout=30,
    )


def _head_text(root: Path, prefix: str, rel: str, cache: dict[str, str | None]) -> str | None:
    if rel not in cache:
        result = _run(root, "cat-file", "blob", f"HEAD:{prefix}{rel}")
        cache[rel] = result.stdout.decode("utf-8", errors="replace") if result.returncode == 0 else None
    return cache[rel]


def scan_secret_history(
    root: str | Path,
    commits: int = DEFAULT_COMMITS,
    *,
    max_output_bytes: int = MAX_OUTPUT_BYTES,
    timeout: float = TIMEOUT_SECONDS,
) -> tuple[list[SecretHistoryHit], list[str]]:
    """Scan the patches of the last ``commits`` commits under ``root``.

    Returns ``(hits, limitations)``. A directory that isn't a git checkout
    yields no hits and one limitation line.
    """
    root_path = Path(root).resolve()
    commits = max(1, min(int(commits), MAX_COMMITS))
    probe = _run(root_path, "rev-parse", "--show-prefix")
    if probe.returncode != 0:
        return [], [f"--secrets-history skipped: {root_path} is not a git repository"]
    prefix = probe.stdout.decode("utf-8", errors="replace").strip()

    proc = subprocess.Popen(
        hardened_git_command(
            root_path, "log", "--all", "-n", str(commits), "-p", "-U0",
            "--no-color", "--no-ext-diff", "--no-textconv", "--no-renames",
            "--diff-filter=AM", f"--format=format:{_COMMIT_MARKER}%H",
            "--", ".",
        ),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        env=hardened_git_env(),
    )
    limitations: list[str] = []
    # fingerprint -> [kind, file, line_text_masked, introduced_in, literal]
    found: dict[tuple[str, str, str], list] = {}
    commit = ""
    current: str | None = None
    read = 0
    seen_commits: set[str] = set()
    started = time.monotonic()
    assert proc.stdout is not None
    try:
        for raw in proc.stdout:
            read += len(raw)
            if read > max_output_bytes:
                limitations.append(f"--secrets-history stopped after {max_output_bytes} bytes of patch output")
                break
            if time.monotonic() - started > timeout:
                limitations.append(f"--secrets-history stopped after {timeout:.0f}s")
                break
            line = raw.decode("utf-8", errors="replace").rstrip("\n")
            if line.startswith(_COMMIT_MARKER):
                commit = line[len(_COMMIT_MARKER):].strip()
                seen_commits.add(commit)
                current = None
                continue
            if line.startswith("+++ "):
                target = line[4:]
                current = target[2:] if target.startswith("b/") else None
                if current is not None and prefix and current.startswith(prefix):
                    current = current[len(prefix):]
                if current is not None and in_skipped_dir(Path(current)):
                    current = None
                continue
            if current is None or not line.startswith("+") or len(line) > MAX_LINE_CHARS:
                continue
            added = line[1:]
            first_party = not is_test_file(current) and not is_vendored_file(current)
            for kind, literal, offset, _confidence in iter_secret_matches(
                added, entropy=False, generic=first_party, urls=first_party
            ):
                fingerprint = (kind, current, hashlib.sha256(literal.encode("utf-8")).hexdigest())
                snippet = _line_snippet(added, offset).replace(literal, mask_secret(literal))
                # `git log` is newest first, so the last sighting is the oldest:
                # keep overwriting `introduced_in`.
                found[fingerprint] = [kind, current, snippet, commit, literal]
    finally:
        proc.stdout.close()
        if proc.poll() is None:
            proc.kill()
        proc.wait()

    head_cache: dict[str, str | None] = {}
    hits: list[SecretHistoryHit] = []
    for kind, rel, snippet, introduced, literal in found.values():
        head = _head_text(root_path, prefix, rel, head_cache)
        hits.append(
            SecretHistoryHit(
                name=mask_secret(literal) if kind != "pem_private_key" else literal,
                kind=kind,
                file=rel,
                introduced_in=introduced,
                still_in_head=bool(head) and literal in head,
                evidence_text=snippet,
            )
        )
    found.clear()
    hits.sort(key=lambda h: (h.still_in_head, h.file, h.kind, h.introduced_in))
    if len(seen_commits) >= commits:
        limitations.append(
            f"--secrets-history scanned the last {commits} commit(s); older history was not checked"
        )
    return hits, limitations
