"""Filesystem access confined to the scanned repository (#234, #228).

AttackMap scans untrusted checkouts, so a symlink in the repo must never make
it read a file outside the repo (and report or send that file's content
elsewhere), and a symlink planted where a report is about to be written must
never redirect that write.

Read side:
    * :func:`walk_repo` yields the regular files under a root without
      following symlinks — symlinked files are skipped and symlinked
      directories are not descended. Set ``ATTACKMAP_FOLLOW_SYMLINKS=1`` to
      follow symlinks whose target resolves inside the root.
    * :func:`is_contained` / :func:`contained_file` validate a path (or a
      repo-relative path taken from evidence text) before it is read.
    * :func:`read_repo_text` reads a file only if it is contained.

Write side:
    * :func:`safe_write_text` refuses to write through a symlink or outside
      the output directory, and never follows a symlink planted at the target.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from pathlib import Path

FOLLOW_SYMLINKS_ENV = "ATTACKMAP_FOLLOW_SYMLINKS"
MAX_FILE_BYTES_ENV = "ATTACKMAP_MAX_FILE_BYTES"
# Files larger than this are not read (#236): a hostile or generated multi-MB
# file must not stall a CI scan. Real source files are far smaller.
DEFAULT_MAX_FILE_BYTES = 2_000_000


class UnsafePathError(OSError):
    """A read or write would escape the repository / output directory."""


def max_file_bytes() -> int:
    raw = os.environ.get(MAX_FILE_BYTES_ENV, "").strip()
    try:
        value = int(raw) if raw else DEFAULT_MAX_FILE_BYTES
    except ValueError:
        value = DEFAULT_MAX_FILE_BYTES
    return value if value > 0 else DEFAULT_MAX_FILE_BYTES


def is_oversized(path: Path) -> bool:
    """True when ``path`` is larger than the per-file read cap."""
    try:
        return path.stat().st_size > max_file_bytes()
    except OSError:
        return False


def follow_symlinks_enabled() -> bool:
    return os.environ.get(FOLLOW_SYMLINKS_ENV, "").strip().lower() in {"1", "true", "yes"}


def _resolved_within(root: Path, path: Path) -> bool:
    try:
        return path.resolve().is_relative_to(root.resolve())
    except (OSError, RuntimeError):  # RuntimeError: symlink loop on some Pythons
        return False


def is_contained(root: str | Path, path: str | Path) -> bool:
    """True when ``path`` is inside ``root`` and is not reached via a symlink.

    Every component between ``root`` and ``path`` is checked with ``lstat`` —
    a symlinked directory in the middle of the path disqualifies it just like
    a symlinked file. With ``ATTACKMAP_FOLLOW_SYMLINKS=1`` symlinks are allowed
    as long as the fully resolved path stays inside ``root``.
    """
    root_path = Path(root)
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = root_path / candidate
    try:
        rel = candidate.relative_to(root_path)
    except ValueError:
        try:
            rel = candidate.relative_to(root_path.resolve())
            root_path = root_path.resolve()
        except ValueError:
            return False
    if ".." in rel.parts:
        return False
    if follow_symlinks_enabled():
        return _resolved_within(root_path, candidate)
    current = root_path
    for part in rel.parts:
        current = current / part
        if current.is_symlink():
            return False
    return _resolved_within(root_path, candidate)


def is_unsafe_link(root: str | Path, entry: Path) -> bool:
    """For hand-rolled ``iterdir`` walkers: True when ``entry`` is a symlink
    that must be skipped (always, unless follow mode is on and it resolves
    inside ``root``)."""
    if not entry.is_symlink():
        return False
    return not (follow_symlinks_enabled() and _resolved_within(Path(root), entry))


def contained_file(root: str | Path, rel: str | Path) -> Path | None:
    """Resolve a repo-relative path from untrusted text (evidence, plugin
    output) to a regular file inside ``root``, or ``None``.

    Absolute paths and paths with ``..`` components are rejected outright.
    """
    rel_path = Path(rel)
    if rel_path.is_absolute() or ".." in rel_path.parts or str(rel).startswith("~"):
        return None
    candidate = Path(root) / rel_path
    if not is_contained(root, candidate):
        return None
    try:
        return candidate if candidate.is_file() else None
    except OSError:
        return None


def read_repo_text(
    root: str | Path, path: str | Path, *, encoding: str = "utf-8", errors: str = "strict"
) -> str:
    """``Path.read_text`` that refuses paths outside ``root`` or behind a symlink."""
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = Path(root) / candidate
    if not is_contained(root, candidate):
        raise UnsafePathError(f"refusing to read outside the repository: {path}")
    return candidate.read_text(encoding=encoding, errors=errors)


def walk_repo(
    root: str | Path,
    *,
    prune: Callable[[str], bool] | None = None,
    on_symlink: Callable[[Path], None] | None = None,
) -> Iterator[Path]:
    """Yield regular files under ``root`` (depth-first, sorted per directory).

    Symlinks are skipped — symlinked files are not yielded and symlinked
    directories are not descended — and ``on_symlink(path)`` is called for
    each. With ``ATTACKMAP_FOLLOW_SYMLINKS=1`` symlinks whose target resolves
    inside ``root`` are followed (cycle-safe); ones pointing outside are still
    skipped. ``prune(dirname)`` returning True skips descending into a
    directory.
    """
    root_path = Path(root)
    follow = follow_symlinks_enabled()
    seen_dirs: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root_path, followlinks=follow):
        current = Path(dirpath)
        if follow:
            real = os.path.realpath(dirpath)
            if real in seen_dirs or not _resolved_within(root_path, current):
                dirnames[:] = []
                continue
            seen_dirs.add(real)
        kept_dirs = []
        for name in sorted(dirnames):
            if prune is not None and prune(name):
                continue
            child = current / name
            if child.is_symlink() and not (follow and _resolved_within(root_path, child)):
                if on_symlink is not None:
                    on_symlink(child)
                continue
            kept_dirs.append(name)
        dirnames[:] = kept_dirs
        for name in sorted(filenames):
            child = current / name
            if child.is_symlink() and not (follow and _resolved_within(root_path, child)):
                if on_symlink is not None:
                    on_symlink(child)
                continue
            try:
                if child.is_file():
                    yield child
            except OSError:
                continue


def ensure_output_dir(out_dir: str | Path) -> Path:
    """Create the report directory, refusing a symlinked one.

    The directory itself and any of its ancestors inside the current working
    directory (usually the checkout being scanned) must be real directories —
    otherwise a committed ``reports -> /somewhere`` link would redirect every
    report write (#228).
    """
    out = Path(out_dir)
    absolute = out.absolute()
    cwd = Path.cwd()
    for candidate in (absolute, *absolute.parents):
        if candidate == cwd or not candidate.is_relative_to(cwd):
            continue
        if candidate.is_symlink():
            raise UnsafePathError(f"refusing to write reports through a symlink: {candidate}")
    out.mkdir(parents=True, exist_ok=True)
    if out.is_symlink():
        raise UnsafePathError(f"refusing to write reports into a symlinked directory: {out}")
    return out


def safe_write_text(out_dir: str | Path, path: str | Path, text: str, *, encoding: str = "utf-8") -> None:
    """Write ``text`` to ``path`` without following symlinks.

    Refuses when ``path`` is (or sits behind) a symlink, or resolves outside
    ``out_dir``. The final open uses ``O_NOFOLLOW`` so a symlink swapped in
    after the check is not followed either.
    """
    out = Path(out_dir)
    target = Path(path)
    if out.is_symlink():
        raise UnsafePathError(f"refusing to write reports into a symlinked directory: {out}")
    if target.is_symlink():
        raise UnsafePathError(f"refusing to write through a symlink: {target}")
    if not target.parent.resolve().is_relative_to(out.resolve()):
        raise UnsafePathError(f"refusing to write outside the output directory {out}: {target}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(target, flags, 0o644)
    except OSError as exc:
        if target.is_symlink():
            raise UnsafePathError(f"refusing to write through a symlink: {target}") from exc
        raise
    with os.fdopen(fd, "w", encoding=encoding) as handle:
        handle.write(text)
