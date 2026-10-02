"""Shared repo walking and reading for analyzer plugins (#253).

Every plugin used to copy the same ``root.rglob(...)`` plus
``any(part in SKIP_DIRS for part in path.parts)`` walk. That pattern:

- matched skip dirs against *absolute* path parts, so a repo checked out under
  ``/build/...`` or ``~/src/out/...`` silently yielded no files at all;
- didn't prune, so it still descended all of ``node_modules`` and ``target``;
- followed symlinks out of the repo;
- let one unreadable file raise out of ``analyze()``;
- dropped latin-1/cp1252 sources without saying so.

Use :func:`iter_repo_files` and :func:`read_source` instead. They prune by
*repo-relative* directory name, never follow symlinks out of the repo, skip
AttackMap's own output directories, cap file size, and never raise on an
unreadable file.
"""

from __future__ import annotations

from collections.abc import Callable, Collection, Iterator
from pathlib import Path

from ..safe_fs import is_contained, max_file_bytes, walk_repo
from ..srcpaths import SKIP_DIRS, is_test_file, line_number

# Directories no analyzer should descend into. Plugins extend it for their
# ecosystem, e.g. ``DEFAULT_SKIP_DIRS | {"bin", "obj"}`` for .NET.
DEFAULT_SKIP_DIRS: frozenset[str] = frozenset(SKIP_DIRS | {"vendor", "bower_components", ".mypy_cache", ".pytest_cache"})

_BINARY_SNIFF_BYTES = 8192


def iter_repo_files(
    root: str | Path,
    *,
    suffixes: Collection[str] | None = None,
    names: Collection[str] | None = None,
    skip_dirs: Collection[str] = DEFAULT_SKIP_DIRS,
    max_bytes: int | None = None,
    include_tests: bool = True,
    on_skip: Callable[[Path, str], None] | None = None,
) -> Iterator[Path]:
    """Yield the repo's regular files, sorted and depth-first.

    - ``suffixes`` (e.g. ``{".go"}``, case-insensitive) and ``names`` (exact
      file names, e.g. ``{"go.mod"}``) filter the files; a file matching
      either is yielded. With neither, every file is.
    - ``skip_dirs`` are matched against directory *names inside the repo* and
      pruned, so the walk never enters them, and directories above ``root``
      never count.
    - Files larger than ``max_bytes`` (default: the core per-file cap,
      ``ATTACKMAP_MAX_FILE_BYTES``) are skipped.
    - ``include_tests=False`` drops test/spec/fixture files (see
      ``ATTACKMAP_INCLUDE_TESTS``).
    - ``on_skip(path, reason)`` is called for each skipped symlink or
      oversized file, so a plugin can report what it didn't analyze.
    """
    root_path = Path(root)
    wanted_suffixes = {s.lower() for s in suffixes} if suffixes is not None else None
    wanted_names = set(names) if names is not None else None
    skip = frozenset(skip_dirs)
    cap = max_bytes if max_bytes is not None else max_file_bytes()

    def _symlink(path: Path) -> None:
        if on_skip is not None:
            on_skip(path, "symlink not followed")

    for path in walk_repo(root_path, prune=skip.__contains__, on_symlink=_symlink):
        if wanted_suffixes is not None or wanted_names is not None:
            if not (
                (wanted_suffixes is not None and path.suffix.lower() in wanted_suffixes)
                or (wanted_names is not None and path.name in wanted_names)
            ):
                continue
        if not include_tests and is_test_file(rel(path, root_path)):
            continue
        try:
            oversized = path.stat().st_size > cap
        except OSError:
            continue
        if oversized:
            if on_skip is not None:
                on_skip(path, "oversized file skipped")
            continue
        yield path


def read_source(path: str | Path, *, root: str | Path | None = None) -> str | None:
    """Read a source file as text, or return None if it can't be read.

    Decodes UTF-8 (with or without a BOM), then falls back to cp1252 and finally
    latin-1, so legacy-encoded sources are analyzed rather than dropped.
    Returns None for unreadable files (``OSError``), binary files (a NUL byte
    in the first 8 KiB) and, when ``root`` is given, paths outside it.
    """
    file_path = Path(path)
    if root is not None:
        if not file_path.is_absolute():
            file_path = Path(root) / file_path
        if not is_contained(root, file_path):
            return None
    try:
        data = file_path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:_BINARY_SNIFF_BYTES]:
        return None
    for encoding in ("utf-8-sig", "cp1252"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1")


def rel(path: str | Path, root: str | Path) -> str:
    """``path`` relative to ``root``, POSIX-style (``src/app.py``)."""
    try:
        return Path(path).relative_to(Path(root)).as_posix()
    except ValueError:
        return Path(path).as_posix()


def line_of(content: str, offset: int) -> int:
    """1-indexed line of a character offset (e.g. ``match.start()``)."""
    return line_number(content, offset)


def line_snippet(content: str, line: int, max_len: int = 200) -> str:
    """The stripped text of 1-indexed ``line``, truncated to ``max_len``.

    Lines are split on ``\n`` only, matching :func:`line_of`; ``str.splitlines``
    would also break on form feeds and other separators common in legacy C and
    put the snippet on the wrong line.
    """
    lines = content.split("\n")
    if line < 1 or line > len(lines):
        return ""
    text = lines[line - 1].strip()
    return text if len(text) <= max_len else text[: max_len - 1] + "…"


__all__ = [
    "DEFAULT_SKIP_DIRS",
    "iter_repo_files",
    "read_source",
    "rel",
    "line_of",
    "line_snippet",
]
