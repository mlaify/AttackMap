"""Dependency supply-chain risk beyond CVEs (#247).

Runs after the SBOM pass over the manifests, lockfiles and package-manager
configs already in the repo and emits a ``SupplyChainIssue`` per risky
pattern. Entirely offline and deterministic: no registry lookups (the
typosquat list is bundled in ``popular_packages``), so it is safe in the
default scan.

Kinds:

- **dependency_confusion** — an internal-looking package name (configured
  ``internal_prefixes`` in ``.attackmap.yaml``, the repo's own npm scope as an
  unscoped prefix, or ``internal-``/``-internal``/``private-``/``corp-``)
  resolved through a setup that also consults the public registry: pip
  ``--extra-index-url`` / Poetry ``supplemental``/``secondary`` sources, or
  npm without a scoped ``@org:registry=``. ``--extra-index-url`` on its own is
  reported low: any private name behind it can be registered on PyPI.
- **typosquat_candidate** — a direct npm/PyPI dependency one edit
  (Damerau-Levenshtein ≤ 1) away from a popular package, not itself popular.
- **mutable_vcs_dependency** — ``git+…`` / ``github:user/repo`` / Cargo
  ``git =`` without a full commit SHA, a tarball URL without a hash, a Go
  ``replace`` to a fork or to a path outside the repo.
- **install_script** — a direct npm dependency with an install hook
  (``hasInstallScript`` in ``package-lock.json``), or the repo's own
  ``preinstall``/``install``/``postinstall``/``prepare`` piping ``curl`` to a
  shell.
- **unlocked_manifest** — an npm/Composer/Pipenv manifest with dependencies
  and no lockfile, or a ``package-lock.json`` entry with ``resolved`` but no
  ``integrity``.
- **insecure_registry** — an ``http://`` registry / index URL, npm/yarn
  ``strict-ssl=false``, or pip ``--trusted-host``.
"""

from __future__ import annotations

import configparser
import json
import re
import tomllib
from pathlib import Path

from .models import DependencyHint, SupplyChainIssue
from .popular_packages import BY_ECOSYSTEM
from .safe_fs import is_oversized, is_unsafe_link, walk_repo

_MAX_DEPTH = 4
_SKIP_DIRS = {".git", "node_modules", "__pycache__", "dist", "build", ".venv", "venv", "target", "vendor"}
_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_NPM_LOCKS = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock")
_PY_LOCKS = ("poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock", "pylock.toml")
_PUBLIC_NPM = ("registry.npmjs.org", "registry.yarnpkg.com")
_GENERIC_INTERNAL_PREFIXES = ("internal-", "private-", "corp-")
_GENERIC_INTERNAL_SUFFIXES = ("-internal", "-private")
_INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare")
_SHELLS = {"sh", "bash", "zsh", "dash", "node", "python", "python3"}
_TYPOSQUAT_MIN_LEN = 5
_URL_ARCHIVE = (".tar.gz", ".tgz", ".zip", ".whl", ".tar.bz2")
# `name @ url` PEP 508 direct reference.
_PEP508_URL_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]{0,200})\s*(?:\[[^\]]{0,200}\]\s*)?@\s*(\S{1,2000})")
# npm `user/repo` GitHub shorthand.
_NPM_GH_SHORTHAND_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}(?:#\S{0,200})?$")
_GO_REPLACE_RE = re.compile(r"^\s*(?:replace\s+)?(\S{1,500})(?:\s+\S{1,100})?\s+=>\s+(\S{1,500})(?:\s+(\S{1,100}))?\s*$")


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _line_of(text: str, needle: str) -> int | None:
    for idx, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return idx
    return None


def _is_local_url(url: str) -> bool:
    host = url.split("://", 1)[-1].split("/", 1)[0].split("@")[-1].split(":")[0].lower()
    return host in {"localhost", "127.0.0.1", "::1", "[::1]"} or host.endswith(".localhost")


class _Collector:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.issues: list[SupplyChainIssue] = []
        self._seen: set[tuple] = set()

    def add(self, kind: str, file: str, severity: str, evidence: str, *,
            package: str | None = None, ecosystem: str | None = None, line: int | None = None) -> None:
        key = (kind, file, package, line, evidence)
        if key in self._seen:
            return
        self._seen.add(key)
        self.issues.append(SupplyChainIssue(
            kind=kind,  # type: ignore[arg-type]
            package=package,
            ecosystem=ecosystem,
            file=file,
            line=line,
            evidence_text=evidence,
            severity=severity,  # type: ignore[arg-type]
        ))


def _iter_files(root: Path):
    for path in walk_repo(root, prune=lambda name: name in _SKIP_DIRS):
        rel = path.relative_to(root)
        if len(rel.parts) > _MAX_DEPTH or is_unsafe_link(root, path) or is_oversized(path):
            continue
        yield path, rel.as_posix()


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _has_lock(root: Path, directory: Path, names: tuple[str, ...]) -> bool:
    """A lockfile in ``directory`` or an ancestor up to ``root`` (workspaces
    keep one lockfile at the top)."""
    current = directory
    while True:
        if any((current / n).is_file() for n in names):
            return True
        if current == root or root not in current.parents:
            return False
        current = current.parent


def _load_internal_prefixes(root: Path) -> list[str]:
    config = root / ".attackmap.yaml"
    if not config.is_file() or is_unsafe_link(root, config) or is_oversized(config):
        return []
    try:
        import yaml  # type: ignore[import-untyped]

        data = yaml.safe_load(config.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 — a bad config must not sink the scan
        return []
    prefixes = data.get("internal_prefixes") if isinstance(data, dict) else None
    if not isinstance(prefixes, list):
        return []
    return [str(p).lower() for p in prefixes if isinstance(p, str) and p.strip()]


# --- Public entrypoint -----------------------------------------------------


def scan_supply_chain(root: str | Path, dependencies: list[DependencyHint] | None = None) -> list[SupplyChainIssue]:
    """Offline supply-chain risk pass. ``dependencies`` are the SBOM hints
    (``analyze_sbom``); when omitted they are computed."""
    root_path = Path(root).resolve()
    if not root_path.is_dir():
        return []
    if dependencies is None:
        from .sbom import analyze_sbom

        dependencies = analyze_sbom(root_path)
    out = _Collector(root_path)
    ctx = _RegistryContext()

    for path, rel in _iter_files(root_path):
        name = path.name
        if name == ".npmrc":
            _scan_npmrc(path, rel, out, ctx)
        elif name in {".yarnrc", ".yarnrc.yml"}:
            _scan_yarnrc(path, rel, out)
        elif name in {"pip.conf", "pip.ini"}:
            _scan_pip_conf(path, rel, out, ctx)
        elif name.endswith(".txt") and ("requirements" in name or name == "constraints.txt"):
            _scan_requirements(path, rel, out, ctx)
        elif name == "pyproject.toml":
            _scan_pyproject(path, rel, out, ctx)
        elif name == "package.json":
            _scan_package_json(root_path, path, rel, out, ctx)
        elif name == "package-lock.json":
            _scan_package_lock(path, rel, out)
        elif name == "go.mod":
            _scan_go_mod(root_path, path, rel, out)
        elif name == "Cargo.toml":
            _scan_cargo_toml(root_path, path, rel, out)
        elif name == "composer.json":
            _scan_unlocked_json(root_path, path, rel, out, ("require", "require-dev"), ("composer.lock",), "composer")
        elif name == "Pipfile":
            if not (path.parent / "Pipfile.lock").is_file():
                out.add("unlocked_manifest", rel, "low", "Pipfile without Pipfile.lock — installs resolve to whatever is newest", ecosystem="pypi")

    _check_confusion(dependencies, _load_internal_prefixes(root_path), ctx, out)
    _check_typosquats(dependencies, out)
    return out.issues


class _RegistryContext:
    """Facts gathered from registry configs that the confusion check needs."""

    def __init__(self) -> None:
        self.pip_extra_index: list[tuple[str, int | None]] = []  # (file, line)
        self.npm_private_registry = False
        self.npm_scoped_registries: set[str] = set()
        self.npm_own_scopes: set[str] = set()


# --- Registry configs ------------------------------------------------------


def _check_registry_url(url: str, rel: str, line: int | None, out: _Collector, eco: str) -> None:
    if url.lower().startswith("http://") and not _is_local_url(url):
        out.add("insecure_registry", rel, "high",
                f"package index over plain http: {url} — a network attacker can swap packages in transit",
                ecosystem=eco, line=line)


def _scan_npmrc(path: Path, rel: str, out: _Collector, ctx: _RegistryContext) -> None:
    text = _read(path)
    if text is None:
        return
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith(("#", ";")) or "=" not in line:
            continue
        key, _, value = (part.strip() for part in line.partition("="))
        key_l = key.lower()
        if key_l == "registry":
            _check_registry_url(value, rel, lineno, out, "npm")
            if not any(p in value for p in _PUBLIC_NPM):
                ctx.npm_private_registry = True
        elif key_l.startswith("@") and key_l.endswith(":registry"):
            ctx.npm_scoped_registries.add(key_l.split(":", 1)[0][1:])
            _check_registry_url(value, rel, lineno, out, "npm")
        elif key_l == "strict-ssl" and value.lower() == "false":
            out.add("insecure_registry", rel, "medium", "strict-ssl=false disables TLS verification for the npm registry",
                    ecosystem="npm", line=lineno)


def _scan_yarnrc(path: Path, rel: str, out: _Collector) -> None:
    text = _read(path)
    if text is None:
        return
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip().replace('"', "").replace("'", "")
        lowered = line.lower()
        if lowered.startswith(("npmregistryserver:", "registry ", "registry:")):
            url = line.split(":", 1)[1].strip() if lowered.startswith("npm") else line.split(None, 1)[-1].lstrip(":").strip()
            _check_registry_url(url, rel, lineno, out, "npm")
        elif lowered.replace(" ", "") in {"enablestrictssl:false", "strict-sslfalse"}:
            out.add("insecure_registry", rel, "medium", f"{line} disables TLS verification for the registry",
                    ecosystem="npm", line=lineno)


def _scan_pip_conf(path: Path, rel: str, out: _Collector, ctx: _RegistryContext) -> None:
    text = _read(path)
    if text is None:
        return
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        parser.read_string(text)
    except configparser.Error:
        return
    for section in parser.sections():
        for key, value in parser.items(section):
            key = key.replace("_", "-")
            for url in value.split():
                if key in {"index-url", "extra-index-url"}:
                    line = _line_of(text, url)
                    _check_registry_url(url, rel, line, out, "pypi")
                    if key == "extra-index-url":
                        ctx.pip_extra_index.append((rel, line))
                elif key == "trusted-host":
                    out.add("insecure_registry", rel, "medium",
                            f"trusted-host {url} skips TLS verification for that index",
                            ecosystem="pypi", line=_line_of(text, url))


# --- Python ----------------------------------------------------------------


def _vcs_ref(url: str) -> str | None:
    """The ref after ``@`` in a pip VCS URL (``git+https://h/o/r.git@<ref>``)."""
    base = url.split("#", 1)[0]
    after_scheme = base.split("://", 1)[-1]
    if "@" not in after_scheme:
        return None
    ref = after_scheme.rsplit("@", 1)[1]
    return None if "/" in ref else ref  # an `@` in the host part is userinfo


def _check_py_url(name: str | None, url: str, line_text: str, rel: str, lineno: int | None,
                  out: _Collector, locked: bool) -> None:
    lowered = url.lower()
    pkg = name or url
    if lowered.startswith(("git+", "hg+", "svn+", "bzr+")):
        ref = _vcs_ref(url)
        if ref is None or not _SHA40.match(ref):
            what = f"@{ref}" if ref else "no ref"
            out.add("mutable_vcs_dependency", rel, "low" if locked else "medium",
                    f"{pkg}: VCS dependency pinned to {what}, not a commit SHA — the remote can change what installs: {url}",
                    package=name, ecosystem="pypi", line=lineno)
    elif lowered.startswith(("http://", "https://")) and lowered.split("#", 1)[0].endswith(_URL_ARCHIVE):
        if "sha256=" not in lowered and "--hash=" not in line_text:
            out.add("mutable_vcs_dependency", rel, "low" if locked else "medium",
                    f"{pkg}: archive URL dependency without a hash (#sha256= / --hash=): {url}",
                    package=name, ecosystem="pypi", line=lineno)


def _scan_requirements(path: Path, rel: str, out: _Collector, ctx: _RegistryContext) -> None:
    text = _read(path)
    if text is None:
        return
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = re.sub(r"(^|\s)#.*$", "", raw).strip()
        if not line:
            continue
        tokens = line.split()
        head = tokens[0]
        opt, _, inline = head.partition("=")
        value = inline or (tokens[1] if len(tokens) > 1 else "")
        if opt in {"--index-url", "-i", "--extra-index-url"}:
            _check_registry_url(value, rel, lineno, out, "pypi")
            if opt == "--extra-index-url":
                ctx.pip_extra_index.append((rel, lineno))
            continue
        if opt == "--trusted-host":
            out.add("insecure_registry", rel, "medium", f"--trusted-host {value} skips TLS verification for that index",
                    ecosystem="pypi", line=lineno)
            continue
        if head in {"-e", "--editable"} and len(tokens) > 1:
            _check_py_url(None, tokens[1], line, rel, lineno, out, locked=False)
            continue
        if head.startswith("-"):
            continue
        match = _PEP508_URL_RE.match(line)
        if match:
            _check_py_url(match.group(1), match.group(2), line, rel, lineno, out, locked=False)
        elif "://" in head:
            _check_py_url(None, head, line, rel, lineno, out, locked=False)


def _scan_pyproject(path: Path, rel: str, out: _Collector, ctx: _RegistryContext) -> None:
    text = _read(path)
    if text is None:
        return
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return
    locked = _has_lock(path.parent, path.parent, _PY_LOCKS)
    project = data.get("project") if isinstance(data.get("project"), dict) else {}
    specs: list[str] = list(project.get("dependencies") or [])
    optional = project.get("optional-dependencies")
    if isinstance(optional, dict):
        for group in optional.values():
            if isinstance(group, list):
                specs.extend(group)
    for spec in specs:
        if not isinstance(spec, str):
            continue
        match = _PEP508_URL_RE.match(spec)
        if match:
            _check_py_url(match.group(1), match.group(2), spec, rel, _line_of(text, spec[:60]), out, locked)

    tool = data.get("tool") if isinstance(data.get("tool"), dict) else {}
    poetry = tool.get("poetry") if isinstance(tool.get("poetry"), dict) else {}
    dep_tables = [poetry.get("dependencies"), poetry.get("dev-dependencies")]
    groups = poetry.get("group")
    if isinstance(groups, dict):
        dep_tables.extend(g.get("dependencies") for g in groups.values() if isinstance(g, dict))
    for table in dep_tables:
        if not isinstance(table, dict):
            continue
        for name, spec in table.items():
            if isinstance(spec, dict) and isinstance(spec.get("git"), str):
                rev = str(spec.get("rev", ""))
                if not _SHA40.match(rev):
                    ref = spec.get("rev") or spec.get("tag") or spec.get("branch") or "default branch"
                    out.add("mutable_vcs_dependency", rel, "low" if locked else "medium",
                            f"{name}: git dependency on {ref}, not a commit SHA: {spec['git']}",
                            package=str(name), ecosystem="pypi", line=_line_of(text, spec["git"]))
    sources = poetry.get("source")
    if isinstance(sources, list):
        for src in sources:
            if not isinstance(src, dict):
                continue
            url = str(src.get("url", ""))
            _check_registry_url(url, rel, _line_of(text, url) if url else None, out, "pypi")
            if str(src.get("priority", "")).lower() in {"supplemental", "secondary"} or src.get("secondary") is True:
                ctx.pip_extra_index.append((rel, _line_of(text, url) if url else None))
    uv = tool.get("uv") if isinstance(tool.get("uv"), dict) else {}
    uv_sources = uv.get("sources")
    if isinstance(uv_sources, dict):
        for name, spec in uv_sources.items():
            if isinstance(spec, dict) and isinstance(spec.get("git"), str) and not _SHA40.match(str(spec.get("rev", ""))):
                ref = spec.get("rev") or spec.get("tag") or spec.get("branch") or "default branch"
                out.add("mutable_vcs_dependency", rel, "low" if locked else "medium",
                        f"{name}: git source on {ref}, not a commit SHA: {spec['git']}",
                        package=str(name), ecosystem="pypi", line=_line_of(text, spec["git"]))
    indexes = uv.get("index")
    if isinstance(indexes, list):
        for idx in indexes:
            if isinstance(idx, dict) and isinstance(idx.get("url"), str):
                _check_registry_url(idx["url"], rel, _line_of(text, idx["url"]), out, "pypi")


# --- npm -------------------------------------------------------------------


def _npm_mutable(spec: str) -> str | None:
    """Why an npm dependency spec is mutable, or None."""
    lowered = spec.lower()
    if lowered.startswith(("file:", "link:", "workspace:", "npm:", "portal:", "patch:")):
        return None
    is_git = lowered.startswith(("git+", "git://", "github:", "gitlab:", "bitbucket:", "gist:")) or (
        not lowered.startswith("@") and "://" not in lowered and _NPM_GH_SHORTHAND_RE.match(spec) is not None
    )
    if is_git:
        ref = spec.split("#", 1)[1] if "#" in spec else ""
        return None if _SHA40.match(ref) else f"git dependency on {('#' + ref) if ref else 'the default branch'}, not a commit SHA"
    if lowered.startswith(("http://", "https://")):
        return "tarball URL dependency (no integrity hash in package.json)"
    return None


def _scan_package_json(root: Path, path: Path, rel: str, out: _Collector, ctx: _RegistryContext) -> None:
    text = _read(path)
    if text is None:
        return
    try:
        data = json.loads(text)
    except ValueError:
        return
    if not isinstance(data, dict):
        return
    own = data.get("name")
    if isinstance(own, str) and own.startswith("@") and "/" in own:
        ctx.npm_own_scopes.add(own[1:].split("/", 1)[0].lower())
    locked = _has_lock(root, path.parent, _NPM_LOCKS)
    has_deps = False
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            has_deps = True
            if not isinstance(spec, str):
                continue
            why = _npm_mutable(spec)
            if why:
                out.add("mutable_vcs_dependency", rel, "low" if locked else "medium", f"{name}: {why}: {spec}",
                        package=str(name), ecosystem="npm", line=_line_of(text, f'"{name}"'))
    if has_deps and not locked:
        out.add("unlocked_manifest", rel, "low",
                "package.json declares dependencies but no lockfile is committed — each install resolves the newest matching versions",
                ecosystem="npm")
    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        for hook in _INSTALL_HOOKS:
            cmd = scripts.get(hook)
            if isinstance(cmd, str) and _pipes_remote_to_shell(cmd):
                out.add("install_script", rel, "high",
                        f"the repo's own {hook} script pipes a download into a shell: {cmd[:160]}",
                        ecosystem="npm", line=_line_of(text, f'"{hook}"'))


def _pipes_remote_to_shell(cmd: str) -> bool:
    for segment in re.split(r"&&|;|\|\|", cmd):
        if "|" not in segment or ("curl" not in segment and "wget" not in segment):
            continue
        head, *tails = segment.split("|")
        if "curl" not in head and "wget" not in head:
            continue
        for tail in tails:
            words = [w for w in tail.split() if w not in {"sudo", "-E", "env"}]
            if words and words[0].rsplit("/", 1)[-1] in _SHELLS:
                return True
    return False


def _scan_package_lock(path: Path, rel: str, out: _Collector) -> None:
    text = _read(path)
    if text is None:
        return
    try:
        data = json.loads(text)
    except ValueError:
        return
    packages = data.get("packages") if isinstance(data, dict) else None
    if not isinstance(packages, dict):
        return
    root_pkg = packages.get("") if isinstance(packages.get(""), dict) else {}
    direct: set[str] = set()
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        if isinstance(root_pkg.get(section), dict):
            direct.update(root_pkg[section])
    missing_integrity: list[str] = []
    for key, pkg in packages.items():
        if not key.startswith("node_modules/") or not isinstance(pkg, dict):
            continue
        name = key[len("node_modules/"):]
        if "node_modules/" in name:
            continue  # nested copy; the top-level entry carries the direct flag
        if pkg.get("hasInstallScript") and name in direct:
            out.add("install_script", rel, "medium",
                    f"{name}@{pkg.get('version', '?')} runs an install script (preinstall/install/postinstall) on npm install",
                    package=name, ecosystem="npm", line=_line_of(text, f'"{key}"'))
        resolved = pkg.get("resolved")
        if (isinstance(resolved, str) and resolved.startswith(("http://", "https://"))
                and not pkg.get("integrity") and not pkg.get("link")):
            missing_integrity.append(name)
    if missing_integrity:
        shown = ", ".join(sorted(missing_integrity)[:5])
        more = f" (+{len(missing_integrity) - 5} more)" if len(missing_integrity) > 5 else ""
        out.add("unlocked_manifest", rel, "medium",
                f"{len(missing_integrity)} lockfile entr{'y' if len(missing_integrity) == 1 else 'ies'} resolved without an integrity hash: {shown}{more}",
                ecosystem="npm")
    for name, pkg in packages.items():
        resolved = pkg.get("resolved") if isinstance(pkg, dict) else None
        if isinstance(resolved, str) and resolved.startswith("http://") and not _is_local_url(resolved):
            out.add("insecure_registry", rel, "high", f"lockfile resolves {name[len('node_modules/'):]} over plain http: {resolved}",
                    ecosystem="npm", line=_line_of(text, resolved))
            break


# --- Go / Cargo / Composer -------------------------------------------------


def _scan_go_mod(root: Path, path: Path, rel: str, out: _Collector) -> None:
    text = _read(path)
    if text is None:
        return
    in_block = False
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("//", 1)[0].strip()
        if line.startswith("replace") and line.endswith("("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if not (in_block or line.startswith("replace ")) or "=>" not in line:
            continue
        match = _GO_REPLACE_RE.match(line)
        if not match:
            continue
        source, target = match.group(1), match.group(2)
        if target.startswith((".", "/")):
            resolved = (path.parent / target).resolve()
            if resolved == root or root in resolved.parents:
                continue  # an in-repo module (monorepo) — part of this codebase
            out.add("mutable_vcs_dependency", rel, "medium",
                    f"replace {source} => {target}: builds from a local path outside the repository, not a pinned module",
                    package=source, ecosystem="go", line=lineno)
        elif target.split("/")[:3] != source.split("/")[:3]:
            out.add("mutable_vcs_dependency", rel, "low",
                    f"replace {source} => {target} {match.group(3) or ''}".rstrip() + ": dependency redirected to a fork",
                    package=source, ecosystem="go", line=lineno)


def _scan_cargo_toml(root: Path, path: Path, rel: str, out: _Collector) -> None:
    text = _read(path)
    if text is None:
        return
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return
    locked = _has_lock(root, path.parent, ("Cargo.lock",))
    tables = [data.get(k) for k in ("dependencies", "dev-dependencies", "build-dependencies")]
    workspace = data.get("workspace")
    if isinstance(workspace, dict):
        tables.append(workspace.get("dependencies"))
    for table in tables:
        if not isinstance(table, dict):
            continue
        for name, spec in table.items():
            if isinstance(spec, dict) and isinstance(spec.get("git"), str) and not _SHA40.match(str(spec.get("rev", ""))):
                ref = spec.get("rev") or spec.get("tag") or spec.get("branch") or "default branch"
                out.add("mutable_vcs_dependency", rel, "low" if locked else "medium",
                        f"{name}: git dependency on {ref}, not a commit SHA: {spec['git']}",
                        package=str(name), ecosystem="cargo", line=_line_of(text, spec["git"]))


def _scan_unlocked_json(root: Path, path: Path, rel: str, out: _Collector, sections: tuple[str, ...],
                        locks: tuple[str, ...], eco: str) -> None:
    text = _read(path)
    try:
        data = json.loads(text) if text else None
    except ValueError:
        return
    if not isinstance(data, dict) or _has_lock(root, path.parent, locks):
        return
    names = [n for s in sections if isinstance(data.get(s), dict) for n in data[s]]
    if any(n.lower() != "php" and not n.lower().startswith(("ext-", "lib-")) for n in names):
        out.add("unlocked_manifest", rel, "low",
                f"{path.name} declares dependencies but no {locks[0]} is committed — each install resolves the newest matching versions",
                ecosystem=eco)


# --- Name-based checks -----------------------------------------------------


def _internal_match(name: str, prefixes: list[str], own_scopes: set[str]) -> tuple[str, bool] | None:
    """(reason, strong) when a name looks internal. ``strong`` = configured or
    the repo's own scope (vs. a generic ``internal-`` pattern)."""
    lowered = name.lower()
    for prefix in prefixes:
        if lowered.startswith(prefix):
            return f"matches internal_prefixes entry '{prefix}'", True
    for scope in own_scopes:
        if lowered.startswith(f"{scope}-"):
            return f"unscoped name with the repo's own '{scope}' prefix", True
    if lowered.startswith(_GENERIC_INTERNAL_PREFIXES) or lowered.endswith(_GENERIC_INTERNAL_SUFFIXES):
        return "internal-looking name", False
    return None


def _check_confusion(deps: list[DependencyHint], prefixes: list[str], ctx: _RegistryContext, out: _Collector) -> None:
    flagged_pypi = False
    for dep in deps:
        if not dep.direct:
            continue
        if dep.ecosystem == "pypi" and ctx.pip_extra_index:
            hit = _internal_match(dep.name, prefixes, set())
            if hit:
                flagged_pypi = True
                src, line = ctx.pip_extra_index[0]
                out.add("dependency_confusion", dep.file, "high",
                        f"{dep.name} ({hit[0]}) is installed with --extra-index-url ({src}) — pip picks the highest "
                        "version across PyPI and the private index, so a public upload of this name wins",
                        package=dep.name, ecosystem="pypi", line=dep.line)
        elif dep.ecosystem == "npm":
            if dep.name.startswith("@"):
                scope = dep.name[1:].split("/", 1)[0].lower()
                if scope in ctx.npm_own_scopes and ctx.npm_private_registry and scope not in ctx.npm_scoped_registries:
                    out.add("dependency_confusion", dep.file, "medium",
                            f"{dep.name}: the repo's own @{scope} scope has no '@{scope}:registry=' in .npmrc, so it "
                            "resolves through the default registry",
                            package=dep.name, ecosystem="npm", line=dep.line)
                continue
            hit = _internal_match(dep.name, prefixes, ctx.npm_own_scopes)
            if hit and (hit[1] or ctx.npm_private_registry):
                out.add("dependency_confusion", dep.file, "high" if hit[1] else "medium",
                        f"{dep.name} ({hit[0]}) is an unscoped npm name — anyone can publish it on the public registry; "
                        "move it under a scope with an '@org:registry=' mapping",
                        package=dep.name, ecosystem="npm", line=dep.line)
    if ctx.pip_extra_index and not flagged_pypi:
        src, line = ctx.pip_extra_index[0]
        out.add("dependency_confusion", src, "low",
                "--extra-index-url (or a supplemental index) merges a private index with PyPI: any private package "
                "name can be registered on PyPI with a higher version. Prefer a single proxying --index-url",
                ecosystem="pypi", line=line)


def _within_one_edit(a: str, b: str) -> bool:
    """Optimal-string-alignment (Damerau-Levenshtein) distance ≤ 1, a != b."""
    la, lb = len(a), len(b)
    if abs(la - lb) > 1 or a == b:
        return False
    if la == lb:
        diffs = [i for i in range(la) if a[i] != b[i]]
        if len(diffs) == 1:
            return True
        return len(diffs) == 2 and diffs[1] == diffs[0] + 1 and a[diffs[0]] == b[diffs[1]] and a[diffs[1]] == b[diffs[0]]
    short, long_ = (a, b) if la < lb else (b, a)
    i = 0
    while i < len(short) and short[i] == long_[i]:
        i += 1
    return short[i:] == long_[i + 1:]


def _check_typosquats(deps: list[DependencyHint], out: _Collector) -> None:
    for dep in deps:
        popular = BY_ECOSYSTEM.get(dep.ecosystem)
        if popular is None or not dep.direct:
            continue
        name = _pep503(dep.name) if dep.ecosystem == "pypi" else dep.name.lower()
        if len(name) < _TYPOSQUAT_MIN_LEN or name in popular:
            continue
        near = sorted(p for p in popular if abs(len(p) - len(name)) <= 1 and _within_one_edit(name, p))
        if near:
            out.add("typosquat_candidate", dep.file, "medium",
                    f"{dep.name} is one edit away from the popular package {', '.join(near[:3])} — check it isn't a typosquat",
                    package=dep.name, ecosystem=dep.ecosystem, line=dep.line)
