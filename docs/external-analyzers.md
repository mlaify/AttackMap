# Writing an external AttackMap analyzer

This is the developer-facing guide for building an analyzer plugin that ships as
its own PyPI package. If you only want to *use* analyzers, run
`pip install "attackmap[all]"` and stop reading.

The contract itself is documented in code at
[`attackmap.sdk`](../src/attackmap/sdk/__init__.py); this guide is the
"how to build one" companion. The two should always agree — if they don't,
the docstring is canonical and this file is wrong.

## What you're building

A small Python package that:

1. exposes a class satisfying [`AnalyzerProtocol`](../src/attackmap/sdk/contracts.py),
2. registers it under the `attackmap.analyzers` entry-point group, and
3. depends on `attackmap` for the contract types.

When a user runs `attackmap analyze /path/to/repo`, core discovers your plugin
via the entry-point group, asks each plugin's `detect()` whether it should run,
merges the `analyze()` outputs (per the rules in
[`merge.MERGE_SCHEMA`](../src/attackmap/merge.py)), and then owns everything
downstream: findings, attack paths, threat-model output, reports.

## Ownership boundary

| Owned by analyzers | Owned by core |
|---|---|
| `detect()` — is this a repo I should run on? | Discovering and loading analyzers |
| `analyze()` — emit structured signals with file/line citations | Merging results across analyzers |
| Surface-level normalization (path canonicalization, etc.) | Building the system graph |
|  | Generating findings + severity scores |
|  | Generating attack paths and threat-model output |
|  | Rendering CLI / JSON / markdown reports |

If you find yourself wanting to add finding generation, severity scoring, or
report rendering to an analyzer: emit a richer signal and let core do the
reasoning. That's how the system stays composable.

## Quick start

```
mkdir attackmap-analyzer-myframework
cd attackmap-analyzer-myframework
mkdir -p src/attackmap_analyzer_myframework tests
```

### `pyproject.toml`

```toml
[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "attackmap-analyzer-myframework"
version = "0.1.0"
description = "MyFramework analyzer plugin for AttackMap."
readme = "README.md"
requires-python = ">=3.11"
license = {text = "MIT"}
dependencies = [
  "pydantic>=2.7.0",
]

[project.optional-dependencies]
core = ["attackmap>=0.1.0"]
dev  = ["attackmap>=0.1.0", "pytest>=8.0.0", "build>=1.2.0"]

# This is what makes AttackMap discover your plugin.
[project.entry-points."attackmap.analyzers"]
myframework = "attackmap_analyzer_myframework:MyFrameworkAnalyzer"

[tool.setuptools]
package-dir = {"" = "src"}

[tool.setuptools.packages.find]
where = ["src"]
```

### `src/attackmap_analyzer_myframework/__init__.py`

```python
from .analyzer import MyFrameworkAnalyzer
__all__ = ["MyFrameworkAnalyzer"]
```

### `src/attackmap_analyzer_myframework/analyzer.py`

```python
from __future__ import annotations
from pathlib import Path

from attackmap.sdk import (
    AnalyzerMetadata,
    AnalyzerResult,
    Route,
)


class MyFrameworkAnalyzer:
    metadata = AnalyzerMetadata(
        name="myframework",
        display_name="MyFramework Analyzer",
        version="0.1.0",
        description="Detects MyFramework routes and config.",
        languages=["python"],
        targets=["myframework"],
        priority=200,           # higher = runs later in discovery order
        experimental=False,
        enabled_by_default=True,
    )

    @property
    def name(self) -> str:
        return self.metadata.name

    def detect(self, root: str | Path) -> bool:
        # Return True iff this repo looks like something we should run on.
        # Keep it fast — this is called on every scan.
        return (Path(root) / "myframework.yaml").exists()

    def analyze(self, root: str | Path) -> AnalyzerResult:
        result = AnalyzerResult(root=str(root))
        # Walk the tree, extract routes/secrets/hints with file:line citations,
        # populate the relevant ScanResult fields.
        # Example:
        # result.routes.append(Route(path="/api/v1/foo", method="GET", file="app/routes.py", line=42))
        return result
```

That's the whole contract.

## Testing

External analyzers typically test against small fixture repos. Pattern:

```
tests/
├── fixtures/
│   ├── myframework-app/        # a small but realistic example
│   │   ├── myframework.yaml
│   │   └── app/routes.py
│   └── not-myframework/        # negative case for detect()
│       └── README.md
└── test_analyzer.py
```

`test_analyzer.py`:

```python
from pathlib import Path
from attackmap_analyzer_myframework import MyFrameworkAnalyzer

FIXTURES = Path(__file__).parent / "fixtures"


def test_detect_finds_myframework_repo() -> None:
    assert MyFrameworkAnalyzer().detect(FIXTURES / "myframework-app") is True


def test_detect_rejects_non_myframework_repo() -> None:
    assert MyFrameworkAnalyzer().detect(FIXTURES / "not-myframework") is False


def test_analyze_emits_expected_routes() -> None:
    result = MyFrameworkAnalyzer().analyze(FIXTURES / "myframework-app")
    assert ("/api/v1/foo", "GET") in {(r.path, r.method) for r in result.routes}
```

Reference: the official analyzers ([`mlaify/attackmap-analyzer-python`](https://github.com/mlaify/attackmap-analyzer-python),
[`mlaify/attackmap-analyzer-rust`](https://github.com/mlaify/attackmap-analyzer-rust), and the
others listed below) all follow this pattern.

### CI tip: install attackmap from git during pre-PyPI development

If your analyzer depends on an unreleased version of `attackmap`, install it
from git in CI so `pip install -e ".[dev]"` doesn't fail resolving the
constraint:

```yaml
- name: Install attackmap core from main
  run: pip install "attackmap @ git+https://github.com/mlaify/AttackMap@main"

- name: Install package
  run: pip install -e ".[dev]"
```

## Merge semantics — what to expect when other analyzers also run

Two analyzers can emit overlapping signals. Core deduplicates by the keys
declared in [`merge.MERGE_SCHEMA`](../src/attackmap/merge.py):

| Field | Dedup key |
|---|---|
| `routes` | `(path, method, file)` |
| `external_calls` | `(target, file)` |
| `databases` | `(kind, file)` |
| `auth_hints` / `service_hints` / `edge_hints` / `entrypoint_hints` / `protocol_hints` / `framework_hints` | `(hint, file)` |
| `secret_hints` | `(name, file)` |

**First-seen wins.** If your analyzer emits `Route("/health", "GET", "app.py")`
and another analyzer emits the same triple, only the first one is kept. So a
"specialty" analyzer running after a "generic" one will *not* clobber the
generic's signal — design accordingly. If you want your signal to win, emit
with a different `file` granularity (e.g. cite the framework config file, not
the route file).

## What analyzers may not do

- **No subprocess calls** to other tools (linters, language servers, etc.).
  Analyzers must be self-contained Python.
- **No network access** during `detect()` or `analyze()`. Scans are offline.
- **No finding generation, severity scoring, or report rendering.** Emit
  signals; core does the reasoning.
- **No mutation of `root`.** Read-only.
- **No global state.** Multiple analyzers run in one process; instances are
  reused across calls.

## Publishing

1. Tag `v0.1.0`. The release workflow in any of the
   [`mlaify/attackmap-analyzer-*`](https://github.com/orgs/mlaify/repositories?q=attackmap-analyzer)
   repos shows the standard CI + GHCR + PyPI Trusted-Publishing setup; copy
   `.github/workflows/release.yml` and `ci.yml` from one of them.

2. Configure a **Pending Publisher** on PyPI for the new project name before
   pushing the tag (PyPI → Account → Publishing → Add a new pending
   publisher). Required fields: project name, GitHub owner, repo name,
   workflow filename `release.yml`, environment name `pypi`.

3. Wait for the release workflow to complete. After the first successful
   publish, the Pending Publisher converts to a Configured one and the
   3-pending-publisher slot is freed.

## Reference: the 13 official analyzers

Each of these lives in its own repo under [`mlaify/`](https://github.com/orgs/mlaify/repositories?q=attackmap-analyzer)
and ships to PyPI. Source-read any of them for a real, working analyzer.

| Plugin | Ecosystem |
|---|---|
| [`attackmap-analyzer-python`](https://github.com/mlaify/attackmap-analyzer-python) | Django, Starlette, AIOHTTP, Sanic, Litestar, DRF, SQLAlchemy/asyncpg, passlib/PyJWT, httpx |
| [`attackmap-analyzer-rust`](https://github.com/mlaify/attackmap-analyzer-rust) | axum, actix-web, rocket; sqlx, diesel, sea-orm; jsonwebtoken, argon2 |
| [`attackmap-analyzer-go`](https://github.com/mlaify/attackmap-analyzer-go) | net/http, chi, gin, echo, fiber; database/sql, gorm; golang-jwt |
| [`attackmap-analyzer-java-spring`](https://github.com/mlaify/attackmap-analyzer-java-spring) | Spring Boot, JAX-RS, Ktor; Spring Data; Spring Security |
| [`attackmap-analyzer-dotnet`](https://github.com/mlaify/attackmap-analyzer-dotnet) | ASP.NET Core, EF Core, Identity, JwtBearer |
| [`attackmap-analyzer-terraform`](https://github.com/mlaify/attackmap-analyzer-terraform) | AWS/Azure/GCP, IAM wildcards, open SGs, secrets |
| [`attackmap-analyzer-c`](https://github.com/mlaify/attackmap-analyzer-c) | libmicrohttpd, civetweb, mongoose; libcurl; OpenSSL/libsodium |
| [`attackmap-analyzer-cpp`](https://github.com/mlaify/attackmap-analyzer-cpp) | Crow, Pistache, Drogon, cpprestsdk; libcurl/cpr; libpqxx/mongocxx |
| [`attackmap-analyzer-node-service`](https://github.com/mlaify/attackmap-analyzer-node-service) | Node.js / TypeScript service ecosystems |
| [`attackmap-analyzer-atproto`](https://github.com/mlaify/attackmap-analyzer-atproto) | AT Protocol (Bluesky) services |
| [`attackmap-analyzer-php-web`](https://github.com/mlaify/attackmap-analyzer-php-web) | Generic PHP web |
| [`attackmap-analyzer-php-laminas`](https://github.com/mlaify/attackmap-analyzer-php-laminas) | Laminas / Zend MVC |
| [`attackmap-analyzer-omeka-s`](https://github.com/mlaify/attack-map-analyzer-omeka-s) | Omeka-S |

## Versioning

The SDK surface (`attackmap.sdk`) is stable across minor releases of the
`attackmap` package. Breaking changes only happen on a major-version bump;
deprecations get one release of overlap. Pin a lower bound in your
`pyproject.toml`:

```toml
[project.optional-dependencies]
core = ["attackmap>=0.1.0,<1.0.0"]
```

When you upgrade your lower bound, bump your analyzer's minor version.

## Where to ask for help

- Open an issue at [`mlaify/AttackMap`](https://github.com/mlaify/AttackMap/issues) tagged `analyzer`.
- Tag `@mlaify/maintainers` on PRs that touch the SDK surface.
