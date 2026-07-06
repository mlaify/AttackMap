# AttackMap macOS GUI — Implementation Plan (dev-tool MVP)

Status: **draft for review** · Target: native SwiftUI app that drives the
already-installed `attackmap` CLI. No Python bundling, no notarization in scope.

---

## 1. Goal & scope

A native macOS app for users who already have `attackmap` on their `PATH`
(brew / pipx / venv). The app is a **launcher + viewer**: it runs a scan,
streams progress, and renders the JSON artifacts the engine already produces.

**Repo:** separate — `mlaify/AttackMap-mac` (versions independently of the engine).
**Min target:** macOS 15 (Sequoia).

**In scope (MVP / v1):**
- Pick a repo folder, choose options, run a scan, watch live progress, cancel.
- Render findings, exploitability ranking, attack paths, attack surface, and the
  defensive review from `attackmap-report.json`.
- Diagram view (Mermaid/Graphviz) and raw-artifact access.
- LLM toggles (`--llm / --hunt / --verify / --remediate`) with a Keychain-stored
  API key or the `claude` CLI backend.
- **Watch mode** — observe the repo and auto re-scan on change (debounced).

**Explicitly out of scope (future):** bundling a Python runtime, code-signing +
notarization for general distribution, Mac App Store / App Sandbox. See §11.

---

## 2. Architecture — subprocess + JSON

```
┌─────────────────────── AttackMap.app (SwiftUI) ───────────────────────┐
│  ScanConfig  ──►  ProcessRunner ──► /usr/bin/env attackmap analyze …   │
│                        │  stderr (NDJSON progress)  ──► ProgressModel  │
│                        │  exit code                                    │
│                        ▼                                               │
│                 reports/  (on disk)                                    │
│                   attackmap-report.json  ──► ReportDecoder (Codable)   │
│                   *.dot / *.md            ──► DiagramView / MarkdownView│
└───────────────────────────────────────────────────────────────────────┘
```

- The engine stays a **black box**. The app never imports Python; it only spawns
  the CLI and reads files. Zero version coupling beyond the JSON schema.
- Results are read from the monolithic `attackmap-report.json` (single decode),
  with `.dot`/`.md` artifacts read on demand for diagrams and prose.

---

## 3. The one engine-side change: machine-readable progress

`progress.py` today gates on `stream.isatty()` and renders a TTY bar, so a
subprocess sees nothing. The `begin / advance / stage / done` hooks already
exist — we add a second sink that emits **NDJSON** (one JSON object per line),
selected by a new flag. No rewrite.

- New CLI flag: `--progress-format {auto,tty,json,none}` (default `auto` = today's
  behavior). `json` emits to **stderr** (stdout stays clean for `--format json`
  consumers).
- Event shape (stable, versioned):
  ```json
  {"v":1,"event":"begin","total":1240,"label":"Scanning files"}
  {"v":1,"event":"advance","current":"src/app.ts","done":37,"total":1240}
  {"v":1,"event":"stage","label":"Taint analysis"}
  {"v":1,"event":"done","summary":"1240 files, 18 findings","elapsed_s":92.4}
  ```
- Swift reads stderr line-by-line, decodes each event, drives a determinate
  `ProgressView` + ETA (ETA computed app-side from done/total/elapsed).
- ~1 small module + a flag; ships as a normal AttackMap patch release. This is
  the only change to the Python side.

**Stream shape the GUI must handle (verified against a real run):** a scan runs
several analyzer sub-passes, and each drives its own `begin → advance… →
stage… → done` cycle on the shared progress object. So the stream contains
**multiple `begin`/`done` cycles**, not one. Consumer contract:
- Treat each `begin` as "(re)start the determinate bar at 0/`total`" for a new
  sub-pass, and `stage` as an indeterminate tail phase within it.
- Treat the **child process exit** (code 0 + `attackmap-report.json` present) as
  the *authoritative* scan-complete signal — not any single `done` (a sub-pass
  that matched no files legitimately emits `done` with `done:0,total:0`).
- Events are versioned (`"v":1`); ignore unknown event types.

*(Nice-to-have, not required for M0: tag each `begin` with the analyzer name so
the GUI can label sub-passes. `scan_repo` doesn't currently know its caller's
analyzer name; deferred.)*

---

## 4. Swift app structure

Single app target, SwiftUI lifecycle, minimum **macOS 15 (Sequoia)** for the
latest SwiftUI (`Table`, `@Observable`, `NavigationSplitView` refinements).

```
AttackMapGUI/
  App.swift                 // @main, window scene
  Models/
    Report.swift            // Codable: Scan, Finding, AttackPath, Exploitability…
    ScanConfig.swift        // folder, format, llm/hunt/verify/remediate/cve, baseline
    ProgressEvent.swift     // Codable NDJSON events
  Services/
    CLILocator.swift        // find `attackmap` on PATH + common locations
    ProcessRunner.swift     // spawn, stream stderr, cancel, exit handling
    ReportStore.swift       // load/parse artifacts, recent-scans history
    RepoWatcher.swift       // FSEvents + debounce → auto re-scan (watch mode)
    Keychain.swift          // ANTHROPIC_API_KEY storage
  Views/
    SidebarView.swift       // sections: Overview, Findings, Exploitability, Paths, Surface, Diagrams, Raw
    ScanBarView.swift       // folder picker, options, Run/Cancel, progress
    FindingsListView.swift  // Table + detail; severity/confidence filters
    ExploitabilityView.swift// ranked table with factor breakdown
    AttackPathView.swift    // step-by-step chain detail
    DiagramView.swift       // WKWebView + mermaid.js (bundled) / dot render
    MarkdownView.swift      // defensive review prose
    SettingsView.swift      // CLI path override, API key, default options
```

---

## 5. Data model mapping

`attackmap-report.json` top-level keys → Swift `Codable` structs:

| JSON key | Swift type | View |
|---|---|---|
| `scan` | `Scan` (root, languages, files_scanned, routes…) | Overview |
| `findings[]` (each has stable `id`) | `[Finding]` | Findings list/detail |
| `exploitability[]` | `[ExploitabilityScore]` | Ranked table + factors |
| `attack_paths[]` | `[AttackPath]` | Path detail |
| `attack_surfaces[]` | `[AttackSurface]` | Surface classification |
| `defensive_review` (md) / `defensive_review_json` | prose + structured | Review |
| `review_context_pack` | context/domain hints | Overview meta |

Two published JSON Schemas already exist (`schemas/defensive-review.schema.json`,
`review-context-pack.schema.json`) — we can **codegen** those structs and
hand-write the rest, keeping the app in lockstep with a documented contract.
Decode is tolerant (unknown keys ignored) so engine minor-version bumps don't
break the app.

---

## 6. UX flow

1. **Pick folder** (`NSOpenPanel`, directories only) → shows detected repo name.
2. **Options row**: format (defaults to `json` for the app), CVE, LLM mode
   (none / review / hunt / hunt+verify / remediate), optional baseline file.
3. **Run** → spawns CLI into a temp/known `reports/` dir; progress bar + current
   file + stage label + ETA; **Cancel** sends SIGTERM.
4. **On success** → auto-load `attackmap-report.json`, land on Overview.
5. **Sidebar navigation** across the result sections; **Findings** is the
   workhorse (sortable `Table`, severity/confidence filters, click → evidence +
   file:line + ATT&CK technique).
6. **Recent scans** persisted so results reopen without re-running.

---

## 7. Process & environment details

- **CLI discovery** (`CLILocator`): search `PATH`, then `/opt/homebrew/bin`,
  `/usr/local/bin`, `~/.local/bin` (pipx); Settings lets the user pin an explicit
  path. Show a clear "attackmap not found — brew install mlaify/tap/attackmap"
  state if missing.
- **Spawn**: `Process` with `env` inheriting the user shell env; add
  `ANTHROPIC_API_KEY` from Keychain only when an LLM mode is selected (respects
  the engine's API→token→CLI backend precedence).
- **Cancel**: `process.terminate()`; treat non-zero/interrupted as "no report."
- **Long scans**: the 10–15 min case is why streaming progress matters; keep the
  UI responsive (runner off the main actor, events marshaled back).

---

## 8. Diagrams

- Mermaid: bundle `mermaid.min.js` in the app, render the `attackmap-*.md`
  fenced diagram in a `WKWebView` (fully offline, no CSP/network calls).
- Graphviz `.dot`: MVP shows source + "Open in…"; a native render (e.g. via a
  bundled dot-to-svg) is a later nicety.

---

## 9. Milestones (dev-tool MVP)

| # | Milestone | Deliverable | Est. |
|---|---|---|---|
| M0 | Engine progress sink | `--progress-format json` NDJSON in AttackMap + tests; patch release | 0.5–1 d |
| M1 | Spawn + parse | CLILocator, ProcessRunner, decode report into models; print to console | 1 d |
| M2 | Core UI | Folder picker, run/cancel, live progress, Overview + Findings table/detail | 1.5–2 d |
| M3 | Rich views | Exploitability, attack paths, surface, defensive-review markdown | 1 d |
| M4 | Diagrams, settings, recents | Mermaid WebView, Settings (CLI path/API key), recent scans | 1 d |
| M5 | Watch mode | `RepoWatcher` (FSEvents + debounce), auto re-scan toggle, diff vs. previous run | 1–1.5 d |

**Total ≈ 6–8 days** for a genuinely useful internal app. M0 is the only piece
that touches the Python engine repo and can ship independently.

**Watch mode notes:** FSEvents stream on the repo root, ignore `reports/` (our
own output) + `.git/` to avoid feedback loops, debounce ~1.5 s of quiet before
re-scanning, and never overlap runs (queue/skip while a scan is in flight).
Auto-reuse the previous `attackmap-report.json` as `--baseline` so each re-scan
surfaces *new vs. resolved* findings.

---

## 10. Risks & mitigations

- **Engine JSON drift** → decode tolerantly; pin to schema; add a decode smoke
  test against a checked-in sample `attackmap-report.json`.
- **Progress protocol churn** → version the NDJSON (`"v":1`); app ignores unknown
  events.
- **CLI not on PATH / wrong version** → explicit not-found + version-mismatch UI;
  Settings override.
- **Very large reports** → decode off-main-actor; lazy-load diagrams/raw.

---

## 11. Deferred (the "self-contained app" path)

If we later want a double-clickable app for non-technical users:
bundle a Python runtime (`python-build-standalone`) + deps (note `pydantic-core`
is a **Rust** native ext), code-sign + notarize for Gatekeeper; Mac App Store
adds App Sandbox → security-scoped bookmarks for scanning arbitrary folders and
no arbitrary subprocess (would force embedding). This is weeks of work and is
intentionally out of scope for the MVP.

---

## 12. Decisions (resolved 2026-07-06)

1. **Repo placement** — separate repo `mlaify/AttackMap-mac`. ✅
2. **Min macOS target** — macOS 15 (Sequoia). ✅
3. **Watch mode** — in v1 (milestone M5). ✅
