# Scanner Responsibility Review

## Scope Reviewed

- Core scanner: [scanner.py](/Volumes/Dev/repos/GitHub/mlaify/attackmap/AttackMap/src/attackmap/scanner.py)
- Specialized analyzers:
  - [node-service analyzer](/Volumes/Dev/repos/GitHub/mlaify/attackmap/attackmap-analyzer-node-service/src/attackmap_analyzer_node_service/analyzer.py)
  - [atproto analyzer](/Volumes/Dev/repos/GitHub/mlaify/attackmap/attackmap-analyzer-atproto/src/attackmap_analyzer_atproto/analyzer.py)

## 1) Ecosystem-Specific Logic Embedded in `scanner.py`

`scanner.py` currently includes both generic scanning and ecosystem overlays:

- Generic route extraction:
  - FastAPI/Flask/Express parsing (`_extract_python_routes`, `_extract_javascript_routes`, `extract_routes`)
- Generic recon extraction:
  - outbound calls (`EXTERNAL_CALL_PATTERNS`)
  - datastore hints (`DB_PATTERNS`, `DB_KEYWORDS`, `_append_unique_database_hints`)
  - auth hints (`AUTH_PATTERNS`, `AUTH_KEYWORDS`, `_append_unique_auth_hints`)
  - secrets (`SECRET_PATTERNS`)
- **Node-service overlay logic**:
  - `NODE_SERVICE_ENV_URL_PATTERN`, `NODE_EVENT_CONSUMER_PATTERN`
  - `_infer_service_name`, `_infer_service_role`, target service inference helpers
  - `_append_node_service_signals` (service name/role, handler visibility/type, edges)
- **ATProto overlay logic**:
  - `ATPROTO_XRPC_LITERAL_PATTERN`, `ATPROTO_EVENT_STREAM_PATTERNS`
  - `_append_atproto_overlay_signals` (atproto protocol/namespace/xrpc refs + synthetic routes/event hints)

## 2) Overlap With Specialized Analyzer Packages

### Overlap with `node-service`

Both scanner overlay and `node-service` analyzer implement:

- JS/TS service identity inference (`service_name:*`, `service_role:*`)
- entrypoint/handler registration signals
- outbound env URL extraction (`env://...`)
- inter-service edge inference (`edge:a->b`)
- JS/TS route extraction for backend patterns

This is duplicated behavior with slightly different heuristics and output richness.

### Overlap with `atproto`

Both scanner overlay and `atproto` analyzer implement:

- detection of `/xrpc/...` references
- atproto namespace hints (`com.atproto`, `app.bsky`)
- protocol hints (`atproto_protocol:xrpc`)
- event-stream hints (`subscribeRepos`, websocket/firehose-like cues)
- synthetic route creation from protocol literals

Again, this is duplicated and currently split across core scanner + analyzer plugin.

## 3) Responsibility Separation (Target State)

### Generic scanner responsibilities (keep in `scanner.py`)

- repo traversal and file filtering
- language accounting and file counts
- framework-agnostic recon extraction:
  - generic route extraction (FastAPI/Flask/Express baseline)
  - generic external call detection
  - generic datastore hints
  - generic auth hints
  - generic secret hints
- deterministic de-dup at scan stage

### Specialized analyzer responsibilities (move out of `scanner.py`)

- Node distributed service overlays:
  - service identity, role, and boundary hints
  - entrypoint classification specific to service architectures
  - inter-service edge inference from env and internal URLs
- AT Protocol overlays:
  - protocol namespace + XRPC surface inference
  - lexicon/protocol event-stream semantics
  - ATProto-specific synthetic endpoint enrichment

## 4) Risk Notes

- Current core scanner still emits Node/ATProto overlays even when corresponding specialized analyzers run, which can inflate/duplicate hints.
- Overlay hints currently flow through legacy `auth_hints`, increasing semantic noise during migration.
- Removal should be staged behind compatibility tests to avoid behavior regressions in findings/path generation.

