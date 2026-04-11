# Scanner Simplification Notes

## What changed

`scanner.py` was refactored to keep only generic scanner responsibilities:

- file walking and suffix filtering
- generic route extraction (FastAPI/Flask/Express)
- generic external call extraction
- generic database hint extraction
- generic auth hint extraction
- generic secret hint extraction

In this pass, scanner imports were also aligned to canonical shared models via `attackmap.sdk.models` to reinforce that scanner emits shared recon models only.

Removed from `scanner.py`:

- node-service overlays:
  - service name/role inference
  - handler visibility overlays
  - edge inference from env vars and URLs
- atproto overlays:
  - XRPC literal overlay hints
  - namespace/protocol overlay hints
  - event-stream overlay hints
  - synthetic ATProto route overlays

## Why

This removes duplicated ownership between core scanner and specialized analyzers.
Node/ATProto specialized behavior should come from dedicated analyzers (`node-service`, `atproto`) rather than generic scanner internals.

## Compatibility behavior

- Main scanning pipeline remains intact.
- Built-in Python/JavaScript analyzers still run generic scanner logic as fallback.
- Specialized ecosystem hints are now expected from dedicated analyzers (or plugins), not scanner overlays.

## Tests updated

- Scanner tests now assert generic JS/TS extraction and explicitly assert absence of node/atproto overlay hints.
- Analyzer tests now include analyzer-driven specialized overlay coverage via a synthetic analyzer fixture.
