# express-docs-demo (benchmark case)

A small Express docs service used by `attackmap bench` (#239). Two routes carry
the two-line source → variable → sink shape and are genuinely exploitable:

- `GET /docs/raw` — `req.query.file` joined into a filesystem path (path traversal).
- `GET /preview` — `req.query.url` fetched server-side (SSRF).

Two routes are their known-clean twins and must not be flagged:

- `GET /docs/view` — the name is reduced with `path.basename` first.
- `GET /status/:service` — the upstream scheme and host are fixed literals.
