# orders-api-demo

A FastAPI orders service that writes to a SQLite datastore using raw,
unparameterized SQL.

## Vulnerabilities on display

- **Raw f-string SQL on a write path.** `POST /orders` interpolates
  `customer_id`, `sku`, and `quantity` directly into an `INSERT` statement —
  classic SQL injection territory.
- **String-concatenated `LIKE` query.** `GET /orders/search` builds the
  `WHERE sku LIKE '%' || q || '%'` clause with `+`, so the query string is
  trusted as SQL.
- **Reachable internal DDL.** `POST /internal/reindex` is "internal" in name
  only — no auth — and interpolates a table name into a `REINDEX` statement.
- **Outbound credentials leaked into call sites.** `SEARCH_API_KEY` is read
  from the environment and sent as a bearer token to a third-party search
  service.

## Try it

```bash
attackmap analyze examples/orders-api-demo --output /tmp/am-orders
```

Expect the scanner to surface:

- An attack path titled *"Public input into sensitive data path"*,
- All three routes flagged for data-store proximity,
- `SEARCH_API_KEY` in the secret inventory,
- Outbound integrations to `fulfillment.example.com` and `search.example.com`.
