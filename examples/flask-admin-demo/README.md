# flask-admin-demo

A Flask app split between public order routes and a `/admin/*` Blueprint, both
sharing one SQLite datastore.

## Vulnerabilities on display

- **Auth gap.** `POST /login` exists but every other route — including the
  `/admin/*` Blueprint — has no authentication or session check.
- **Mixed exposure on one datastore.** `GET /orders/<id>` (public) and
  `POST /admin/users/<id>/role` (privileged) both write to `orders.db`.
- **Privileged data export.** `GET /admin/export` reads `password_hash` from
  the users table and ships it to an external analytics endpoint with an API
  key from the environment.

## Try it

```bash
attackmap analyze examples/flask-admin-demo --output /tmp/am-flask
```

Expect the scanner to surface:

- An attack path titled *"Administrative route abuse"*,
- The `/admin/*` routes flagged with HIGH severity,
- `ANALYTICS_API_KEY` in the secret inventory,
- Outbound integrations to `shipping.example.com`, `audit.example.com`, and
  `analytics.example.com` as separate trust-boundary edges.
