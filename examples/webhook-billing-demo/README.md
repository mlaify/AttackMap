# webhook-billing-demo

A FastAPI billing app with a third-party webhook entry point and a couple of
privileged admin routes sharing a single SQLite datastore.

## Vulnerabilities on display

- **Unsigned webhook.** `POST /webhook/stripe` reads `STRIPE_WEBHOOK_SECRET`
  from the environment but never verifies the inbound payload's signature.
- **No auth on admin routes.** `POST /admin/refund` and
  `GET /admin/customers/{id}` are reachable without any authentication
  middleware, despite touching financial state and PII.
- **Tight coupling between untrusted input and the datastore.** The same
  database is written to from the webhook handler and the admin handlers.

## Try it

```bash
attackmap analyze examples/webhook-billing-demo --output /tmp/am-webhook
```

Expect the scanner to surface:

- The webhook endpoint as a HIGH-severity public entry point,
- An attack path titled *"External event spoofing into internal state change"*,
- The outbound call to `billing-gateway.example.com` as a trust-boundary edge,
- `STRIPE_WEBHOOK_SECRET` in the secret inventory.
