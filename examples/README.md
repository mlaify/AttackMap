# AttackMap example applications

Three small, intentionally vulnerable apps used to demo AttackMap and validate
its analyzer behavior. Each is a single `app.py` so the scan output is easy to
trace back to source.

| Example | Stack | What it demonstrates | Attack path it surfaces |
|---|---|---|---|
| [`webhook-billing-demo`](./webhook-billing-demo) | FastAPI | Unsigned third-party webhook + privileged admin routes adjacent to a data store | External event spoofing into internal state change |
| [`flask-admin-demo`](./flask-admin-demo) | Flask + Blueprint | Login endpoint, public order routes, and `/admin/*` routes that share a data store | Administrative route abuse |
| [`orders-api-demo`](./orders-api-demo) | FastAPI | Public route writing to a data store with raw f-string SQL and unvalidated input | Public input into sensitive data path |

## Run AttackMap against any example

```bash
attackmap analyze examples/webhook-billing-demo --output /tmp/am-out
```

Add `--llm` to also generate a Claude-backed narrative review.

## What "vulnerable" means here

These apps are deliberate caricatures — they make one or two weaknesses obvious
so the scanner has clear signal to work with. They are *not* meant to be
exhaustive vulnerable test corpora; for that, see projects like
[OWASP Juice Shop](https://github.com/juice-shop/juice-shop) or
[Damn Vulnerable Web Application](https://github.com/digininja/DVWA).

Each example produces:

- **A clear attack surface** — routes, datastores, external calls enumerated.
- **Meaningful findings** — 3–4 HIGH/MEDIUM signals per app, each tied to a
  file:line citation.
- **At least one attack path** — a named, multi-step narrative that connects
  the surface to a plausible impact.

Across the three apps you get three distinct attack-path archetypes; together
they're enough to demo what AttackMap looks at on real code without each demo
having to repeat the others.
