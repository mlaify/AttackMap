from fastapi import FastAPI
import os
import requests
import sqlite3

app = FastAPI()


@app.get("/health")
def health() -> dict[str, bool]:
    return {"ok": True}


@app.post("/webhook/stripe")
def stripe_webhook() -> dict[str, bool]:
    signing_secret = os.getenv("STRIPE_WEBHOOK_SECRET")
    db = sqlite3.connect("billing.db")
    db.execute(
        "insert into webhook_events(status, secret_present) values (?, ?)",
        ("received", bool(signing_secret)),
    )
    requests.post(
        "https://billing-gateway.example.com/reconcile",
        json={"source": "stripe"},
    )
    return {"processed": True}


@app.post("/admin/refund")
def issue_refund(payload: dict) -> dict[str, bool]:
    customer_id = payload.get("customer_id")
    amount = payload.get("amount")
    db = sqlite3.connect("billing.db")
    db.execute(
        "insert into refunds(customer_id, amount_cents) values (?, ?)",
        (customer_id, amount),
    )
    requests.post(
        "https://payments-gateway.example.com/refunds",
        json={"customer_id": customer_id, "amount": amount},
    )
    return {"refunded": True}


@app.get("/admin/customers/{customer_id}")
def admin_get_customer(customer_id: str) -> dict[str, str]:
    db = sqlite3.connect("billing.db")
    db.execute("select email, tax_id from customers where id = ?", (customer_id,))
    return {"customer_id": customer_id}
