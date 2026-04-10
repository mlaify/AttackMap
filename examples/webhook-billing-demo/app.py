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
    db.execute("insert into webhook_events(status, secret_present) values (?, ?)", ("received", bool(signing_secret)))
    requests.post("https://billing-gateway.example.com/reconcile", json={"source": "stripe"})
    return {"processed": True}
