from fastapi import FastAPI
import os
import requests

app = FastAPI()

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/webhook/stripe")
def stripe_hook():
    api_key = os.getenv("STRIPE_SECRET_KEY")
    requests.post("https://api.example.com/notify", json={"event": "stripe", "key_present": bool(api_key)})
    return {"processed": True}
