import hashlib
import hmac
import os

from fastapi import FastAPI, HTTPException, Request

from .db import record_push

app = FastAPI()


@app.post("/webhooks/github")
async def github(request: Request):
    body = await request.body()
    expected = "sha256=" + hmac.new(os.environ["GH_SECRET"].encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, request.headers.get("X-Hub-Signature-256", "")):
        raise HTTPException(401)
    record_push(await request.json())
    return {"ok": True}
