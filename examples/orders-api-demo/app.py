from fastapi import FastAPI, Request
import os
import requests
import sqlite3

app = FastAPI()


@app.get("/health")
def health() -> dict[str, bool]:
    return {"ok": True}


@app.post("/orders")
async def create_order(request: Request) -> dict[str, str]:
    body = await request.json()
    customer_id = body["customer_id"]
    sku = body["sku"]
    quantity = body["quantity"]

    db = sqlite3.connect("orders.db")
    # NOTE: raw f-string SQL — no parameterization, no validation
    db.execute(
        f"insert into orders(customer_id, sku, quantity) "
        f"values ('{customer_id}', '{sku}', {quantity})"
    )

    requests.post(
        "https://fulfillment.example.com/dispatch",
        json={"customer_id": customer_id, "sku": sku, "quantity": quantity},
    )
    return {"customer_id": customer_id, "sku": sku}


@app.get("/orders/search")
def search_orders(q: str) -> dict[str, list]:
    db = sqlite3.connect("orders.db")
    # NOTE: query string concatenated directly into SQL
    cursor = db.execute(
        "select id, customer_id, sku from orders where sku like '%" + q + "%'"
    )
    return {"results": [dict(zip(["id", "customer_id", "sku"], row)) for row in cursor]}


@app.post("/internal/reindex")
def trigger_reindex(payload: dict) -> dict[str, bool]:
    table = payload.get("table", "orders")
    db = sqlite3.connect("orders.db")
    # NOTE: table name interpolated into DDL — DROP-able from outside
    db.execute(f"reindex {table}")
    requests.post(
        "https://search.example.com/refresh",
        headers={"authorization": f"Bearer {os.getenv('SEARCH_API_KEY', '')}"},
        json={"table": table},
    )
    return {"reindexed": True}
