import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/orders/lookup")
def lookup_order():
    order_id = int(request.args["id"])  # taint: source
    db = sqlite3.connect("orders.db")
    row = db.execute(f"SELECT id, sku FROM orders WHERE id = {order_id}").fetchone()  # taint: sink
    return {"row": row}
