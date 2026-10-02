import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/orders/search")
def search_orders():
    term = request.args.get("q", "")  # taint: source
    db = sqlite3.connect("orders.db")
    rows = db.execute(f"SELECT id, sku FROM orders WHERE sku LIKE '%{term}%'").fetchall()  # taint: sink
    return {"rows": rows}
