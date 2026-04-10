from flask import Blueprint, Flask, request
import requests
import sqlite3

app = Flask(__name__)
admin = Blueprint("admin", __name__, url_prefix="/admin")


@app.route("/login", methods=["POST"])
def login():
    return {"authenticated": True}


@app.route("/orders/<order_id>", methods=["GET"])
def get_order(order_id: str):
    db = sqlite3.connect("orders.db")
    db.execute("select * from orders where id = ?", (order_id,))
    requests.get(f"https://shipping.example.com/orders/{order_id}")
    return {"order_id": order_id}


@admin.route("/users/<user_id>/role", methods=["POST"])
def update_user_role(user_id: str):
    role = request.json.get("role", "viewer")
    db = sqlite3.connect("orders.db")
    db.execute("update users set role = ? where id = ?", (role, user_id))
    requests.post("https://audit.example.com/admin-events", json={"user_id": user_id, "role": role})
    return {"updated": True}
