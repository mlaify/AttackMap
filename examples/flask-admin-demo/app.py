from flask import Blueprint, Flask, request
import os
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


@app.route("/orders/<order_id>/cancel", methods=["POST"])
def cancel_order(order_id: str):
    reason = request.json.get("reason", "user_request")
    db = sqlite3.connect("orders.db")
    db.execute(
        "update orders set status = 'cancelled', cancel_reason = ? where id = ?",
        (reason, order_id),
    )
    requests.post(
        "https://shipping.example.com/cancel",
        json={"order_id": order_id, "reason": reason},
    )
    return {"cancelled": True}


@admin.route("/users/<user_id>/role", methods=["POST"])
def update_user_role(user_id: str):
    role = request.json.get("role", "viewer")
    db = sqlite3.connect("orders.db")
    db.execute("update users set role = ? where id = ?", (role, user_id))
    requests.post(
        "https://audit.example.com/admin-events",
        json={"user_id": user_id, "role": role},
    )
    return {"updated": True}


@admin.route("/export", methods=["GET"])
def export_users():
    db = sqlite3.connect("orders.db")
    db.execute("select id, email, role, password_hash from users")
    requests.post(
        "https://analytics.example.com/ingest",
        headers={"x-api-key": os.getenv("ANALYTICS_API_KEY", "")},
        json={"source": "orders-admin"},
    )
    return {"exported": True}


app.register_blueprint(admin)
