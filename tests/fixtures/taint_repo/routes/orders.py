from flask import Flask, request

from services.orders import place_order

app = Flask(__name__)


@app.route("/orders", methods=["POST"])
def create_order():
    body = request.get_json()
    return place_order(body["order_id"])
