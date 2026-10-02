import jsonpickle
from flask import Flask, request

app = Flask(__name__)


@app.route("/carts/restore", methods=["POST"])  # taint: route
def restore_cart():
    payload = request.get_data(as_text=True)
    cart = jsonpickle.decode(payload)  # taint: sink
    return {"items": len(cart.items)}
