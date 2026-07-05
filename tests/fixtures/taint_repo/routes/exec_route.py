from flask import Flask, request

from services.calculator import run

app = Flask(__name__)


@app.route("/calc", methods=["POST"])
def calc():
    expr = request.get_json()["expr"]
    return {"result": run(expr)}
