from flask import Flask, request

from services.calc import compute

app = Flask(__name__)


@app.route("/compute")
def compute_route():
    return compute(request.args["expr"])
