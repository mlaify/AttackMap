import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/fetch")
def fetch_preview():
    target = request.args.get("url")  # taint: source
    resp = requests.get(target, timeout=3)  # taint: sink
    return resp.text
