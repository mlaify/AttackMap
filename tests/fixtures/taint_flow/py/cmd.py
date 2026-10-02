import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/diag/ping", methods=["POST"])
def ping_host():
    host = request.form["host"]  # taint: source
    out = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)  # taint: sink
    return out.stdout
