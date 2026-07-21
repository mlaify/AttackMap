from flask import Flask, request

# The symbol below is imported but never called or referenced in this file
# (a dead import). Its module holds a dangerous sink the route never reaches.
from services.reporting import run_report  # noqa: F401

app = Flask(__name__)


@app.route("/dashboard")
def dashboard():
    return "dashboard"
