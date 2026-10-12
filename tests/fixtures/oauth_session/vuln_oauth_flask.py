from urllib.parse import urlencode

from flask import Flask, redirect, request

app = Flask(__name__)


@app.route("/login")
def login():
    query = urlencode({
        "response_type": "code",
        "client_id": app.config["CLIENT_ID"],
        "redirect_uri": "https://app.example.com/callback",
    })
    return redirect(f"https://id.example.com/authorize?{query}")


def redirect_allowed(redirect_uri):
    return "app.example.com" in redirect_uri
