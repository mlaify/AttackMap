import secrets
from urllib.parse import urlencode

from flask import Flask, redirect, session

app = Flask(__name__)
REGISTERED_REDIRECT_URIS = {"https://app.example.com/callback"}


@app.route("/login")
def login():
    session["oauth_state"] = secrets.token_urlsafe(32)
    query = urlencode({
        "response_type": "code",
        "client_id": app.config["CLIENT_ID"],
        "redirect_uri": "https://app.example.com/callback",
        "state": session["oauth_state"],
    })
    return redirect(f"https://id.example.com/authorize?{query}")


def redirect_allowed(redirect_uri):
    return redirect_uri in REGISTERED_REDIRECT_URIS
