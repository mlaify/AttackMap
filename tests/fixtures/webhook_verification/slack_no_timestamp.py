import hashlib
import hmac
import os

from flask import Flask, abort, request

from .db import save_command

app = Flask(__name__)


@app.post("/webhooks/slack")
def slack_events():
    timestamp = request.headers["X-Slack-Request-Timestamp"]
    signature = request.headers["X-Slack-Signature"]
    base = f"v0:{timestamp}:{request.get_data(as_text=True)}"
    digest = "v0=" + hmac.new(os.environ["SLACK_SIGNING_SECRET"].encode(), base.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(digest, signature):
        abort(401)
    save_command(request.form)
    return "", 200
