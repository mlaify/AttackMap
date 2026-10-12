import os

from flask import Flask, abort, request
from twilio.request_validator import RequestValidator

from .db import save_sms

app = Flask(__name__)


@app.route("/webhooks/twilio/sms", methods=["POST"])
def sms():
    validator = RequestValidator(os.environ["TWILIO_AUTH_TOKEN"])
    if not validator.validate(request.url, request.form, request.headers.get("X-Twilio-Signature", "")):
        abort(403)
    save_sms(request.form)
    return "<Response/>"
