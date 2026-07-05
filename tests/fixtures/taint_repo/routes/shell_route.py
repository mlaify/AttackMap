from flask import Flask, request

from services.deploy import kickoff

app = Flask(__name__)


@app.route("/deploy", methods=["POST"])
def deploy():
    return kickoff(request.get_json())
