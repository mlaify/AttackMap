import re

from flask import Flask, request

app = Flask(__name__)


@app.route("/logs/search")  # taint: route
def search_logs():
    pattern = re.escape(request.args["q"])
    matcher = re.compile(pattern)  # taint: sink
    return {"hits": [line for line in read_logs() if matcher.search(line)]}
