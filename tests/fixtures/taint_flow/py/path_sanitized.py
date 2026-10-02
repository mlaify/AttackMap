import os

from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)
REPORT_DIR = "/srv/reports"


@app.route("/reports/download")
def download_report():
    name = secure_filename(request.args["name"])  # taint: source
    with open(os.path.join(REPORT_DIR, name), "rb") as fh:  # taint: sink
        return fh.read()
