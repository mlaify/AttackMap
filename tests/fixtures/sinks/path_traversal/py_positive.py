import os

from flask import Flask, request, send_file

app = Flask(__name__)
EXPORT_DIR = "/srv/exports"


@app.route("/exports/download")  # taint: route
def download_export():
    name = request.args["file"]
    return send_file(os.path.join(EXPORT_DIR, name))  # taint: sink
