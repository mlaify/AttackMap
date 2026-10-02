import os

from flask import Flask, request, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)
EXPORT_DIR = "/srv/exports"


@app.route("/exports/download")  # taint: route
def download_export():
    name = secure_filename(request.args["file"])
    return send_file(os.path.join(EXPORT_DIR, name))  # taint: sink
