import tarfile

from flask import Flask, request

app = Flask(__name__)
IMPORT_DIR = "/srv/imports"


@app.route("/themes/import", methods=["POST"])  # taint: route
def import_theme():
    upload = request.files["bundle"]
    with tarfile.open(fileobj=upload.stream) as tar:
        tar.extractall(IMPORT_DIR, filter="data")  # taint: sink
    return {"ok": True}
