import importlib

from flask import Flask, abort, request

app = Flask(__name__)
ALLOWED_REPORTS = {"reports.daily", "reports.weekly"}


@app.route("/reports/run")  # taint: route
def run_report():
    module_name = request.args["report"]
    if module_name not in ALLOWED_REPORTS:
        abort(400)
    report = importlib.import_module(module_name)  # taint: sink
    return report.render()
