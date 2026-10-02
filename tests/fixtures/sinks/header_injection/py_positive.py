from flask import Flask, make_response, request

app = Flask(__name__)


@app.route("/exports/csv")  # taint: route
def export_csv():
    name = request.args.get("name", "export")
    resp = make_response(build_csv())
    resp.headers["Content-Disposition"] = f"attachment; filename={name}.csv"  # taint: sink
    return resp
