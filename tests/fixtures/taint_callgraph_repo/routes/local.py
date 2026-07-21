from flask import Flask, request

app = Flask(__name__)


def _do_eval(expr):
    return eval(expr)  # sink defined + called within this same file


@app.route("/local-eval")
def local_eval():
    return _do_eval(request.args["expr"])
