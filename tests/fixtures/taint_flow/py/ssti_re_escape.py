import html
import re

from flask import Flask, render_template_string, request

app = Flask(__name__)
SEPARATOR = re.compile(re.escape("--") + "+")


def slugify(text):
    return SEPARATOR.sub("-", html.escape(text).lower())


@app.route("/preview", methods=["POST"])
def preview():
    body = request.form["template"]  # taint: source
    return render_template_string(body)  # taint: sink
