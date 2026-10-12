import os

from flask import Flask

app = Flask(__name__)
app.secret_key = "dev"
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev")
