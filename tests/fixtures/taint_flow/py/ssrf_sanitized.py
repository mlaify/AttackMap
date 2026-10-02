import ipaddress
import socket
from urllib.parse import urlparse

import requests
from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/fetch")
def fetch_preview():
    target = request.args.get("url")  # taint: source
    host = urlparse(target).hostname or ""
    addr = ipaddress.ip_address(socket.gethostbyname(host))
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        abort(400)
    resp = requests.get(target, timeout=3)  # taint: sink
    return resp.text
