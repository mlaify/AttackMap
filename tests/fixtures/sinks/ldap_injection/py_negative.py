import ldap
from ldap.filter import escape_filter_chars
from flask import Flask, request

app = Flask(__name__)
BASE_DN = "ou=people,dc=example,dc=com"


@app.route("/directory/lookup")  # taint: route
def lookup_user():
    uid = escape_filter_chars(request.args["uid"])
    conn = ldap.initialize("ldap://ldap.internal")
    results = conn.search_s(BASE_DN, ldap.SCOPE_SUBTREE, f"(uid={uid})")  # taint: sink
    return {"count": len(results)}
