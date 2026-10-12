import os

import jwt

KEYS = {"main": os.environ["JWT_PUBLIC_KEY"]}


def issue(user_id):
    return jwt.encode({"sub": user_id}, os.environ["JWT_PRIVATE_KEY"], algorithm="RS256")


def check(token):
    header = jwt.get_unverified_header(token)
    return jwt.decode(token, KEYS[header["kid"]], algorithms=["RS256"], audience="api")


def key_row(db, header):
    return db.execute("SELECT pem FROM keys WHERE kid = %s", (header["kid"],))
