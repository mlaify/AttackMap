import jwt


def issue(user_id):
    return jwt.encode({"sub": user_id}, "secret", algorithm="HS256")


def check(token, public_key):
    return jwt.decode(token, public_key)


def lenient(token, key):
    return jwt.decode(token, key, algorithms=["RS256"], options={"verify_exp": False})


def key_for(header):
    with open(f"keys/{header['kid']}.pem") as fh:
        return fh.read()


def key_row(db, header):
    return db.execute(f"SELECT pem FROM keys WHERE kid = '{header['kid']}'")
