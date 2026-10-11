from jose import jwt


def current_user(token):
    return jwt.get_unverified_claims(token)["sub"]
