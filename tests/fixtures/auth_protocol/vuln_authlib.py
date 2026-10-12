from authlib.jose import jwt


def current_user(token, key):
    claims = jwt.decode(token, key)
    return claims["sub"]
