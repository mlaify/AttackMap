from authlib.jose import JsonWebToken

jwt = JsonWebToken(["RS256"])


def current_user(token, key):
    claims = jwt.decode(token, key, claims_options={"iss": {"essential": True, "value": "https://id.example.com"}})
    claims.validate()
    return claims["sub"]
