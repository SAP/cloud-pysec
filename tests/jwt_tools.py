import jwt

from tests.keys import PRIVATE_KEY


def sign(payload):
    payload = {k: payload[k] for k in payload if payload[k] is not None}
    return jwt.encode(payload, PRIVATE_KEY, algorithm="RS256", headers={
        "jku": "https://api.cf.test.com",
        "kid": "key-id-0"
    }).decode("utf-8")
