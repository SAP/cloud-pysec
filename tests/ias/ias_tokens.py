from tests.jwt_tools import sign


def merge(dict1, dict2):
    result = dict1.copy()
    result.update(dict2)
    return result


HEADER = {
        "alg": "RS256",
        "kid": "kid-custom"
    }

PAYLOAD = {
        "sub": "vorname.nachname@sap.com",
        "iss": "https://tenant.accounts400.ondemand.com",
        "groups": "CONFIGURED_GROUP",
        "given_name": "Vorname",
        "aud": [
          "clientid"
        ],
        "user_uuid": "db60e49c-1fb7-4a15-9a9e-8ababf856fe9",
        "azp": "70af88d4-0371-4374-b4f5-f24f650bfac5",
        "zone_uuid": "4b0c2b7a-1279-4352-a68d-a9a228a4f1e9",
        "iat": 1470815434,
        "exp": 2101535434,
        "family_name": "Nachname",
        "jti": "b23fa11e-3455-49f4-b0c3-a141e648e6ae",
        "email": "vorname.nachname@sap.com"
      }


VALID_TOKEN = sign(PAYLOAD, headers=HEADER)

VALID_TOKEN_WITH_CUSTOM_DOMAIN = sign(merge(PAYLOAD, {
        "ias_iss": "https://tenant.accounts400.ondemand.com",
        "iss": "https://tenant.custom.domain.com",
}), headers=HEADER)

TOKEN_INVALID_ISSUER = sign(merge(PAYLOAD, {
        "iss": "https://wrong-domain",
}), headers=HEADER)

TOKEN_INVALID_AUDIENCE = sign(merge(PAYLOAD, {
        "aud": ["wrong-client"],
}), headers=HEADER)

TOKEN_EXPIRED = sign(merge(PAYLOAD, {
        "exp": 1470815434,
}), headers=HEADER)
