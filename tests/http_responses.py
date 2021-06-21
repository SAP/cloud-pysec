import json

from tests.keys import JWT_SIGNING_PUBLIC_KEY

KEY_ID_0 = JWT_SIGNING_PUBLIC_KEY

KEY_ID_1 = "ANOTHER-KEY"

HTTP_SUCCESS = json.loads(r'''{
    "keys": [
        {
            "kty": "RSA",
            "e": "AQAB",
            "use": "sig",
            "kid": "key-id-0",
            "alg": "RS256",
            "value": "%s",
            "n": "AJjTNzl32UtFLvHmGVwoBlhYFVkF-jB52nWJN8x2eTyD3g2NwKWkhqTBIlcJ9XE-ilFRzCx3Js9YLDcu
            -KQp5gmttluydwaGbpc0dAN-2sjFa0R4d5334MkpPLufNZdNm723KWm93txKLUjeS4sRk9VVmbw22pV3-p-ZKuOfTVi
            -mc5BLNtDKzhJOXC3Z7IoE0FB0iiEOU6ZXcg5CTJts8DpawdkffOPkHZQxZqFR-2Gro8a9oNGferu1vSJopOsE4hXPFu3lF34Txp
            -63lS6tf-aNjc9CcdHoxRw8Exp3LPpNUQUug26UzjK_bZCRHN2bF9xbeDragpEVyOYVJmvh8"
        },
        {
            "kty": "RSA",
            "e": "AQAB",
            "use": "sig",
            "kid": "key-id-1",
            "alg": "RS256",
            "value": "%s",
            "n": "AJjTNzl32UtFLvHmGVwoBlhYFVkF-jB52nWJN8x2eTyD3g2NwKWkhqTBIlcJ9XE-ilFRzCx3Js9YLDcu
            -KQp5gmttluydwaGbpc0dAN-2sjFa0R4d5334MkpPLufNZdNm723KWm93txKLUjeS4sRk9VVmbw22pV3-p-ZKuOfTVi
            -mc5BLNtDKzhJOXC3Z7IoE0FB0iiEOU6ZXcg5CTJts8DpawdkffOPkHZQxZqFR-2Gro8a9oNGferu1vSJopOsE4hXPFu3lF34Txp
            -63lS6tf-aNjc9CcdHoxRw8Exp3LPpNUQUug26UzjK_bZCRHN2bF9xbeDragpEVyOYVJmvh8"
        }
    ]
}''' % (KEY_ID_0, KEY_ID_1), strict=False)


HTTP_SUCCESS_DUMMY = json.loads(r'''{
    "keys": [
        {
            "kty": "RSA",
            "e": "AQAB",
            "use": "sig",
            "kid": "key-id-0",
            "alg": "RS256",
            "value": "dummy-key",
            "n": "AJjTNzl32UtFLvHmGVwoBlhYFVkF-jB52nWJN8x2eTyD3g2NwKWkhqTBIlcJ9XE-ilFRzCx3Js9YLDcu
            -KQp5gmttluydwaGbpc0dAN-2sjFa0R4d5334MkpPLufNZdNm723KWm93txKLUjeS4sRk9VVmbw22pV3-p-ZKuOfTVi
            -mc5BLNtDKzhJOXC3Z7IoE0FB0iiEOU6ZXcg5CTJts8DpawdkffOPkHZQxZqFR-2Gro8a9oNGferu1vSJopOsE4hXPFu3lF34Txp
            -63lS6tf-aNjc9CcdHoxRw8Exp3LPpNUQUug26UzjK_bZCRHN2bF9xbeDragpEVyOYVJmvh8"
        },
        {
            "kty": "RSA",
            "e": "AQAB",
            "use": "sig",
            "kid": "key-id-1",
            "alg": "RS256",
            "value": "dummy-key",
            "n": "AJjTNzl32UtFLvHmGVwoBlhYFVkF-jB52nWJN8x2eTyD3g2NwKWkhqTBIlcJ9XE-ilFRzCx3Js9YLDcu
            -KQp5gmttluydwaGbpc0dAN-2sjFa0R4d5334MkpPLufNZdNm723KWm93txKLUjeS4sRk9VVmbw22pV3-p-ZKuOfTVi
            -mc5BLNtDKzhJOXC3Z7IoE0FB0iiEOU6ZXcg5CTJts8DpawdkffOPkHZQxZqFR-2Gro8a9oNGferu1vSJopOsE4hXPFu3lF34Txp
            -63lS6tf-aNjc9CcdHoxRw8Exp3LPpNUQUug26UzjK_bZCRHN2bF9xbeDragpEVyOYVJmvh8"
        }
    ]
}''', strict=False)


