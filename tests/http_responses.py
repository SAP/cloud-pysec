import json

KEY_ID_0 = "NODETESTSECRET"

KEY_ID_1 = r'''-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmNM3OXfZS0Uu8eYZXCgG
    WFgVWQX6MHnadYk3zHZ5PIPeDY3ApaSGpMEiVwn1cT6KUVHMLHcmz1gsNy74pCnm
    Ca22W7J3BoZulzR0A37ayMVrRHh3nffgySk8u581l02bvbcpab3e3EotSN5LixGT
    1VWZvDbalXf6n5kq459NWL6ZzkEs20MrOEk5cLdnsigTQUHSKIQ5TpldyDkJMm2zwOlrB2R984
    +QdlDFmoVH7Yaujxr2g0Z96u7W9Imik6wTiFc8W7eUXfhPGn7reVLq1/5o2Nz0Jx0ejFHDwTGncs
    +k1RBS6DbpTOMr9tkJEc3ZsX3Ft4OtqCkRXI5hUma+HwIDAQAB-----END PUBLIC KEY-----'''

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


