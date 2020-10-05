# pylint: disable=line-too-long
''' Test jwt tokens '''


def merge(dict1, dict2):
    result = dict1.copy()
    result.update(dict2)
    return result


USER_TOKEN = {
    "jti": "c6831125-1ed6-41b0-8ea8-e60a341a2787",
    "sub": "425130",
    "scope": [
        "openid",
        "uaa.resource"
    ],
    "client_id": "sb-xssectest",
    "cid": "sb-xssectest",
    "azp": "sb-xssectest",
    "grant_type": "password",
    "user_id": "425130",
    "user_name": "NODETESTUSER",
    "email": "Nodetest@sap.com",
    "origin": "testidp",
    "given_name": "NodetestFirstName",
    "family_name": "NodetestLastName",
    "iat": 1470815434,
    "exp": 2101535434,
    "iss": "http://paas.localhost:8080/uaa/oauth/token",
    "zid": "test-idz",
    "hdb.nameduser.saml": "<?xml version=\"1.0\" encoding=\"UTF-8\"?><saml2:Assertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_71ee1776-9d2f-4973-aca8-9e22b2967ac8\" IssueInstant=\"2016-08-10T07:45:34.347Z\" Version=\"2.0\"><saml2:Issuer>TST-saml</saml2:Issuer><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><ds:Reference URI=\"#_71ee1776-9d2f-4973-aca8-9e22b2967ac8\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>ou8r3R0WBHG1bp4KKOx1PyVOiYA=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>LbRKv1r/h7IMmiSyx10WkM7JuekrmwyVNsB53pkFRnrjCGWtmFkQsknsL7eTUN4+gcJGW0qGTUmvUkfXE1O8rf2CmTcC01cYsGAZWbNpOLNmpP9gG6572pveRqjTXLGSilM2ejJiylq2JnFLhXpgrnTbCvQW6a9JTpRpvMz8SiSodxax7rJw7C0yZzUq862M5yNjdoIHhEkngMcC5LDDhfpf6TkQMsyVcMamDqjTS7WTgvkQKl5pkOPKEuhTjCR7P7KAekeDmYoqs7yEZrrdKEixSY4i5F3weM+dw+A1ue9jF2KmeRvjoxs2hwfsWwUvCxy+2Jhr54vatmweG8dI0Q==</ds:SignatureValue></ds:Signature><saml2:Subject><saml2:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\">NODETESTUSER</saml2:NameID><saml2:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml2:SubjectConfirmationData NotOnOrAfter=\"2016-08-10T11:50:34.347Z\"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore=\"2016-08-10T07:45:34.347Z\" NotOnOrAfter=\"2016-08-10T11:50:34.347Z\"/><saml2:AuthnStatement AuthnInstant=\"2016-08-10T07:50:34.347Z\" SessionNotOnOrAfter=\"2016-08-10T07:55:34.347Z\"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement></saml2:Assertion>",
    "az_attr": {
        "external_group": "domaingroup1",
        "external_id": "abcd1234"
    },
    "ext_attr": {
        "serviceinstanceid": "abcd1234",
        "zdn": "paas"
    },
    "xs.system.attributes": {
        "xs.saml.groups": [
            "Canary_RoleBuilder"
        ],
        "xs.rolecollections": []
    },
    "xs.user.attributes": {
        "country": [
            "USA"
        ]
    },
    "aud": [
        "sb-xssectest",
        "openid"
    ]
}

USER_TOKEN_NO_ATTR = merge(USER_TOKEN, {
    "ext_attr": {
        "zdn": "paas"
    },
    "xs.user.attributes": None
})

USER_TOKEN_NAMES_IN_EXT_ATTR = merge(USER_TOKEN, {
    "ext_attr": {
        "given_name": "NodetestFirstNameExtAttr",
        "family_name": "NodetestLastNameExtAttr"
    }
})

USER_TOKEN_EXPIRED = merge(USER_TOKEN, {
    "exp": 946684800,
})

USER_TOKEN_JWT_BEARER_FOR_CLIENT = merge(USER_TOKEN, {
    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
    "scope": [
        "openid",
    ]
})

USER_SAML_BEARER_TOKEN = merge(USER_TOKEN, {
    "grant_type": "urn:ietf:params:oauth:grant-type:saml2-bearer",
    "scope": [
        "openid"
    ],
    "ext_attr": None
})

USER_APPLICATION_PLAN_TOKEN = merge(USER_TOKEN, {
    "client_id": "sb-xssectest!t4",
    "cid": "sb-xssectest!t4",
    "ext_attr": {},
})

INVALID_TRUSTED_APPLICATION_PLAN_TOKEN = {
    "jti": "a3b643f88e964bcab2f7e996db4b5183",
    "ext_attr": {
        "enhancer": "XSUAA",
        "zdn": "api"
    },
    "sub": "sb-tenant-test!t13",
    "scope": [
        "dox-ui-poc!b7857.Callback"
    ],
    "client_id": "sb-tenant-test!t13",
    "cid": "sb-tenant-test!t13",
    "azp": "sb-tenant-test!t13",
    "grant_type": "client_credentials",
    "rev_sig": "f2a1a9d1",
    "iss": "https://api.cf.test.com/uaa/oauth/token",
    "zid": "api",
    "aud": [
        "dox-ui-poc!b7857",
        "sb-tenant-test!t13"
    ]
}

CLIENT_CREDENTIALS_TOKEN = {
    "jti": "284a265a-8ef5-4b70-925d-ac061273eb21",
    "sub": "sb-xssectest",
    "authorities": [
        "uaa.resource"
    ],
    "scope": [
        "uaa.resource"
    ],
    "client_id": "sb-xssectest",
    "cid": "sb-xssectest",
    "azp": "sb-xssectest",
    "grant_type": "client_credentials",
    "iat": 1470814482,
    "exp": 2101534482,
    "iss": "http://saas.localhost:8080/uaa/oauth/token",
    "zid": "test-idz",
    "aud": [
        "sb-xssectest",
        "uaa"
    ],
    "az_attr": {
        "external_group": "domaingroup1",
        "external_id": "abcd1234"
    },
    "ext_attr": {
        "serviceinstanceid": "abcd1234",
        "zdn": "saas"
    },
    "xs.system.attributes": {
        "xs.saml.groups": [
            "Canary_RoleBuilder"
        ],
        "xs.rolecollections": []
    },
    "xs.user.attributes": {
        "country": [
            "USA"
        ]
    }
}

CLIENT_CREDENTIALS_TOKEN_NO_ATTR = merge(CLIENT_CREDENTIALS_TOKEN, {
    "ext_attr": {},
    "az_attr": None,
    "xs.system.attributes": None,
    "xs.user.attributes": None
})

CLIENT_CREDENTIALS_BROKER_PLAN_TOKEN = merge(CLIENT_CREDENTIALS_TOKEN, {
    "client_id": "sb-xssectestclone!b4|sb-xssectest!b4",
    "cid": "sb-xssectestclone!b4|sb-xssectest!b4",
    "ext_attr": {}
})

CLIENT_CREDENTIALS_TOKEN_ATTR_SUBACCOUNTID = merge(CLIENT_CREDENTIALS_TOKEN, {
    "ext_attr": {
        "serviceinstanceid": "abcd1234",
        "zdn": "saas",
        "subaccountid": "5432",
    },
})

TOKEN_NEW_FORMAT = {
    "jti": "6c0072fd01fb440b86f8a23bf91612b4-r",
    "sub": "b5607c1e-5494-4bf3-8305-de35357e0021",
    "scope": [
        "openid"
    ],
    "ext_attr": {
        "enhancer": "XSUAA",
        "given_name": "michi",
        "family_name": "engler",
        "serviceinstanceid": "reuse-service-paas-lr-clone2-instanceid"
    },
    "ext_cxt": {
        "hdb.nameduser.saml": "<?xml version=\"1.0\" encoding=\"UTF-8\"?><saml2:Assertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_1dc8d7cd-eac8-4a67-bfa4-76ca5ede2e52\" IssueInstant=\"2017-11-16T11:06:40.325Z\" Version=\"2.0\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"><saml2:Issuer>local-idp</saml2:Issuer><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><ds:Reference URI=\"#_1dc8d7cd-eac8-4a67-bfa4-76ca5ede2e52\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"><ec:InclusiveNamespaces xmlns:ec=\"http://www.w3.org/2001/10/xml-exc-c14n#\" PrefixList=\"xs\"/></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>+Y1GYfmqS5JPVIVXQSWBx5++6ec=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>dGlm4QwVGz+NzI9ufKdav6bDoV6BLU+EOEQXZGRbpsr+KyzMjNGcutq3Dcmoh9KOk+wxqE0uWwypQfd1YLV0f2LuQAFo5zNH0uqxsqtkq4YhPNvt0q85vupa/FacyBIjJsKXTnh0OrMS7aDu/j4Tk4J7bk964/B4fzVlanPxBulh/alcA3FnDpAOeSwlr9iTqj22l9LSHuglF7wFhfcZCT+emUbJR9RL9uy4DKzI+pM/q8blPfmirrWWKtiEFsqxgRWFjJTMM9vwFodUlZBnxoQYqRHaW3Nfsnwcl+642lSxMyRAckbYlO2DXL8QsJZxOAXC87Mrkh4ltphtkwYmDA==</ds:SignatureValue></ds:Signature><saml2:Subject><saml2:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\">TestUser</saml2:NameID><saml2:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml2:SubjectConfirmationData NotOnOrAfter=\"2017-11-16T15:11:40.325Z\"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore=\"2017-11-16T11:06:40.325Z\" NotOnOrAfter=\"2017-11-16T15:11:40.325Z\"/><saml2:AttributeStatement><saml2:Attribute Name=\"acr\"><saml2:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name=\"Groups\"><saml2:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">g1</saml2:AttributeValue></saml2:Attribute></saml2:AttributeStatement><saml2:AuthnStatement AuthnInstant=\"2017-11-16T11:11:40.326Z\" SessionNotOnOrAfter=\"2017-11-16T11:16:40.326Z\"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement></saml2:Assertion>",
        "xs.user.attributes": {
            "country": [
                "de"
            ]
        },
        "xs.system.attributes": {
            "xs.saml.groups": [
                "g1"
            ],
            "xs.rolecollections": []
        }
    },
    "iat": 1510830717,
    "exp": 2177366400,
    "cid": "sb-clone2!b1|LR-master!b1",
    "client_id": "sb-clone2!b1|LR-master!b1",
    "iss": "http://paas.localhost:8080/uaa/oauth/token",
    "zid": "paas",
    "revocable": True,
    "grant_type": "user_token",
    "user_name": "TestUser",
    "origin": "useridp",
    "user_id": "b5607c1e-5494-4bf3-8305-de35357e0021",
    "rev_sig": "f2b8ade8",
    "aud": []
}

TOKEN_XSA_FORMAT = {
    "sub": "HDB00",
    "name": "SYSTEM",
    "cid": "sb-xssectest",
    "zid": "uaa",
    "admin": True,
    "authorities": [
        "uaa.resource"
    ],
    "scope": [
        "uaa.user",
        "openid",
        "uaa.resource"
    ],
    "user_name": "ADMIN"
}
