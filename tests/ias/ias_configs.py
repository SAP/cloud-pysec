SERVICE_CREDENTIALS = {
    "clientid": "clientid",
    "clientsecret": "SECRET",
    "domain": "accounts400.ondemand.com",
    "url": "https://tenant.accounts400.ondemand.com",
    "zone_uuid": "1c3bc4e1-0d22-4497-b7bb-06c5f1494d79"
}

WELL_KNOWN = {
    "issuer": "https://tenant.accounts400.ondemand.com",
    "authorization_endpoint": "https://tenant.accounts400.ondemand.com/oauth2/authorize",
    "token_endpoint": "https://tenant.accounts400.ondemand.com/oauth2/token",
    "end_session_endpoint": "https://tenant.accounts400.ondemand.com/oauth2/logout",
    "jwks_uri": "https://tenant.accounts400.ondemand.com/oauth2/certs",
    "response_types_supported": ["code", "id_token", "token"],
    "grant_types_supported": ["password", "authorization_code", "refresh_token", "client_credentials"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
    "scopes_supported": ["openid", "email"],
    "token_endpoint_auth_methods_supported": ["tls_client_auth_subject_dn", "client_secret_basic"],
    "code_challenge_methods_supported": ["plain", "S256"],
    "tls_client_certificate_bound_access_tokens": True
}

JWKS = {
    "keys": [{
        "kty": "RSA",
        "e": "AQAB",
        "use": "sig",
        "kid": "kid-custom",
        "alg": "RS256",
        "value": "public key here",
        "n": "AMGmSCHT8kourWCKVwTQKKr7a_rs8AGiwVPmeycKq2Mja5P3YXMDMOO7Qb9"
             "-v5YNv0dkD7eu9v4AzilpcnnGASQbewNbaz2wJWMwIvjxG7VcHjqcf-oF9bfHv8nR1TTp52OwSKaKqunMtIrS1uJ"
             "-1opcRmlX1x8zgi2l-XxzSKrLABz0Fq2GJGZmD1PU_"
             "-W6FHzE7ocokfYSViJ1_mBGn5KJwUIC2vBO9jWquGlM9TkdPP5DpmONEO5yFu6aO6GeEF3k9hOEL0AS0GOm8KmywhDg"
             "-s5FGVNuwNG0O_nQn3VI9jigXuKuz5_e1becT2rw88fpizFG476TwB6BQCk8SWc "
    }]
}