import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from sap.xssec.jwt_validation_facade import JwtValidationFacade
from sap.xssec.key_tools import jwk_to_pem

RSA_ALGS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"]
EC_ALGS = ["ES256", "ES384", "ES512"]
ALL_ALGS = RSA_ALGS + EC_ALGS

_EC_CURVE_BY_ALG = {
    "ES256": ec.SECP256R1(),
    "ES384": ec.SECP384R1(),
    "ES512": ec.SECP521R1(),
}


def _keypair(alg):
    if alg in EC_ALGS:
        return ec.generate_private_key(_EC_CURVE_BY_ALG[alg])
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _public_jwk(alg, private_key):
    algorithm = ECAlgorithm(ECAlgorithm.SHA256) if alg in EC_ALGS \
        else RSAAlgorithm(RSAAlgorithm.SHA256)
    return json.loads(algorithm.to_jwk(private_key.public_key()))


def _validate(alg, token, jwk):
    facade = JwtValidationFacade()
    facade.loadPEM(jwk_to_pem(jwk))
    facade.checkToken(token)
    return facade.getErrorRC()


@pytest.mark.parametrize("alg", ALL_ALGS)
def test_supports_alg(alg):
    import jwt
    key = _keypair(alg)
    token = jwt.encode({"foo": "bar"}, key, algorithm=alg)
    jwk = _public_jwk(alg, key)
    assert _validate(alg, token, jwk) == 0


@pytest.mark.parametrize("alg", ALL_ALGS)
def test_detects_tampered_signature(alg):
    import jwt
    key = _keypair(alg)
    good = jwt.encode({"foo": "bar"}, key, algorithm=alg)
    other = jwt.encode({"foo": "baz"}, key, algorithm=alg)
    tampered = good.rsplit(".", 1)[0] + "." + other.rsplit(".", 1)[1]
    jwk = _public_jwk(alg, key)
    assert _validate(alg, tampered, jwk) == 1
