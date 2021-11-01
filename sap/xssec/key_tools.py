
import base64
import struct

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


def jwk_to_pem(jwk) -> str:
    """
        source: https://github.com/jpf/okta-jwks-to-pem/blob/master/jwks_to_pem.py
    """
    if jwk["kty"] != "RSA":
        raise ValueError("KTY {} not supported".format(jwk["kty"]))

    def intarr2long(arr):
        return int(''.join(["%02x" % byte for byte in arr]), 16)

    def base64_to_long(data_str: str):
        data = data_str.encode("ascii")
        _d = base64.urlsafe_b64decode(bytes(data) + b'==')
        return intarr2long(struct.unpack('%sB' % len(_d), _d))

    exponent = base64_to_long(jwk['e'])
    modulus = base64_to_long(jwk['n'])
    numbers = RSAPublicNumbers(exponent, modulus)
    public_key = numbers.public_key(backend=default_backend())
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return pem
