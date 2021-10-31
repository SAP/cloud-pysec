
import base64
import struct

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


def jwk_to_pem(jwk) -> bytes:
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
    )
    return pem

keys = [
    {
      "kty": "RSA",
      "e": "AQAB",
      "use": "sig",
      "kid": "default-jwt-key--586369860",
      "alg": "RS256",
      "value": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Kf15lt1n8l2MTPzWOdI\nx+snwGVa3IS8gXhl0EyakF4UhumzIDAZPQRysHxMsjYB7MW0ir4HntKuxKrixuDN\n/0qm+PPDoPYUDUlrPUwfvcg7N5auPGa8Is4Zmv4mHL2j3l0lt+y+vNJJzEe70RKY\n4/+XgnhaIQxYMzfFMFb2B8WSglU7Zak2yv+ZeGjaHWLiIndbW48fqTnvUO5pq0tW\n4LQLVMUO6VFmph8wtkAHUYMtoc+pWCweZIt5+AciQboVBCLyyAh5BlBFzM59XMjD\nTCG6iXY6nirvNxo+LUbafHx6yK3Ca0hi60eseAV0E4mxjAkA1PYlW1pZjAuVCzYR\nYQIDAQAB\n-----END PUBLIC KEY-----",
      "n": "ANCn9eZbdZ_JdjEz81jnSMfrJ8BlWtyEvIF4ZdBMmpBeFIbpsyAwGT0EcrB8TLI2AezFtIq-B57SrsSq4sbgzf9Kpvjzw6D2FA1Jaz1MH73IOzeWrjxmvCLOGZr-Jhy9o95dJbfsvrzSScxHu9ESmOP_l4J4WiEMWDM3xTBW9gfFkoJVO2WpNsr_mXho2h1i4iJ3W1uPH6k571DuaatLVuC0C1TFDulRZqYfMLZAB1GDLaHPqVgsHmSLefgHIkG6FQQi8sgIeQZQRczOfVzIw0whuol2Op4q7zcaPi1G2nx8esitwmtIYutHrHgFdBOJsYwJANT2JVtaWYwLlQs2EWE"
    }
  ]

print(jwk_to_pem(keys[0]))