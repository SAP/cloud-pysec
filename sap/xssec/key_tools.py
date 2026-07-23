import json

from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from jwt.algorithms import ECAlgorithm, RSAAlgorithm


def jwk_to_pem(jwk) -> str:
    jwk = {k: v.strip() if isinstance(v, str) else v for k, v in jwk.items()}
    if jwk.get("kty") == "EC":
        pubkey = ECAlgorithm.from_jwk(json.dumps(jwk))
    else:
        pubkey = RSAAlgorithm.from_jwk(json.dumps(jwk))
    pem = pubkey.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    return pem
