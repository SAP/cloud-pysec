import json

from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from jwt.algorithms import RSAAlgorithm


def jwk_to_pem(jwk) -> str:
    pubkey = RSAAlgorithm.from_jwk(json.dumps(jwk))
    pem = pubkey.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    return pem
