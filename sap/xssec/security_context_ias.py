""" Security Context class for IAS support"""
import logging
from typing import List, Any, Dict

import jwt
from urllib3.util import Url, parse_url  # type: ignore
from sap.xssec.jwt_audience_validator import JwtAudienceValidator
from sap.xssec.key_cache import KeyCache
from sap.xssec.key_cache_v2 import get_verification_key_ias


class SecurityContextIAS(object):
    """ SecurityContextIAS class """

    verificationKeyCache = KeyCache()

    def __init__(self, token: str, service_credentials: Dict[str, Any]):
        self.token = token
        self.service_credentials = service_credentials
        self.token_payload = jwt.decode(token, options={"verify_signature": False})
        self.token_header = jwt.get_unverified_header(token)
        self.logger = logging.getLogger(__name__)
        self.validate_issuer().validate_audience().validate_timestamp_and_signature()

    def get_issuer(self):
        return self.token_payload.get("ias_iss") or self.token_payload["iss"]

    def validate_issuer(self):
        """
        check `ias_iss` or `iss` in jwt token
        """
        issuer_url: Url = parse_url(self.get_issuer())
        if issuer_url.scheme != "https":
            raise ValueError("Token's issuer has wrong protocol ({})".format(issuer_url.scheme))

        if issuer_url.query is not None:
            raise ValueError("Token's issuer has unallowed query value ({})".format(issuer_url.query))

        if issuer_url.fragment is not None:
            raise ValueError("Token's issuer has unallowed hash value ({})".format(issuer_url.fragment))

        domains: List[str] = self.service_credentials.get("domains") or (
            [self.service_credentials["domain"]] if "domain" in self.service_credentials else [])
        if not any(map(lambda d: issuer_url.host.endswith(d), domains)):
            raise ValueError("Token's issuer is not found in domain list {}".format(", ".join(domains)))

        return self

    def validate_audience(self):
        """
        check `aud` in jwt token
        """
        audience_validator = JwtAudienceValidator(self.service_credentials["clientid"])
        validation_result = audience_validator.validate_token(self.token_payload["clientid"], self.token_payload["aud"])
        if validation_result is False:
            raise RuntimeError('Audience Validation Failed')
        return self

    def validate_timestamp_and_signature(self):
        """
        check `exp` and signature in jwt token
        """
        rs256 = "RS256"
        if self.token_header["alg"] != rs256:
            raise ValueError("alg {} not supported".format(self.token_header["alg"]))

        verification_key: bytes = get_verification_key_ias(
            self.get_issuer(), self.token_payload.get("zone_uuid"), self.token_header["kid"])
        jwt.decode(self.token, verification_key, algorithms=[rs256], options={"verify_exp": True})
        return self
