""" Security Context class for IAS support"""
import logging
from typing import List, Dict
from urllib3.util import Url, parse_url  # type: ignore
from sap.xssec.jwt_audience_validator import JwtAudienceValidator
from sap.xssec.jwt_validation_facade import JwtValidationFacade, DecodeError
from sap.xssec.key_cache import KeyCache
from sap.xssec.key_cache_v2 import get_verification_key_ias


class SecurityContextIAS(object):
    """ SecurityContextIAS class """

    verificationKeyCache = KeyCache()

    def __init__(self, token: str, service_credentials: Dict[str, str]):
        self.token = token
        self.service_credentials = service_credentials
        self.logger = logging.getLogger(__name__)
        self.jwt_validator = JwtValidationFacade()
        self.audience_validator = JwtAudienceValidator(self.service_credentials["clientid"])
        try:
            self.token_payload = self.jwt_validator.decode(token, False)
            self.token_header = self.jwt_validator.get_unverified_header(token)
            self.validate_issuer().validate_timestamp().validate_audience().validate_signature()
        except DecodeError:
            raise ValueError("Failed to decode provided token")

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

    def validate_timestamp(self):
        """
        check `exp` in jwt token
        """
        if self.jwt_validator.has_token_expired(self.token):
            raise ValueError("Token has expired")
        return self

    def validate_audience(self):
        """
        check `aud` in jwt token
        """
        validation_result = self.audience_validator.validate_token(audiences_from_token=self.token_payload["aud"])
        if validation_result is False:
            raise RuntimeError('Audience Validation Failed')
        return self

    def validate_signature(self):
        """
        check signature in jwt token
        """
        verification_key: str = get_verification_key_ias(
            self.get_issuer(), self.token_payload.get("zone_uuid"), self.token_header["kid"])

        result_code = self.jwt_validator.loadPEM(verification_key)
        if result_code != 0:
            raise RuntimeError('Invalid verification key, result code {0}'.format(result_code))

        self.jwt_validator.checkToken(self.token)
        error_description = self.jwt_validator.getErrorDescription()
        if error_description != '':
            raise RuntimeError(
                'Error in validation of access token: {0}, result code {1}'.format(
                    error_description, self.jwt_validator.getErrorRC()))

        return self
