""" xssec """
from enum import Enum
from typing import Dict

from sap.xssec.security_context_ias import SecurityContextIAS
from sap.xssec.security_context_xsuaa import SecurityContextXSUAA


class SecurityContextType(Enum):
    XSUAA = 1
    IAS = 2


def create_security_context(token, service_credentials: Dict[str, str],
                            type: SecurityContextType = SecurityContextType.XSUAA):
    """
    Creates the Security Context by validating the received access token.

    :param token: string containing the access_token
    :param service_credentials: dict containing the uaa/ias credentials
    :param type: xsuaa or ias
    :return: SecurityContext object
    """
    return SecurityContextXSUAA(token, service_credentials) if type == SecurityContextType.XSUAA \
        else SecurityContextIAS(token, service_credentials)
