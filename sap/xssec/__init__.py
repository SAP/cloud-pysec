""" xssec """
from typing import Dict

from sap.xssec.security_context_ias import SecurityContextIAS
from sap.xssec.security_context_xsuaa import SecurityContextXSUAA


def create_security_context_xsuaa(token, service_credentials: Dict[str, str]):
    """
    Creates the XSUAA Security Context by validating the received access token.

    :param token: string containing the access_token
    :param service_credentials: dict containing the uaa/ias credentials
    :return: SecurityContextXSUAA object
    """
    return SecurityContextXSUAA(token, service_credentials)


def create_security_context_ias(token, service_credentials: Dict[str, str]):
    """
    Creates the IAS Security Context by validating the received access token.

    :param token: string containing the access_token
    :param service_credentials: dict containing the uaa/ias credentials
    :return: SecurityContextIAS object
    """
    return SecurityContextIAS(token, service_credentials)


create_security_context = create_security_context_xsuaa
