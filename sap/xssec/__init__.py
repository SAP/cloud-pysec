""" xssec """

from sap.xssec.security_context import SecurityContext

def create_security_context(token, uaa_service):
    """
    Creates the Security Context by validating the received access token.

    :param token: string containing the access_token
    :param uaa_service: dict containing the uaa credentials
    :return: SecurityContext object
    """
    return SecurityContext(token, uaa_service)
