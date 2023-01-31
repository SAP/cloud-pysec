# pylint: disable=missing-docstring,invalid-name,missing-docstring,too-many-public-methods
import unittest
from os import environ
from parameterized import parameterized_class
from sap import xssec
from sap.xssec import jwt_validation_facade, security_context_ias
from tests.ias import ias_configs
from tests.ias.ias_configs import SERVICE_CREDENTIALS
from tests.ias.ias_tokens import TOKEN_INVALID_ISSUER, VALID_TOKEN, TOKEN_INVALID_AUDIENCE, TOKEN_EXPIRED, PAYLOAD, \
    HEADER
from tests.keys import JWT_SIGNING_PUBLIC_KEY

try:
    from importlib import reload
    from unittest.mock import MagicMock, patch
except ImportError:
    reload = None
    from mock import MagicMock, patch


class IASXSSECTest(unittest.TestCase):

    def setUp(self):
        reload(jwt_validation_facade)
        reload(security_context_ias)

    @patch('sap.xssec.security_context_ias.get_verification_key_ias', return_value=JWT_SIGNING_PUBLIC_KEY)
    def test_input_validation_valid_token(self, get_verification_key_ias_mock):
        xssec.create_security_context_ias(VALID_TOKEN, ias_configs.SERVICE_CREDENTIALS)
        get_verification_key_ias_mock.assert_called_with(PAYLOAD["iss"], PAYLOAD["zone_uuid"], HEADER["kid"])

    def test_input_validation_invalid_token(self):
        with self.assertRaises(ValueError) as ctx:
            xssec.create_security_context_ias("some-invalid-token", ias_configs.SERVICE_CREDENTIALS)
        self.assertEqual("Failed to decode provided token", str(ctx.exception))

    def test_input_validation_invalid_issuer(self):
        with self.assertRaises(ValueError) as ctx:
            xssec.create_security_context_ias(TOKEN_INVALID_ISSUER, ias_configs.SERVICE_CREDENTIALS)
        self.assertEqual("Token's issuer is not found in domain list " + SERVICE_CREDENTIALS["domain"],
                         str(ctx.exception))

    def test_input_validation_token_expired(self):
        with self.assertRaises(ValueError) as ctx:
            xssec.create_security_context_ias(TOKEN_EXPIRED, ias_configs.SERVICE_CREDENTIALS)
        self.assertEqual("Token has expired", str(ctx.exception))

    def test_input_validation_invalid_audience(self):
        with self.assertRaises(RuntimeError) as ctx:
            xssec.create_security_context_ias(TOKEN_INVALID_AUDIENCE, ias_configs.SERVICE_CREDENTIALS)
        self.assertEqual("Audience Validation Failed", str(ctx.exception))
