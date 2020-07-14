import unittest

from xssec.jwt_audience_validator import JwtAudienceValidator


class TestJwtAudienceValidator:

    def test_constructor(self):
        jwt_audience_validator = JwtAudienceValidator(clientId="ABC")
        assert (jwt_audience_validator.clientIds).__len__() == 1
