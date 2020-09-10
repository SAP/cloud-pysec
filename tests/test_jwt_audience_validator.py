import unittest
try:
    from unittest.mock import MagicMock, patch
except ImportError:
    from mock import MagicMock, patch


from sap.xssec.jwt_audience_validator import JwtAudienceValidator


class TestJwtAudienceValidator:

    XSUAA_BROKER_XSAPPNAME = "brokerplanmasterapp!b123"

    def test_constructor(self):
        self.jwt_audience_validator = JwtAudienceValidator(clientid="client")
        assert (self.jwt_audience_validator.trusted_clientids).__len__() == 1


    def test_tokenaudience_matches_clientid(self):
        clientid_from_token = "clientid1"
        self.jwt_audience_validator = JwtAudienceValidator(clientid_from_token)
        validation_result = self.jwt_audience_validator.validate_token(clientId_from_token=clientid_from_token)
        assert  validation_result == True

    def test_tokenaudience_matches_appId(self):
        audiences_from_token=["appId!t1"]
        self.jwt_audience_validator = JwtAudienceValidator("sb-appId!t1")
        self.jwt_audience_validator.configure_trusted_clientId('appId!t1')
        validation_result = self.jwt_audience_validator.validate_token(audiences_from_token=audiences_from_token)
        assert validation_result == True

    def test_token_audience_matches_foreign_clientId(self):
        audiences_from_token = ["client", "foreignclient", "sb-test4!t1.data"]
        self.jwt_audience_validator = JwtAudienceValidator("any")
        self.jwt_audience_validator.configure_trusted_clientId('foreignclient')
        validation_result = self.jwt_audience_validator.validate_token(audiences_from_token=audiences_from_token)
        assert validation_result == True

    def test_clientid_matches_token_audience_without_dot(self):
        audiences_from_token = ["client", "sb-test4!t1.data.x"]
        self.jwt_audience_validator = JwtAudienceValidator("sb-test4!t1")
        validation_result = self.jwt_audience_validator.validate_token(audiences_from_token=audiences_from_token)
        assert validation_result == True

    def test_token_client_id_matches_trusted_clientid(self):
        self.jwt_audience_validator = JwtAudienceValidator("client")
        validation_result = self.jwt_audience_validator.validate_token(clientId_from_token="client")
        assert validation_result == True

    def test_broker_clientid_matches_clone_audience(self):
        audiences_from_token = ["sb-f7016e93-8665-4b73-9b46-f99d7808fe3c!b446|" + self.XSUAA_BROKER_XSAPPNAME]
        self.jwt_audience_validator = JwtAudienceValidator("sb-" + self.XSUAA_BROKER_XSAPPNAME)
        self.jwt_audience_validator.configure_trusted_clientId(self.XSUAA_BROKER_XSAPPNAME)
        validation_result = self.jwt_audience_validator.validate_token(audiences_from_token=audiences_from_token)
        assert validation_result == True

    def test_token_clientid_matches_trusted_broker_client_id(self):
        clientid_from_token = "sb-clone-app-id!b123|" + self.XSUAA_BROKER_XSAPPNAME
        self.jwt_audience_validator = JwtAudienceValidator(self.XSUAA_BROKER_XSAPPNAME)
        validation_result = self.jwt_audience_validator.validate_token(clientId_from_token= clientid_from_token)
        assert validation_result == True

    def test_token_clientid_does_not_match_trusted_broker_clientid(self):
        clientid_from_token = "sb-clone-app-id!b123|xxx" + self.XSUAA_BROKER_XSAPPNAME
        self.jwt_audience_validator = JwtAudienceValidator(self.XSUAA_BROKER_XSAPPNAME)
        validation_result = self.jwt_audience_validator.validate_token(clientId_from_token=clientid_from_token)
        assert validation_result == False

    def test_broker_clientid_does_not_match_clone_audience(self):
        audiencesfromToken = ["sb-f7016e93-8665-4b73-9b46-f99d7808fe3c!b446|ANOTHERAPP!b12"]
        self.jwt_audience_validator = JwtAudienceValidator("sb-" + self.XSUAA_BROKER_XSAPPNAME)
        self.jwt_audience_validator.configure_trusted_clientId(self.XSUAA_BROKER_XSAPPNAME)
        validation_result = self.jwt_audience_validator.validate_token(audiences_from_token=audiencesfromToken)
        assert validation_result == False

    def test_negative_when_no_token_audience_matches(self):
        audiences_from_token = ["client", "foreignclient", "sb-test4!t1.data"]
        self.jwt_audience_validator = JwtAudienceValidator("any")
        self.jwt_audience_validator.configure_trusted_clientId("anyOther")
        validation_result = self.jwt_audience_validator.validate_token(audiences_from_token=audiences_from_token)
        assert validation_result == False

    def test_should_filter_empty_audiences(self):
        audiences_from_token = [".", "test.", " .test2"]
        self.jwt_audience_validator = JwtAudienceValidator("any")
        validation_result = self.jwt_audience_validator.validate_token(audiences_from_token=audiences_from_token)
        assert validation_result == False

    def test_negative_fails_when_token_audiences_are_empty(self):
        self.jwt_audience_validator = JwtAudienceValidator("any")
        validation_result = self.jwt_audience_validator.validate_token()
        assert validation_result == False

    def test_extract_audiences_from_token_scopes(self):
        scopes = ["client.read", "test1!t1.read", "client.write", "xsappid.namespace.ns.write", "openid"]
        self.jwt_audience_validator = JwtAudienceValidator("client")
        audiences_result = self.jwt_audience_validator.extract_audiences_from_token(scopes_from_token=scopes)
        assert len(audiences_result) == 3
        assert 'client' in audiences_result
        assert 'xsappid' in audiences_result
        assert 'test1!t1' in audiences_result
