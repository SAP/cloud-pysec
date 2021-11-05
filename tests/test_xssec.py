# pylint: disable=missing-docstring,invalid-name,missing-docstring,too-many-public-methods
from ssl import SSLError
import unittest
import json
from os import environ
from datetime import datetime
from parameterized import parameterized_class
from sap import xssec
from sap.xssec import constants, jwt_validation_facade, security_context_xsuaa
from sap.conf import config
from tests import uaa_configs
from tests import jwt_payloads
from tests.http_responses import HTTP_SUCCESS
from tests.jwt_tools import sign


try:
    from importlib import reload
    from unittest.mock import MagicMock, patch
except ImportError:
    reload = None
    from mock import MagicMock, patch

# test with sap-jwt if installed
TEST_PARAMETERS = [(False,), (True,)]
CONFIG_ERROR_MSG = 'Either clientid,clientsecret,url or clientid,certificate,certurl should be provided'


@parameterized_class(('USE_SAP_PY_JWT',), TEST_PARAMETERS)
class XSSECTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        ''' Test class static setup '''
        environ['SAP_EXT_JWT_ALG'] = '*'

    def setUp(self):
        if 'SAP_JWT_TRUST_ACL' in environ:
            del environ['SAP_JWT_TRUST_ACL']

        config.USE_SAP_PY_JWT = self.USE_SAP_PY_JWT
        # reloads needed to propagate changes to USE_SAP_PY_JWT
        reload(jwt_validation_facade)
        reload(security_context_xsuaa)
        jwt_validation_facade.ALGORITHMS = ['RS256', 'HS256']

        patcher = patch('httpx.get')
        self.mock_httpx_get = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_httpx_get.side_effect = SSLError

    def _check_invalid_params(self, token, uaa, message):
        with self.assertRaises(ValueError) as ctx:
            xssec.create_security_context(token, uaa)
        self.assertEqual(message, str(ctx.exception))

    def test_input_validation_none_token(self):
        ''' input validation: None token '''
        self._check_invalid_params(
            None, uaa_configs.VALID['uaa'], '"token" should not be None')

    def test_input_validation_empty_token(self):
        ''' input validation: empty token '''
        self._check_invalid_params(
            '', uaa_configs.VALID['uaa'], '"token" should not be an empty string')

    def test_input_validation_invalid_token(self):
        ''' input validation: invalid token '''
        with self.assertRaises(ValueError) as ctx:
            xssec.create_security_context('invalid', uaa_configs.VALID['uaa'])
        self.assertEqual(
            'Failed to decode provided token',
            str(ctx.exception))

    def test_input_validation_none_config(self):
        ''' input validation: None config '''
        self._check_invalid_params(
            'valid', None, '"config" should not be None')

    def test_input_validation_invalid_config_url(self):
        ''' input validation: invalid config url '''
        self._check_invalid_params(
            'valid', uaa_configs.INVALID['uaa_url_undefined'], CONFIG_ERROR_MSG)

    def test_input_validation_invalid_config_clientid(self):
        ''' input validation: invalid config clientid '''
        self._check_invalid_params(
            'valid',
            uaa_configs.INVALID['uaa_clientid_undefined'],
            CONFIG_ERROR_MSG)

    def test_input_validation_invalid_config_clientsecretand_and_certificate(self):
        ''' input validation: invalid config clientsecret '''
        self._check_invalid_params(
            'valid',
            uaa_configs.INVALID['uaa_clientsecret_and_certificate_undefined'],
            CONFIG_ERROR_MSG)

    def test_input_validation_invalid_config_xsappname(self):
        ''' input validation: invalid config xsappname '''
        self._check_invalid_params(
            'valid',
            uaa_configs.INVALID['uaa_xsappname_undefined'],
            'Invalid config: Missing xsappname.'
            ' The application name needs to be defined in xs-security.json.')

    def _check_user_info(self, sec_context):
        self.assertEqual(sec_context.get_logon_name(), 'NODETESTUSER')
        self.assertEqual(sec_context.get_given_name(), 'NodetestFirstName')
        self.assertEqual(sec_context.get_family_name(), 'NodetestLastName')
        self.assertEqual(sec_context.get_email(), 'Nodetest@sap.com')

    def _check_hdb_token(self, sec_context):
        hdb_token = sec_context.get_hdb_token()
        self.assertIsNotNone(hdb_token)
        system_hdb_token = sec_context.get_token(
            xssec.constants.SYSTEM, xssec.constants.HDB)
        self.assertEqual(system_hdb_token, hdb_token)

    def _check_app_token(self, sec_context):
        app_token = sec_context.get_app_token()
        self.assertIsNotNone(app_token)
        system_app_token = sec_context.get_token(
            xssec.constants.SYSTEM, xssec.constants.JOBSCHEDULER)
        self.assertEqual(system_app_token, app_token)

    def _check_user_token(self, sec_context):
        self.assertTrue(sec_context.check_scope('openid'))
        self.assertTrue(sec_context.check_scope('$XSAPPNAME.resource'))
        self.assertFalse(sec_context.check_scope(
            'cloud_controller.nonexistingscope'))
        self.assertTrue(sec_context.check_local_scope('resource'))
        self.assertFalse(sec_context.check_local_scope('nonexistingscope'))
        self._check_user_info(sec_context)
        self._check_hdb_token(sec_context)
        self.assertIsNone(sec_context.get_attribute('hugo'))
        self.assertIsNone(sec_context.get_additional_auth_attribute('hugo'))
        self.assertEqual(sec_context.get_grant_type(),
                         xssec.constants.GRANTTYPE_PASSWORD)
        self.assertEqual(sec_context.get_identity_zone(), 'test-idz')
        self.assertEqual(sec_context.get_zone_id(), 'test-idz')
        self.assertEqual(sec_context.get_subaccount_id(), 'test-idz')
        self.assertEqual(sec_context.get_origin(), 'testidp')
        self.assertEqual(sec_context.get_subdomain(), 'paas')
        self.assertFalse(sec_context.is_in_foreign_mode())
        self.assertEqual(sec_context.get_expiration_date(),
                         datetime.utcfromtimestamp(2101535434))

    def test_valid_end_user_token_with_attr(self):
        ''' Test valid end-user token with attributes '''
        sec_context = xssec.create_security_context(
            sign(jwt_payloads.USER_TOKEN), uaa_configs.VALID['uaa'])
        self._check_user_token(sec_context)
        self.assertTrue(sec_context.has_attributes())
        self.assertEqual(sec_context.get_attribute('country'), ['USA'])
        self.assertEqual(
            sec_context.get_clone_service_instance_id(), 'abcd1234')
        self.assertEqual(
            sec_context.get_additional_auth_attribute('external_group'), 'domaingroup1')

    def test_valid_end_user_token_no_attr(self):
        ''' Test valid end-user token no attributes '''
        sec_context = xssec.create_security_context(
            sign(jwt_payloads.USER_TOKEN_NO_ATTR), uaa_configs.VALID['uaa'])
        self._check_user_token(sec_context)
        self.assertFalse(sec_context.has_attributes())
        self.assertIsNone(sec_context.get_clone_service_instance_id())

    def test_valid_end_user_token_with_ext_attr(self):
        ''' Test valid end-user token (given_name/family_name in ext_attr) '''
        sec_context = xssec.create_security_context(
            sign(jwt_payloads.USER_TOKEN_NAMES_IN_EXT_ATTR), uaa_configs.VALID['uaa'])
        self.assertEqual(
            sec_context.get_given_name(), 'NodetestFirstNameExtAttr')
        self.assertEqual(
            sec_context.get_family_name(), 'NodetestLastNameExtAttr')

    def test_expired_end_user_token(self):
        ''' Test expired end-user token '''
        with self.assertRaises(RuntimeError) as ctx:
            xssec.create_security_context(
                sign(jwt_payloads.USER_TOKEN_EXPIRED), uaa_configs.VALID['uaa'])
        self.assertTrue(
            'Error in offline validation of access token:' in str(ctx.exception) and
            'expired' in str(ctx.exception)
        )

    def test_invalid_signature_end_user_token(self):
        ''' Test invalid signature end-user token '''
        token_parts = sign(jwt_payloads.USER_TOKEN).split('.')
        token_parts[2] = 'aW52YWxpZAo'
        invalid_token = '.'.join(token_parts)
        with self.assertRaises(RuntimeError) as ctx:
            xssec.create_security_context(
                invalid_token, uaa_configs.VALID['uaa'])
        self.assertTrue(
            'Error in offline validation of access token:' in str(ctx.exception))

    # def test_valid_end_user_token_in_foreign_mode_idz(self):
    #     ''' valid end-user token in foreign mode (idz - correct SAP_JWT_TRUST_ACL) '''
    #     environ['SAP_JWT_TRUST_ACL'] = '[{"clientid":"sb-xssectest","identityzone":"test-idz"}]'
    #     sec_context = xssec.create_security_context(
    #         sign(jwt_payloads.USER_TOKEN), uaa_configs.VALID['uaa_foreign_idz'])
    #     self.assertTrue(sec_context.is_in_foreign_mode())
    #     self.assertEqual(
    #         sec_context.get_additional_auth_attribute('external_group'), 'domaingroup1')
    #     self.assertIsNone(sec_context.get_additional_auth_attribute('hugo'))
    #     self.assertIsNone(sec_context.get_hdb_token())
    #     self.assertIsNotNone(sec_context.get_app_token())

    def _check_token_in_foreign_mode(self, cid, idz, uaa_config_name):
        environ['SAP_JWT_TRUST_ACL'] = json.dumps([{
            'clientid': 'other-clientid',
            'identityzone': 'other-idz'
        },
        {
            'clientid': cid,
            'identityzone': idz
        }])
        sec_context = xssec.create_security_context(
            sign(jwt_payloads.USER_TOKEN_NO_ATTR), uaa_configs.VALID[uaa_config_name])
        self.assertTrue(sec_context.is_in_foreign_mode())
        self.assertIsNotNone(sec_context.get_hdb_token())
        self.assertIsNotNone(sec_context.get_app_token())

    # TBD :After foriegn mode decision is made
    # def test_valid_end_user_token_in_foreign_mode_clientid(self):
    #     ''' valid end-user token in foreign mode (clientid - correct SAP_JWT_TRUST_ACL) '''
    #     self._check_token_in_foreign_mode(
    #         'sb-xssectest', 'test-idz', 'uaa_foreign_clientid')

    # TBD :After foriegn mode decision is made
    # def test_valid_end_user_token_in_foreign_mode_idz_and_clientid(self):
    #     ''' valid end-user token in foreign mode (idz & clientid - correct SAP_JWT_TRUST_ACL) '''
    #     self._check_token_in_foreign_mode(
    #         'sb-xssectest', 'test-idz', 'uaa_foreign_idz_clientid')

    # TBD :After foriegn mode decision is made
    # def test_valid_end_user_token_in_foreign_mode_idz_and_clientid_with_star(self):
    #     ''' valid end-user token in foreign mode (idz & clientid in SAP_JWT_TRUST_ACL with *) '''
    #     self._check_token_in_foreign_mode('*', '*', 'uaa_foreign_idz_clientid')

    def _check_token_in_foreign_mode_error(self, cid, idz, uaa_config_name):
        environ['SAP_JWT_TRUST_ACL'] = json.dumps([{
            'clientid': cid,
            'identityzone': idz
        }])
        with self.assertRaises(RuntimeError) as ctx:
            xssec.create_security_context(
                sign(jwt_payloads.USER_TOKEN_NO_ATTR), uaa_configs.VALID[uaa_config_name])
        self.assertTrue(str(ctx.exception).startswith(
            'No match found in JWT trust ACL (SAP_JWT_TRUST_ACL)'))

    # def test_valid_end_user_token_in_foreign_mode_invalid_idz(self):
    #     ''' valid end-user token in foreign mode (idz - incorrect SAP_JWT_TRUST_ACL) '''
    #     self._check_token_in_foreign_mode_error(
    #         'sb-xssectest', 'uaa', 'uaa_foreign_idz')

    # def test_valid_end_user_token_in_foreign_mode_invalid_clientid(self):
    #     ''' valid end-user token in foreign mode (clientid - incorrect SAP_JWT_TRUST_ACL) '''
    #     self._check_token_in_foreign_mode_error(
    #         'foreign-clientid', 'test-idz', 'uaa_foreign_clientid')

    def test_valid_end_user_saml_bearer_token(self):
        ''' valid end-user saml bearer token '''
        sec_context = xssec.create_security_context(
            sign(jwt_payloads.USER_SAML_BEARER_TOKEN), uaa_configs.VALID['uaa_bearer'])
        self.assertTrue(sec_context.check_scope('openid'))
        self._check_user_info(sec_context)
        self._check_hdb_token(sec_context)
        self.assertEqual(sec_context.get_grant_type(),
                         xssec.constants.GRANTTYPE_SAML2BEARER)
        self.assertEqual(sec_context.get_identity_zone(), 'test-idz')
        self.assertEqual(sec_context.get_zone_id(), 'test-idz')
        self.assertEqual(sec_context.get_subaccount_id(), 'test-idz')
        self.assertIsNone(sec_context.get_subdomain())
        self.assertFalse(sec_context.is_in_foreign_mode())

    def test_valid_end_user_application_plan_token(self):
        ''' valid end-user application plan token '''
        sec_context = xssec.create_security_context(
            sign(jwt_payloads.USER_APPLICATION_PLAN_TOKEN),
            uaa_configs.VALID['uaa_application_plan'])

        self.assertTrue(sec_context.check_scope('openid'))
        self.assertTrue(sec_context.check_scope('$XSAPPNAME.resource'))
        self.assertFalse(sec_context.check_scope(
            'cloud_controller.nonexistingscope'))
        self.assertTrue(sec_context.check_local_scope('resource'))
        self.assertFalse(sec_context.check_local_scope('nonexistingscope'))
        self._check_user_info(sec_context)
        self._check_hdb_token(sec_context)
        self.assertIsNone(sec_context.get_attribute('hugo'))
        self.assertIsNone(sec_context.get_additional_auth_attribute('hugo'))
        self.assertEqual(sec_context.get_grant_type(),
                         xssec.constants.GRANTTYPE_PASSWORD)
        self.assertEqual(sec_context.get_identity_zone(), 'test-idz')
        self.assertEqual(sec_context.get_zone_id(), 'test-idz')
        self.assertEqual(sec_context.get_subaccount_id(), 'test-idz')
        self.assertIsNone(sec_context.get_subdomain())
        self.assertFalse(sec_context.is_in_foreign_mode())

    def _check_client_credentials_token(self, sec_context, expected_subaccount_id='test-idz'):
        self.assertTrue(sec_context.check_scope('$XSAPPNAME.resource'))
        self.assertTrue(sec_context.check_scope('uaa.resource'))
        self.assertFalse(sec_context.check_scope(
            'cloud_controller.nonexistingscope'))
        self.assertTrue(sec_context.check_local_scope('resource'))
        self.assertFalse(sec_context.check_local_scope('nonexistingscope'))
        self._check_hdb_token(sec_context)
        user_attribute_getters = [
            'get_logon_name', 'get_family_name', 'get_given_name', 'get_email', 'has_attributes'
        ]
        for getter in user_attribute_getters:
            self.assertIsNone(getattr(sec_context, getter)())
        self.assertIsNone(sec_context.get_attribute('country'))
        self.assertIsNone(sec_context.get_attribute('hugo'))
        self.assertIsNone(sec_context.get_additional_auth_attribute('hugo'))
        self.assertEqual(
            sec_context.get_grant_type(), xssec.constants.GRANTTYPE_CLIENTCREDENTIAL)
        self.assertEqual(sec_context.get_identity_zone(), 'test-idz')
        self.assertEqual(sec_context.get_zone_id(), 'test-idz')
        self.assertEqual(sec_context.get_subaccount_id(), expected_subaccount_id)
        self.assertIsNone(sec_context.get_origin())
        self.assertEqual(sec_context.get_clientid(), 'sb-xssectest')
        self.assertFalse(sec_context.is_in_foreign_mode())
        self.assertEqual(sec_context.get_expiration_date(),
                         datetime.utcfromtimestamp(2101534482))

    def test_valid_client_credentials_token_attributes(self):
        ''' valid client credentials token (with attributes) '''
        sec_context = xssec.create_security_context(
            sign(jwt_payloads.CLIENT_CREDENTIALS_TOKEN),
            uaa_configs.VALID['uaa_cc'])
        self._check_client_credentials_token(sec_context)
        self.assertEqual(
            sec_context.get_additional_auth_attribute('external_group'), 'domaingroup1')
        self.assertEqual(
            sec_context.get_clone_service_instance_id(), 'abcd1234')

    def test_valid_client_credentials_token_no_attributes(self):
        ''' valid client credentials token (no attributes) '''
        sec_context = xssec.create_security_context(
            sign(jwt_payloads.CLIENT_CREDENTIALS_TOKEN_NO_ATTR),
            uaa_configs.VALID['uaa_cc'])
        self._check_client_credentials_token(sec_context)
        self.assertIsNone(
            sec_context.get_additional_auth_attribute('external_group'))

    def test_valid_credentials_token_subaccount(self):
        ''' valid client credentials token (subaccountid in attributes) '''
        sec_context = xssec.create_security_context(
            sign(jwt_payloads.CLIENT_CREDENTIALS_TOKEN_ATTR_SUBACCOUNTID),
            uaa_configs.VALID['uaa_cc'])
        # if subaccountid is set, then the "subaccount_id" property is taken
        # from subaccountid and no longer from the zid field
        self._check_client_credentials_token(sec_context, expected_subaccount_id='5432')

    def _check_client_credentials_broker_plan(self):
        sec_context = xssec.create_security_context(
            sign(jwt_payloads.CLIENT_CREDENTIALS_BROKER_PLAN_TOKEN),
            uaa_configs.VALID['uaa_broker_plan'])
        self.assertTrue(sec_context.check_scope('$XSAPPNAME.resource'))
        self.assertTrue(sec_context.check_scope('uaa.resource'))
        self._check_hdb_token(sec_context)
        self.assertIsNone(sec_context.has_attributes())
        self.assertIsNone(sec_context.get_attribute('country'))
        self.assertEqual(sec_context.get_grant_type(),
                         xssec.constants.GRANTTYPE_CLIENTCREDENTIAL)
        self.assertEqual(sec_context.get_identity_zone(), 'test-idz')
        self.assertEqual(sec_context.get_zone_id(), 'test-idz')
        self.assertEqual(sec_context.get_subaccount_id(), 'test-idz')
        self.assertEqual(sec_context.get_clientid(),
                         'sb-xssectestclone!b4|sb-xssectest!b4')
        self.assertIsNone(sec_context.get_subdomain())
        self.assertFalse(sec_context.is_in_foreign_mode())

    def test_valid_client_credentials_broker_plan_token_acl_not_matching(self):
        ''' valid client credentials broker plan token with SAP_JWT_TRUST_ACL (not matching) '''
        environ['SAP_JWT_TRUST_ACL'] = json.dumps([{
            'clientid': 'hugo',
            'identityzone': 'uaa'
        }])
        self._check_client_credentials_broker_plan()

    def test_valid_client_credentials_broker_plan_token_no_acl(self):
        ''' valid client credentials broker plan token without SAP_JWT_TRUST_ACL '''
        self._check_client_credentials_broker_plan()

    # def test_valid_client_credentials_broker_plan_token_with_wrong_trustedclientidsuffix(self):
    #     ''' valid client credentials broker plan token with wrong trustedclientidsuffix '''
    #     with self.assertRaises(RuntimeError) as ctx:
    #         xssec.create_security_context(
    #             sign(jwt_payloads.CLIENT_CREDENTIALS_BROKER_PLAN_TOKEN),
    #             uaa_configs.INVALID['uaa_broker_plan_wrong_suffix'])
    #     self.assertEqual(
    #         'Missmatch of client id and/or identityzone id. No JWT trust ACL (SAP_JWT_TRUST_ACL) specified in environment. '
    #         'Client id of the access token: "sb-xssectestclone!b4|sb-xssectest!b4", identity zone of the access token: '
    #         '"test-idz", OAuth client id: "sb-xssectest!t4", application identity zone: "test-idz".'
    #         , str(ctx.exception))

    def test_valid_application_plan_with_trustedclientidsuffix(self):
        ''' valid application plan with shared tenant mode, defined via SAP_JWT_TRUST_ACL '''
        environ['SAP_JWT_TRUST_ACL'] = json.dumps([{
            'clientid': '*',
            'identityzone': '*'
        }])
        sec_context = xssec.create_security_context(
            sign(jwt_payloads.INVALID_TRUSTED_APPLICATION_PLAN_TOKEN),
            uaa_configs.INVALID['uaa_broker_plan_wrong_suffix'])
        self.assertEqual('sb-tenant-test!t13',sec_context.get_clientid())
        self.assertEqual('api', sec_context.get_identity_zone())
        self.assertEqual('api', sec_context.get_zone_id())

    # def test_invalid_application_plan_with_trustedclientidsuffix(self):
    #     ''' invalid application plan with SAP_JWT_TRUST_ACL '''
    #     environ['SAP_JWT_TRUST_ACL'] = json.dumps([{
    #         'clientid': 'wrong-tenant',
    #         'identityzone': 'api'
    #     }])
    #     with self.assertRaises(RuntimeError) as ctx:
    #         xssec.create_security_context(
    #             sign(jwt_payloads.INVALID_TRUSTED_APPLICATION_PLAN_TOKEN),
    #             uaa_configs.INVALID['uaa_broker_plan_wrong_suffix'])
    #     self.assertTrue(str(ctx.exception).startswith(
    #             'No match found in JWT trust ACL (SAP_JWT_TRUST_ACL)'))

    def test_token_with_ext_cxt(self):
        ''' valid user token with "ext_cxt" property '''
        sec_context = xssec.create_security_context(
            sign(jwt_payloads.TOKEN_NEW_FORMAT),
            uaa_configs.VALID['uaa_new_token_structure'])
        self._check_hdb_token(sec_context)
        jobsheduler_token = sec_context.get_token(
            xssec.constants.SYSTEM, xssec.constants.JOBSCHEDULER)
        self.assertEqual(jobsheduler_token, sign(jwt_payloads.TOKEN_NEW_FORMAT))
        self.assertNotEqual(sec_context.get_hdb_token(), jobsheduler_token)

    def test_get_token_with_invalid_parameters(self):
        ''' valid user token with "ext_cxt" property '''
        sec_context = xssec.create_security_context(
            sign(jwt_payloads.TOKEN_NEW_FORMAT),
            uaa_configs.VALID['uaa_new_token_structure'])
        self._check_hdb_token(sec_context)
        self.assertIsNone(sec_context.get_token('invalid', xssec.constants.JOBSCHEDULER))
        self.assertIsNone(sec_context.get_token(xssec.constants.SYSTEM, 'invalid'))

    def test_token_with_ext_cxt_invalid_validation_key(self):
        ''' valid user token with "ext_cxt" property, invalid validation key '''
        with self.assertRaises(RuntimeError) as ctx:
            xssec.create_security_context(
                sign(jwt_payloads.TOKEN_NEW_FORMAT),
                uaa_configs.INVALID['uaa_verificationkey_invalid'])
        self.assertTrue(
            'Error in offline validation of access token:' in str(ctx.exception))

    @patch('httpx.get')
    def test_get_verification_key_from_uaa(self, mock_requests):
        from sap.xssec.key_cache import KeyCache
        xssec.SecurityContextXSUAA.verificationKeyCache = KeyCache()

        mock = MagicMock()
        mock_requests.return_value = mock
        mock.json.return_value = HTTP_SUCCESS

        sec_context = xssec.create_security_context(
            sign(jwt_payloads.USER_TOKEN), uaa_configs.VALID['uaa_no_verification_key'])
        self._check_user_token(sec_context)
        self.assertTrue(sec_context.has_attributes())
        self.assertEqual(sec_context.get_attribute('country'), ['USA'])
        self.assertEqual(
            sec_context.get_clone_service_instance_id(), 'abcd1234')
        self.assertEqual(
            sec_context.get_additional_auth_attribute('external_group'), 'domaingroup1')
        mock_requests.assert_called_once_with("https://api.cf.test.com", timeout=constants.HTTP_TIMEOUT_IN_SECONDS)

    def test_not_trusted_jku(self):

        with self.assertRaises(RuntimeError) as e:
            xssec.create_security_context(sign(jwt_payloads.USER_TOKEN), uaa_configs.VALID['uaa_no_verification_key_other_domain'])

        self.assertEqual("JKU of token is not trusted", str(e.exception),)

    def test_valid_xsa_token_attributes(self):
        ''' valid client credentials token (with attributes) '''
        sec_context = xssec.create_security_context(
            sign(jwt_payloads.TOKEN_XSA_FORMAT),
            uaa_configs.VALID['uaa_xsa_environment'])
        self.assertEqual(
            sec_context.get_logon_name(), 'ADMIN')


    def test_valid_xsa_token_with_newlines(self):
        ''' valid client credentials token (with attributes) '''
        sec_context = xssec.create_security_context(
            sign(jwt_payloads.TOKEN_XSA_FORMAT),
            uaa_configs.VALID['uaa_xsa_with_newlines'])
        self.assertEqual(
            sec_context.get_logon_name(), 'ADMIN')

    def test_invalid_jku_in_token_header(self):
        uaa_config = uaa_configs.VALID['uaa']
        token = sign(jwt_payloads.USER_TOKEN, headers={
            "jku": 'http://ana.ondemandh.com\\\\\\\\\\\\\\\\@' + uaa_config['uaadomain'],
            "kid": "key-id-0"
        })
        with self.assertRaises(RuntimeError) as e:
            xssec.create_security_context(token, uaa_config)
        self.assertEqual("JKU of token is not trusted", str(e.exception),)
