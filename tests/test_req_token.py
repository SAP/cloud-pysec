# pylint: disable=missing-docstring,invalid-name,missing-docstring
import unittest
from os import environ, path, devnull
import socket
from time import sleep
from subprocess import Popen

from sap.xssec import jwt_validation_facade

from sap import xssec
from tests import uaa_configs
from tests import jwt_payloads

TEST_SERVER_POLL_ATTEMPTS = 10


def get_free_tcp_port():
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.bind(('', 0))
    _, port = tcp.getsockname()
    tcp.close()
    return port


flask_env = environ.copy()

flask_env['FLASK_APP'] = path.join(path.dirname(
    path.abspath(__file__)), 'utils', 'uaa_mock.py')
flask_port = str(get_free_tcp_port())
flask_url = 'http://localhost:' + flask_port


class ReqTokenForClientTest(unittest.TestCase):
    DEVNULL = None
    flask_process = None

    @classmethod
    def setUpClass(cls):
        """ Test class static setup """
        environ["SAP_EXT_JWT_ALG"] = "*"

        cls.DEVNULL = open(devnull, 'w')
        cls.flask_process = Popen(['flask', 'run', '-p', flask_port, '-h', 'localhost'],
                                  env=flask_env, stdout=cls.DEVNULL, stderr=cls.DEVNULL)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        poll = 0

        while poll != TEST_SERVER_POLL_ATTEMPTS:
            try:
                sleep(1)
                poll += 1
                s.connect(('localhost', int(flask_port)))
                print('Test server is up!')  # pylint: disable=superfluous-parens
                break
            except socket.error as e:
                if poll == TEST_SERVER_POLL_ATTEMPTS:
                    print(
                        'Test server could not start!')  # pylint: disable=superfluous-parens
                    raise e
        s.close()

        jwt_validation_facade.ALGORITHMS = ['RS256', 'HS256']

    @classmethod
    def tearDownClass(cls):
        if cls.flask_process:
            cls.flask_process.terminate()
        if cls.DEVNULL:
            cls.DEVNULL.close()

    def _request_token_for_client_error(self, sec_context, url, error_message_end):
        service_credentials = {
            'clientid': 'clientid',
            'clientsecret': 'clientsecret',
            'url': url
        }
        with self.assertRaises(RuntimeError) as ctx:
            sec_context.request_token_for_client(service_credentials, None)
        self.assertTrue(str(ctx.exception).endswith(error_message_end))

    def test_request_token_for_client_missing_uaa_user_scope(self):
        '''
        Test valid end-user token no attributes.
        request_token_for_client failure, scope uaa.user missing
        '''
        sec_context = xssec.create_security_context(
            jwt_payloads.CORRECT_END_USER_TOKEN_NO_ATTR, uaa_configs.VALID['uaa'])
        self._request_token_for_client_error(
            sec_context, flask_url + '/500',
            'JWT token does not include scope "uaa.user"')

    def test_req_client_for_user_401_error(self):
        sec_context = xssec.create_security_context(
            jwt_payloads.CORRECT_END_USER_TOKEN_SCOPE_UAA_USER, uaa_configs.VALID['uaa'])
        expected_message = \
            'Bearer token invalid, requesting client does'\
            ' not have grant_type=user_token or no scopes were granted.'

        self._request_token_for_client_error(
            sec_context, flask_url + '/401', expected_message)

    def test_req_client_for_user_500_error(self):
        sec_context = xssec.create_security_context(
            jwt_payloads.CORRECT_END_USER_TOKEN_SCOPE_UAA_USER, uaa_configs.VALID['uaa'])
        self._request_token_for_client_error(
            sec_context, flask_url + '/500', 'HTTP status code: 500')

    def test_req_client_for_user(self):
        sec_context = xssec.create_security_context(
            jwt_payloads.CORRECT_END_USER_TOKEN_SCOPE_UAA_USER, uaa_configs.VALID['uaa'])
        service_credentials = {
            'clientid': 'clientid',
            'clientsecret': 'clientsecret',
            'url': flask_url + '/correct'
        }
        token = sec_context.request_token_for_client(service_credentials, None)
        self.assertEqual(token, 'access_token')
