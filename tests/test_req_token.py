# pylint: disable=missing-docstring,invalid-name,missing-docstring
import asyncio
import unittest
from unittest.mock import patch
from os import environ, path, devnull
import socket
from time import sleep
from subprocess import Popen
from sap.xssec import jwt_validation_facade, constants
from sap import xssec
from tests import uaa_configs
from tests import jwt_payloads
from tests.jwt_tools import sign

import requests

from tests.keys import CLIENT_X509_CERTIFICATE, CLIENT_X509_KEY

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

# Event loop for running async functions in tests
loop = asyncio.get_event_loop()

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

    def _setup_get_error(self, mock):
        mock.side_effect = requests.exceptions.SSLError

    def _req_client_service_credentials(self):
        service_credentials = {
            'clientid': 'clientid',
            'clientsecret': 'clientsecret',
            'url': flask_url + '/correct'
        }
        return service_credentials

    def _req_client_sec_context(self):
        sec_context = xssec.create_security_context(
            sign(jwt_payloads.USER_TOKEN_JWT_BEARER_FOR_CLIENT), uaa_configs.VALID['uaa'])
        return sec_context

    @patch('httpx.get')
    def test_req_client_for_user_401_error(self, mock_get):
        self._setup_get_error(mock_get)

        sec_context = xssec.create_security_context(
            sign(jwt_payloads.USER_TOKEN_JWT_BEARER_FOR_CLIENT), uaa_configs.VALID['uaa'])
        sec_context = self._req_client_sec_context()

        expected_message = \
            'Authorization header invalid, requesting client does'\
            ' not have grant_type={} or no scopes were granted.'.format(constants.GRANTTYPE_JWT_BEARER)

        self._request_token_for_client_error(
            sec_context, flask_url + '/401', expected_message)

    @patch('httpx.get')
    def test_req_client_for_user_500_error(self, mock_get):
        self._setup_get_error(mock_get)

        sec_context = self._req_client_sec_context()
        self._request_token_for_client_error(
            sec_context, flask_url + '/500', 'HTTP status code: 500')

    @patch('httpx.get')
    def test_req_client_for_user(self, mock_get):
        self._setup_get_error(mock_get)

        sec_context = self._req_client_sec_context()
        service_credentials = self._req_client_service_credentials()
        token = sec_context.request_token_for_client(service_credentials, None)
        self.assertEqual(token, 'access_token')

    @patch('httpx.get')
    def test_req_client_for_user_with_mtls(self, mock_get):
        self._setup_get_error(mock_get)

        sec_context = xssec.create_security_context(
            sign(jwt_payloads.USER_TOKEN_JWT_BEARER_FOR_CLIENT), uaa_configs.VALID['uaa'])
        service_credentials = {
            'clientid': 'clientid',
            'certificate':  CLIENT_X509_CERTIFICATE,
            'key': CLIENT_X509_KEY,
            'certurl': flask_url + '/mtls'
        }
        token = sec_context.request_token_for_client(service_credentials, None)

    @patch('httpx.get')
    def test_req_client_for_user_async(self, mock_get):
        self._setup_get_error(mock_get)

        sec_context = self._req_client_sec_context()
        service_credentials = self._req_client_service_credentials()
        coro = sec_context.request_token_for_client_async(service_credentials)
        token = loop.run_until_complete(coro)
        self.assertEqual(token, 'access_token')
