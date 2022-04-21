import jwt
import json

ALGORITHMS = ['RS256']
OPTIONS = {
    'verify_aud': False
}


class JwtValidationFacade(object):
    """
    Hides if either sapjwt or pyjwt library is used for the validation.
    """
    def __init__(self):
        self._pem = None
        self._payload = None
        self._error_desc = None
        self._error_code = 0

    def decode(self, token, verify=True):
        try:
            return jwt.decode(token, options={"verify_signature": verify})
        except jwt.exceptions.DecodeError as e:
            raise DecodeError(e)

    def get_unverified_header(self, token):
        try:
            return jwt.get_unverified_header(token)
        except jwt.exceptions.DecodeError as e:
            raise DecodeError(e)

    def has_token_expired(self, token) -> bool:
        try:
            jwt.decode(token, options={"verify_signature": False, 'verify_exp': True})
            return False
        except jwt.exceptions.ExpiredSignatureError as e:
            return True

    def loadPEM(self, verification_key):
        self._pem = verification_key
        return 0

    def checkToken(self, token):
        try:
            if "-----BEGIN PUBLIC KEY-----" in self._pem and '\n' not in self._pem:
                self._pem = self._pem.replace('-----BEGIN PUBLIC KEY-----', '-----BEGIN PUBLIC KEY-----\n').replace('-----END PUBLIC KEY-----','\n-----END PUBLIC KEY-----')
            self._payload = jwt.decode(token, self._pem, algorithms=ALGORITHMS, options=OPTIONS)
            self._error_desc = ''
            self._error_code = 0
        except jwt.exceptions.InvalidTokenError as e:
            self._error_desc = str(e)
            self._error_code = 1
        except ValueError as e:
            self._error_desc = str(e)
            self._error_code = 1

    def getErrorDescription(self):
        return self._error_desc

    def getErrorRC(self):
        return self._error_code

    def getJWPayload(self):
        return self._payload


class DecodeError(Exception):
    pass
