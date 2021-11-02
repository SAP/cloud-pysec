from sap.xssec.key_tools import jwk_to_pem
from tests.ias.ias_configs import JWKS


def test_jwk_to_pem():
    expected = '-----BEGIN PUBLIC KEY-----\n' \
               'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwaZIIdPySi6tYIpXBNAo\n' \
               'qvtr+uzwAaLBU+Z7JwqrYyNrk/dhcwMw47tBv36/lg2/R2QPt672/gDOKWlyecYB\n' \
               'JBt7A1trPbAlYzAi+PEbtVweOpx/6gX1t8e/ydHVNOnnY7BIpoqq6cy0itLW4n7W\n' \
               'ilxGaVfXHzOCLaX5fHNIqssAHPQWrYYkZmYPU9T/5boUfMTuhyiR9hJWInX+YEaf\n' \
               'konBQgLa8E72Naq4aUz1OR08/kOmY40Q7nIW7po7oZ4QXeT2E4QvQBLQY6bwqbLC\n' \
               'EOD6zkUZU27A0bQ7+dCfdUj2OKBe4q7Pn97Vt5xPavDzx+mLMUbjvpPAHoFAKTxJ\n' \
               'ZwIDAQAB\n' \
               '-----END PUBLIC KEY-----\n'
    assert expected == jwk_to_pem(JWKS["keys"][0])
