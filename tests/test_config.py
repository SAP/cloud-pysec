from sap.xssec import constants
from importlib import reload


def test_http_timeout_overridden(monkeypatch):
    assert constants.HTTP_TIMEOUT_IN_SECONDS == 2

    monkeypatch.setenv("XSSEC_HTTP_TIMEOUT_IN_SECONDS", "10")
    reload(constants)
    assert constants.HTTP_TIMEOUT_IN_SECONDS == 10

    monkeypatch.delenv("XSSEC_HTTP_TIMEOUT_IN_SECONDS")
    reload(constants)
    assert constants.HTTP_TIMEOUT_IN_SECONDS == 2

