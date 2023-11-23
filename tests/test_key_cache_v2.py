import threading
from time import sleep
from typing import List, Callable

import pytest
from httpx import Response, HTTPStatusError, Request

from sap.xssec.key_tools import jwk_to_pem
from tests.ias.ias_configs import JWKS, WELL_KNOWN, SERVICE_CREDENTIALS
from tests.ias.ias_tokens import PAYLOAD, HEADER, merge

VERIFICATION_KEY_PARAMS = {
    "issuer_url": PAYLOAD["iss"],
    "app_tid": PAYLOAD["app_tid"] or PAYLOAD["zone_uuid"],
    "azp": PAYLOAD["azp"],
    "client_id": SERVICE_CREDENTIALS["clientid"],
    "kid": HEADER["kid"]
}


def test_thread_safe_decorator():
    sum = 0

    def add_to_sum(x: int):
        nonlocal sum
        local_sum = sum
        sleep(0.1)
        sum = local_sum + x

    def run_func_in_threads(func: Callable[[int], None], func_args: List[int]):
        threads = []
        for arg in func_args:
            t = threading.Thread(target=func, args=[arg])
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

    # not thread-safe without decorator
    sum = 0
    run_func_in_threads(add_to_sum, [1] * 10)
    assert 10 != sum

    # thread-safe when args are same
    sum = 0
    from sap.xssec.key_cache_v2 import thread_safe_by_args
    run_func_in_threads(thread_safe_by_args(add_to_sum), [1] * 10)
    assert 10 == sum

    # not thread-safe when args are different
    sum = 0
    run_func_in_threads(thread_safe_by_args(add_to_sum), list(range(1, 11)))
    assert 55 != sum


@pytest.fixture
def well_known_endpoint_mock(respx_mock):
    return respx_mock.get(PAYLOAD["iss"] + '/.well-known/openid-configuration').mock(
        return_value=Response(200, json=WELL_KNOWN))


def jwk_endpoint_response(request: Request):
    if all(k in request.headers for k in ("x-app-tid", "x-azp", "x-client-id")):
        return Response(200, json=JWKS)
    else:
        return Response(404)


@pytest.fixture
def jwk_endpoint_mock(respx_mock):
    return respx_mock.get(WELL_KNOWN["jwks_uri"]).mock(side_effect=jwk_endpoint_response)


def test_get_verification_key_ias_should_return_key(well_known_endpoint_mock, jwk_endpoint_mock):
    from sap.xssec.key_cache_v2 import get_verification_key_ias, key_cache
    key_cache.clear()
    pem_key = get_verification_key_ias(**VERIFICATION_KEY_PARAMS)
    assert well_known_endpoint_mock.called
    assert jwk_endpoint_mock.called
    jwk = next(filter(lambda k: k["kid"] == HEADER["kid"], JWKS["keys"]))
    assert jwk_to_pem(jwk) == pem_key


def test_get_verification_key_ias_should_cache_key(well_known_endpoint_mock, jwk_endpoint_mock):
    from sap.xssec.key_cache_v2 import get_verification_key_ias, key_cache
    key_cache.clear()
    for _ in range(0, 10):
        get_verification_key_ias(**VERIFICATION_KEY_PARAMS)
    assert 1 == well_known_endpoint_mock.call_count == jwk_endpoint_mock.call_count

    for _ in range(0, 10):
        get_verification_key_ias(**merge(VERIFICATION_KEY_PARAMS, {"app_tid": "another-app-tid"}))
    assert 2 == well_known_endpoint_mock.call_count == jwk_endpoint_mock.call_count

    for _ in range(0, 10):
        get_verification_key_ias(**merge(VERIFICATION_KEY_PARAMS, {"azp": "another-azp"}))
    assert 3 == well_known_endpoint_mock.call_count == jwk_endpoint_mock.call_count

    for _ in range(0, 10):
        get_verification_key_ias(**merge(VERIFICATION_KEY_PARAMS, {"client_id": "another-client-id"}))
    assert 4 == well_known_endpoint_mock.call_count == jwk_endpoint_mock.call_count

    for _ in range(0, 10):
        get_verification_key_ias(**merge(VERIFICATION_KEY_PARAMS, {"kid": "another-kid"}))
    assert 5 == well_known_endpoint_mock.call_count == jwk_endpoint_mock.call_count


def test_get_verification_key_ias_should_throw_error_for_missing_key(well_known_endpoint_mock, jwk_endpoint_mock):
    from sap.xssec.key_cache_v2 import get_verification_key_ias, key_cache
    key_cache.clear()
    for _ in range(0, 10):
        with pytest.raises(ValueError):
            get_verification_key_ias(**merge(VERIFICATION_KEY_PARAMS, {"kid": "non-existing-kid"}))
    assert 10 == well_known_endpoint_mock.call_count == jwk_endpoint_mock.call_count


def test_get_verification_key_ias_should_raise_http_error(respx_mock):
    respx_mock.get(PAYLOAD["iss"] + '/.well-known/openid-configuration').mock(
        return_value=Response(500))
    from sap.xssec.key_cache_v2 import get_verification_key_ias, key_cache
    key_cache.clear()
    with pytest.raises(HTTPStatusError):
        get_verification_key_ias(**VERIFICATION_KEY_PARAMS)
