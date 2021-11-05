import threading
from time import sleep
from typing import List, Callable

import pytest
from httpx import Response, HTTPStatusError

from sap.xssec.key_tools import jwk_to_pem
from tests.ias.ias_configs import JWKS, WELL_KNOWN
from tests.ias.ias_tokens import PAYLOAD, HEADER


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
    run_func_in_threads(add_to_sum, [1]*10)
    assert 10 != sum

    # thread-safe when args are same
    sum = 0
    from sap.xssec.key_cache_v2 import thread_safe_by_args
    run_func_in_threads(thread_safe_by_args(add_to_sum), [1]*10)
    assert 10 == sum

    # not thread-safe when args are different
    sum = 0
    run_func_in_threads(thread_safe_by_args(add_to_sum), list(range(1, 11)))
    assert 55 != sum


@pytest.fixture
def well_known_endpoint_mock(respx_mock):
    return respx_mock.get(PAYLOAD["iss"] + '/.well-known/openid-configuration').mock(
        return_value=Response(200, json=WELL_KNOWN))


@pytest.fixture
def jwk_endpoint_mock(respx_mock):
    return respx_mock.get(WELL_KNOWN["jwks_uri"]).mock(return_value=Response(200, json=JWKS))


def test_get_verification_key_ias_should_return_key(well_known_endpoint_mock, jwk_endpoint_mock):
    from sap.xssec.key_cache_v2 import get_verification_key_ias, key_cache
    key_cache.clear()
    pem_key = get_verification_key_ias(PAYLOAD["iss"], PAYLOAD["zone_uuid"], HEADER["kid"])
    assert well_known_endpoint_mock.called
    assert jwk_endpoint_mock.called
    jwk = next(filter(lambda k: k["kid"] == HEADER["kid"], JWKS["keys"]))
    assert jwk_to_pem(jwk) == pem_key


def test_get_verification_key_ias_should_cache_key(well_known_endpoint_mock, jwk_endpoint_mock):
    from sap.xssec.key_cache_v2 import get_verification_key_ias, key_cache
    key_cache.clear()
    for _ in range(0, 10):
        get_verification_key_ias(PAYLOAD["iss"], PAYLOAD["zone_uuid"], HEADER["kid"])
    assert 1 == well_known_endpoint_mock.call_count
    assert 1 == jwk_endpoint_mock.call_count


def test_get_verification_key_ias_should_raise_http_error(respx_mock):
    respx_mock.get(PAYLOAD["iss"] + '/.well-known/openid-configuration').mock(
        return_value=Response(500))
    from sap.xssec.key_cache_v2 import get_verification_key_ias, key_cache
    key_cache.clear()
    with pytest.raises(HTTPStatusError):
        get_verification_key_ias(PAYLOAD["iss"], PAYLOAD["zone_uuid"], HEADER["kid"])
