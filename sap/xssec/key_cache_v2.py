"""
Thread safe cache for verification keys.
For XSUAA, each verification key is identified by its jku and kid.
For IAS, each verification key is identified by issuer_url, zone_id and kid.
There are a maximum of KEYCACHE_DEFAULT_CACHE_SIZE keys in the cache and
keys are invalid if KEYCACHE_DEFAULT_CACHE_ENTRY_EXPIRATION_TIME_IN_MINUTES have passed since the key
has been in inserted in the cache.

Improvement: use dedicated lock for each cache entry key
"""
from collections import defaultdict
from functools import _make_key # noqa
from threading import Lock
from typing import List, Dict, Any

import httpx
from cachetools import cached, TTLCache

from sap.xssec.constants import HTTP_TIMEOUT_IN_SECONDS, KEYCACHE_DEFAULT_CACHE_SIZE, \
    KEYCACHE_DEFAULT_CACHE_ENTRY_EXPIRATION_TIME_IN_MINUTES
from sap.xssec.key_tools import jwk_to_pem


def thread_safe_by_args(func):
    lock_dict = defaultdict(Lock)

    def _thread_safe_func(*args, **kwargs):
        key = _make_key(args, kwargs, typed=False)
        with lock_dict[key]:
            return func(*args, **kwargs)

    return _thread_safe_func


def _fetch_verification_key_url_ias(issuer_url: str) -> str:
    """
    get the verification key url from issuer's well-known endpoint
    """
    resp = httpx.get(issuer_url + '/.well-known/openid-configuration', headers={'Accept': 'application/json'},
                     timeout=HTTP_TIMEOUT_IN_SECONDS)
    resp.raise_for_status()
    return resp.json()["jwks_uri"]


def _download_verification_key_ias(verification_key_url: str, app_tid: str, azp: str,
                                   client_id: str) -> List[Dict[str, Any]]:
    """
    get all the keys from verification key url
    """
    headers = {
        'x-app_tid': app_tid,
        'x-azp': azp,
        'x-client_id': client_id,
        'Accept': 'application/json',
    }
    headers = {k: v for k, v in headers.items() if v is not None}
    resp = httpx.get(verification_key_url, headers=headers, timeout=HTTP_TIMEOUT_IN_SECONDS)
    resp.raise_for_status()
    return resp.json()["keys"]


key_cache = TTLCache(
    maxsize=KEYCACHE_DEFAULT_CACHE_SIZE, ttl=KEYCACHE_DEFAULT_CACHE_ENTRY_EXPIRATION_TIME_IN_MINUTES * 60)


@thread_safe_by_args
@cached(cache=key_cache)
def get_verification_key_ias(issuer_url: str, app_tid: str, azp: str, client_id: str, kid: str) -> str:
    """
    get verification key for ias
    """
    verification_key_url: str = _fetch_verification_key_url_ias(issuer_url)
    verification_key_list: List[Dict[str, Any]] = _download_verification_key_ias(verification_key_url, app_tid, azp,
                                                                                 client_id)
    found = list(filter(lambda k: k["kid"] == kid, verification_key_list))
    if len(found) == 0:
        raise ValueError("Could not find key with kid {}".format(kid))
    return jwk_to_pem(found[0])


@thread_safe_by_args
@cached(cache=key_cache)
def get_verification_key_xsuaa(jku: str, kid: str) -> str:
    """
    get verification key for xsuaa
    """
    # TODO
    raise NotImplementedError()
