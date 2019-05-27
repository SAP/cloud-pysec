import logging
import time
import requests
from collections import OrderedDict
from threading import Lock

from sap.xssec.constants import HTTP_TIMEOUT_IN_SECONDS
from sap.xssec.constants import KEYCACHE_DEFAULT_CACHE_SIZE
from sap.xssec.constants import KEYCACHE_DEFAULT_CACHE_ENTRY_EXPIRATION_TIME_IN_MINUTES

lock = Lock()


class CacheEntry(object):
    def __init__(self, key, insert_timestamp):
        self.key = key
        self.insert_timestamp = insert_timestamp

    def is_valid(self):
        return self.insert_timestamp + KEYCACHE_DEFAULT_CACHE_ENTRY_EXPIRATION_TIME_IN_MINUTES * 60 >= time.time()


class KeyCache(object):
    """
    Thread safe cache for verification keys. Each verification key is identified by its jku and pid.
    There are a maximum of KEYCACHE_DEFAULT_CACHE_SIZE keys in the cache and
    keys are invalid if KEYCACHE_DEFAULT_CACHE_ENTRY_EXPIRATION_TIME_IN_MINUTES have passed since the key
    has been in inserted in the cache.
    """
    def __init__(self):
        self._cache = OrderedDict()
        self._logger = logging.getLogger(__name__)

    def load_key(self, jku, kid):
        """
        Either returns key from cache or retrieves it from the UAA.
        :param jku: jku of token
        :param kid: kid of token
        :return: verification key
        """
        with lock:
            self._logger.debug("Loading verification key for 'jku'={} and kid={}".format(jku, kid))
            cache_key = self._create_cache_key(jku, kid)

            if cache_key in self._cache:
                if self._cache[cache_key].is_valid():
                    self._logger.debug("Using cached verification key")
                    return self._cache[cache_key].key
                else:
                    self._logger.debug("Verification key expired. Retrieving key from uua.")
                    self._cache.pop(cache_key)

            self._logger.debug("Key not cached. Retrieving key from uua.")

            key = self._retrieve_key(jku, kid)
            self._cache[cache_key] = CacheEntry(key, time.time())

            # remove oldest key if cache is full
            if len(self._cache) > KEYCACHE_DEFAULT_CACHE_SIZE:
                self._cache.popitem(last=False)

            return key

    def _retrieve_key(self, jku, kid):
        try:
            r = requests.get(jku, timeout=HTTP_TIMEOUT_IN_SECONDS)
            r.raise_for_status()
            r_json = r.json()

            for key in r_json.get('keys', {}):
                if key.get('kid', "") == kid:
                    return key['value']

            raise ValueError("Could not find key with kid {}".format(kid))
        except requests.exceptions.HTTPError as e:
            self._logger.error("Error while trying to get key from uaa. {}".format(e))
            raise

    @staticmethod
    def _create_cache_key(jku, kid):
        return jku + kid
