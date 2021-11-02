from httpx import HTTPStatusError, Response
from httpx import TimeoutException

from sap.xssec import constants
from sap.xssec.key_cache import KeyCache
import unittest
try:
    from unittest.mock import MagicMock, patch
except ImportError:
    from mock import MagicMock, patch

from tests.http_responses import *

MOCKED_CURRENT_TIME = 915148801.25
threadErrors = False


@patch('time.time', return_value=MOCKED_CURRENT_TIME)
@patch('httpx.get')
class CacheTest(unittest.TestCase):

    def setUp(self):
        self.cache = KeyCache()
        self.mock = MagicMock()

    def test_empty_cache_load_key(self, mock_requests, mock_time):
        mock_requests.return_value = self.mock
        self.mock.json.return_value = HTTP_SUCCESS

        key = self.cache.load_key("jku1", "key-id-1")

        self.assert_key_equal(KEY_ID_1, key)
        mock_requests.assert_called_once_with("jku1", timeout=constants.HTTP_TIMEOUT_IN_SECONDS)

    def test_not_hit_load_key(self, mock_requests, mock_time):
        mock_requests.return_value = self.mock
        self.mock.json.side_effect = [HTTP_SUCCESS_DUMMY, HTTP_SUCCESS]
        self.cache.load_key("jku2", "key-id-1")

        key = self.cache.load_key("jku1", "key-id-1")

        self.assert_key_equal(KEY_ID_1, key)
        self.assertEqual(2, mock_requests.call_count)

    def test_hit_do_not_load_key(self, mock_requests, mock_time):
        mock_requests.return_value = self.mock
        self.mock.json.side_effect = [HTTP_SUCCESS_DUMMY, HTTP_SUCCESS]

        mock_time.return_value = MOCKED_CURRENT_TIME - (constants.KEYCACHE_DEFAULT_CACHE_ENTRY_EXPIRATION_TIME_IN_MINUTES - 1) * 60
        self.cache.load_key("jku1", "key-id-1")
        mock_time.return_value = MOCKED_CURRENT_TIME

        key = self.cache.load_key("jku1", "key-id-1")

        self.assert_key_equal("dummy-key", key)
        self.assertEqual(1, mock_requests.call_count)

    def test_expired_key_load_key(self, mock_requests, mock_time):
        mock_requests.return_value = self.mock
        self.mock.json.side_effect = [HTTP_SUCCESS_DUMMY, HTTP_SUCCESS]

        mock_time.return_value = MOCKED_CURRENT_TIME - (constants.KEYCACHE_DEFAULT_CACHE_ENTRY_EXPIRATION_TIME_IN_MINUTES + 1) * 60
        self.cache.load_key("jku1", "key-id-1")
        mock_time.return_value = MOCKED_CURRENT_TIME

        key = self.cache.load_key("jku1", "key-id-1")

        self.assert_key_equal(KEY_ID_1, key)
        self.assertEqual(2, mock_requests.call_count)

    def test_kid_does_not_match(self, mock_requests, mock_time):
        mock_requests.return_value = self.mock
        self.mock.json.side_effect = [HTTP_SUCCESS_DUMMY, HTTP_SUCCESS]
        self.cache.load_key("jku2", "key-id-1")

        key = self.cache.load_key("jku2", "key-id-0")

        self.assert_key_equal(KEY_ID_0, key)
        self.assertEqual(2, mock_requests.call_count)

    def test_cache_max_size(self, mock_requests, mock_time):
        mock_requests.return_value = self.mock
        self.mock.json.return_value = HTTP_SUCCESS_DUMMY
        for i in range(0, constants.KEYCACHE_DEFAULT_CACHE_SIZE):
            self.cache.load_key("jku-" + str(i), "key-id-1")

        self.assertEqual(len(self.cache._cache), constants.KEYCACHE_DEFAULT_CACHE_SIZE)
        self.assertTrue(KeyCache._create_cache_key("jku-0", "key-id-1") in self.cache._cache)

        self.mock.json.return_value = HTTP_SUCCESS
        key = self.cache.load_key("jku1", "key-id-0")

        self.assert_key_equal(KEY_ID_0, key)
        self.assertEqual(constants.KEYCACHE_DEFAULT_CACHE_SIZE + 1, mock_requests.call_count)
        self.assertEqual(len(self.cache._cache), constants.KEYCACHE_DEFAULT_CACHE_SIZE)
        # assert that least recently inserted key got deleted
        self.assertFalse(KeyCache._create_cache_key("jku-0", "key-id-1") in self.cache._cache)

    def test_update_increases_insertion_order(self, mock_requests, mock_time):
        mock_requests.return_value = self.mock
        self.mock.json.return_value = HTTP_SUCCESS_DUMMY
        for i in range(0, constants.KEYCACHE_DEFAULT_CACHE_SIZE):
            self.cache.load_key("jku-" + str(i), "key-id-1")
        self.assertEqual(len(self.cache._cache), constants.KEYCACHE_DEFAULT_CACHE_SIZE)
        self.assertTrue(KeyCache._create_cache_key("jku-0", "key-id-1") in self.cache._cache)

        # first cache entry is invalid -> must be updated
        self.cache._cache[KeyCache._create_cache_key("jku-0", "key-id-1")].insert_timestamp = 0

        self.mock.json.return_value = HTTP_SUCCESS
        # update first cache entry -> should not deleted if new key is added
        self.cache.load_key("jku-0", "key-id-1")
        self.assertTrue(KeyCache._create_cache_key("jku-0", "key-id-1") in self.cache._cache)
        self.assertTrue(KeyCache._create_cache_key("jku-1", "key-id-1") in self.cache._cache)

        # add new key
        self.cache.load_key("jku1", "key-id-0")

        self.assertTrue(KeyCache._create_cache_key("jku-0", "key-id-1") in self.cache._cache)
        self.assertFalse(KeyCache._create_cache_key("jku-1", "key-id-1") in self.cache._cache)
        self.assertEqual(len(self.cache._cache), constants.KEYCACHE_DEFAULT_CACHE_SIZE)

    @patch('sap.xssec.key_cache.CacheEntry.is_valid', return_value=False)
    def test_parallel_access_works(self, mock_valid, mock_requests, mock_time):
        # All entries are invalid, so each load updates the cache.
        # This leads to problems if the threads are not correctly synchronized.
        import threading
        mock_requests.return_value = self.mock
        self.mock.json.return_value = HTTP_SUCCESS

        def thread_target():
            for _ in range(0, 100):
                try:
                    self.cache.load_key("jku1", "key-id-0")
                except Exception:
                    global threadErrors
                    threadErrors = True
                    raise

        threads = []
        for _ in range(0, 10):
            t = threading.Thread(target=thread_target, args=[])
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

        self.assertFalse(threadErrors)

    def test_get_returns_empty(self, mock_requests, mock_time):
        mock_requests.return_value = self.mock
        self.mock.json.return_value = {}

        with self.assertRaises(ValueError):
            self.cache.load_key("jku1", "key-id-1")

        mock_requests.assert_called_once_with("jku1", timeout=constants.HTTP_TIMEOUT_IN_SECONDS)

    def test_no_matching_kid(self, mock_requests, mock_time):
        mock_requests.return_value = self.mock
        self.mock.json.return_value = HTTP_SUCCESS

        with self.assertRaises(ValueError):
            self.cache.load_key("jku1", "key-id-3")

        mock_requests.assert_called_once_with("jku1", timeout=constants.HTTP_TIMEOUT_IN_SECONDS)

    def assert_key_equal(self, key1, key2):
        self.assertEqual(strip_white_space(key1), strip_white_space(key2))

    def test_timeout_retry(self, mock_requests, mock_time):
        # mock_requests.side_effect = [Timeout(), self.mock]

        exc = TimeoutException('timeout_retry test case', request=None)
        mock_requests.side_effect = [exc, self.mock]
        self.mock.json.return_value = HTTP_SUCCESS

        key = self.cache.load_key("jku1", "key-id-1")

        self.assert_key_equal(KEY_ID_1, key)
        self.assertEqual(2, mock_requests.call_count)

    def test_timeout_retry_max(self, mock_requests, mock_time):
        exc = TimeoutException('retry_max test case', request=None)
        mock_requests.side_effect = [exc, exc, exc, self.mock]
        self.mock.json.return_value = HTTP_SUCCESS

        key = self.cache.load_key("jku1", "key-id-1")

        self.assert_key_equal(KEY_ID_1, key)
        self.assertEqual(4, mock_requests.call_count)

    def test_timeout_retry_fail(self, mock_requests, mock_time):
        exc = TimeoutException('retry_fail test case', request=None)
        mock_requests.side_effect = 4 * [exc]

        with self.assertRaises(TimeoutException):
            self.cache.load_key("jku1", "key-id-1")
        self.assertEqual(4, mock_requests.call_count)

    def test_http_retry_(self, mock_requests, mock_time):
        response = Response(status_code=502)
        mock_requests.side_effect = [HTTPStatusError(message=..., request=..., response=response), self.mock]
        self.mock.json.return_value = HTTP_SUCCESS

        key = self.cache.load_key("jku1", "key-id-1")
        self.assertEqual(2, mock_requests.call_count)
        self.assert_key_equal(KEY_ID_1, key)


def strip_white_space(key):
    return key.replace(" ", "").replace("\t", "").replace("\n", "")
