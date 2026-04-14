from unittest.mock import MagicMock, patch

import pytest

from saq.collectors.hunter.correlation.cache import (
    _make_cache_key,
    get_cached_result,
    set_cached_result,
)


@pytest.mark.unit
class TestCacheKeyGeneration:

    def test_deterministic(self):
        args = {"type": "query", "source": "splunk", "query": "index=main"}
        key1 = _make_cache_key(args)
        key2 = _make_cache_key(args)
        assert key1 == key2

    def test_different_args_different_keys(self):
        key1 = _make_cache_key({"query": "a"})
        key2 = _make_cache_key({"query": "b"})
        assert key1 != key2

    def test_key_format(self):
        key = _make_cache_key({"test": "value"})
        assert key.startswith("hunt_cache:")
        assert len(key) == len("hunt_cache:") + 64  # sha256 hex digest


@pytest.mark.unit
class TestCacheOperations:

    @patch("saq.collectors.hunter.correlation.cache.get_redis_connection")
    def test_get_cached_hit(self, mock_get_redis):
        mock_redis = MagicMock()
        mock_redis.get.return_value = "cached_output"
        mock_get_redis.return_value = mock_redis

        result = get_cached_result({"query": "test"})
        assert result == "cached_output"

    @patch("saq.collectors.hunter.correlation.cache.get_redis_connection")
    def test_get_cached_miss(self, mock_get_redis):
        mock_redis = MagicMock()
        mock_redis.get.return_value = None
        mock_get_redis.return_value = mock_redis

        result = get_cached_result({"query": "test"})
        assert result is None

    @patch("saq.collectors.hunter.correlation.cache.get_redis_connection")
    def test_set_cached(self, mock_get_redis):
        mock_redis = MagicMock()
        mock_get_redis.return_value = mock_redis

        set_cached_result({"query": "test"}, "output", 3600)
        mock_redis.setex.assert_called_once()

    @patch("saq.collectors.hunter.correlation.cache.get_redis_connection")
    def test_get_handles_redis_error(self, mock_get_redis):
        mock_get_redis.side_effect = Exception("connection error")
        result = get_cached_result({"query": "test"})
        assert result is None

    @patch("saq.collectors.hunter.correlation.cache.get_redis_connection")
    def test_set_handles_redis_error(self, mock_get_redis):
        mock_get_redis.side_effect = Exception("connection error")
        # Should not raise
        set_cached_result({"query": "test"}, "output", 3600)
