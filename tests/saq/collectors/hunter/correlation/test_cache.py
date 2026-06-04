from unittest.mock import MagicMock, patch

import pytest

from saq.collectors.hunter.correlation.cache import (
    CorrelateQueryRecorder,
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


@pytest.mark.unit
class TestCorrelateQueryRecorder:

    def test_capture_export_roundtrip(self):
        recorder = CorrelateQueryRecorder()
        assert recorder.replay_active is False
        recorder.record("splunk", "search index=main", '{"host": "web1"}\n{"host": "web2"}')
        exported = recorder.export()
        assert exported == [{
            "source": "splunk",
            "query": "search index=main",
            "results": [{"host": "web1"}, {"host": "web2"}],
        }]

    def test_replay_lookup_hit_and_miss(self):
        recorder = CorrelateQueryRecorder(replay=[
            {"source": "splunk", "query": "search index=main", "results": [{"host": "web1"}]},
        ])
        assert recorder.replay_active is True
        # hit returns the JSONL string _execute_query expects
        assert recorder.lookup("splunk", "search index=main") == '{"host": "web1"}'
        # miss on a different rendered query / source
        assert recorder.lookup("splunk", "search index=other") is None
        assert recorder.lookup("logscale", "search index=main") is None

    def test_record_dedup_first_wins(self):
        recorder = CorrelateQueryRecorder()
        recorder.record("splunk", "q", '{"a": 1}')
        recorder.record("splunk", "q", '{"a": 2}')
        exported = recorder.export()
        assert len(exported) == 1
        assert exported[0]["results"] == [{"a": 1}]

    def test_replay_then_export_is_complete(self):
        """A round-trip: a recorder seeded for replay, whose hits are recorded, exports
        the same records — so re-saving after an offline run keeps the file complete."""
        saved = [
            {"source": "splunk", "query": "q1", "results": [{"x": 1}]},
            {"source": "splunk", "query": "q2", "results": [{"y": 2}]},
        ]
        recorder = CorrelateQueryRecorder(replay=saved)
        for record in saved:
            output = recorder.lookup(record["source"], record["query"])
            recorder.record(record["source"], record["query"], output)
        assert recorder.export() == saved

    def test_empty_replay_is_inactive(self):
        assert CorrelateQueryRecorder(replay=[]).replay_active is False
        assert CorrelateQueryRecorder(replay=None).replay_active is False
