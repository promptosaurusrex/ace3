import datetime
from unittest.mock import MagicMock, patch

import pytest

from saq.collectors.hunter.correlation.engine import CorrelationEngine, CorrelationResult
from saq.collectors.hunter.correlation.registry import (
    QuerySource,
    clear_query_sources,
    register_query_source,
)
from saq.collectors.hunter.correlation.schema import CorrelateConfig, PredefinedCommandConfig, StepConfig


def _make_config(logic_data, timeout="15m"):
    """Helper to create a CorrelateConfig from raw logic data."""
    return CorrelateConfig.model_validate({
        "timeout": timeout,
        "logic": logic_data,
    })


@pytest.fixture(autouse=True)
def _mock_secrets_and_config():
    mock_raw = MagicMock()
    mock_raw._data = {}
    with patch("saq.collectors.hunter.correlation.engine.export_encrypted_passwords", return_value={}), \
         patch("saq.collectors.hunter.correlation.engine.get_config", return_value=MagicMock(raw=mock_raw)):
        yield


@pytest.mark.unit
class TestCorrelationEngine:

    def test_no_logic_all_alert(self):
        """Events with no logic steps should all become alerts."""
        config = _make_config([])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        events = [{"id": 1}, {"id": 2}, {"id": 3}]
        result = engine.execute(events)
        assert len(result.events) == 3
        assert not result.discarded

    def test_filter_action(self):
        """Filter action should remove the event."""
        config = _make_config([
            {
                "when": {"type": "equals", "value": "admin", "property": "user"},
                "execute": [{"action": "filter"}],
            },
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        events = [{"user": "admin"}, {"user": "guest"}, {"user": "admin"}]
        result = engine.execute(events)
        assert len(result.events) == 1
        assert result.events[0]["user"] == "guest"

    def test_stop_action(self):
        """Stop action should halt processing but keep accumulated alerts."""
        config = _make_config([
            {
                "when": {"type": "equals", "value": "stop_here", "property": "action"},
                "execute": [{"action": "stop"}],
            },
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        events = [
            {"action": "continue", "id": 1},
            {"action": "stop_here", "id": 2},
            {"action": "continue", "id": 3},
        ]
        result = engine.execute(events)
        assert len(result.events) == 1
        assert result.events[0]["id"] == 1

    def test_discard_action(self):
        """Discard action should stop everything and set discarded flag."""
        config = _make_config([
            {
                "when": {"type": "equals", "value": "discard_all", "property": "action"},
                "execute": [{"action": "discard"}],
            },
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        events = [
            {"action": "continue", "id": 1},
            {"action": "discard_all", "id": 2},
            {"action": "continue", "id": 3},
        ]
        result = engine.execute(events)
        assert result.discarded is True

    def test_alert_action_with_overrides(self):
        """Alert action should include queue/analysis_mode overrides."""
        config = _make_config([
            {"action": {"type": "alert", "queue": "high_priority", "analysis_mode": "deep"}},
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        events = [{"id": 1}]
        result = engine.execute(events)
        assert len(result.events) == 1
        assert result.event_actions[0].queue_override == "high_priority"

    def test_condition_else_branch(self):
        """Else branch should execute when condition is false."""
        config = _make_config([
            {
                "when": {"type": "equals", "value": "admin", "property": "user"},
                "execute": [{"action": "alert"}],
                "else": [{"action": "filter"}],
            },
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        events = [{"user": "admin"}, {"user": "guest"}]
        result = engine.execute(events)
        assert len(result.events) == 1
        assert result.events[0]["user"] == "admin"

    def test_default_alert(self):
        """Events that fall through without an explicit action should become alerts."""
        config = _make_config([
            {
                "when": {"type": "equals", "value": "special", "property": "type"},
                "execute": [{"action": {"type": "log", "log_message": "found special"}}],
            },
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        events = [{"type": "normal"}]
        result = engine.execute(events)
        assert len(result.events) == 1

    def test_timeout_remaining_events_alert(self):
        """When timeout occurs, remaining events should fall through to alert."""
        config = _make_config([], timeout="1s")
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        # Set timeout to already expired
        engine.timeout = datetime.timedelta(seconds=0)
        events = [{"id": 1}, {"id": 2}]
        result = engine.execute(events)
        assert len(result.events) == 2

    def test_log_action_continues_processing(self):
        """Log action should not interrupt processing."""
        config = _make_config([
            {"action": {"type": "log", "log_message": "logging {{ _event.id }}", "log_level": "INFO"}},
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        events = [{"id": 1}, {"id": 2}]
        result = engine.execute(events)
        assert len(result.events) == 2

    def test_multiple_conditions_sequential(self):
        """Multiple conditions should be processed in order."""
        config = _make_config([
            {
                "when": {"type": "equals", "value": "noise", "property": "category"},
                "execute": [{"action": "filter"}],
            },
            {
                "when": {"type": "equals", "value": "critical", "property": "severity"},
                "execute": [{"action": {"type": "alert", "queue": "critical"}}],
            },
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        events = [
            {"category": "noise", "severity": "low"},
            {"category": "alert", "severity": "critical"},
            {"category": "alert", "severity": "low"},
        ]
        result = engine.execute(events)
        assert len(result.events) == 2
        # The critical event should have queue override
        assert result.event_actions[1].queue_override == "critical"

    def test_empty_events(self):
        """Empty event list should return empty result."""
        config = _make_config([{"action": "alert"}])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        result = engine.execute([])
        assert len(result.events) == 0
        assert not result.discarded

    def test_alert_event_origin_indices_tracks_pre_correlation_index(self):
        """`alert_event_origin_indices[i]` should be the engine event_index that produced
        `events[i]` — letting downstream callers map a kept event back to its EventTrace.
        """
        # Filter middle event, keep first and third
        config = _make_config([
            {
                "when": {"type": "equals", "value": "drop", "property": "tag"},
                "execute": [{"action": "filter"}],
            },
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        events = [
            {"id": 1, "tag": "keep"},
            {"id": 2, "tag": "drop"},
            {"id": 3, "tag": "keep"},
        ]
        result = engine.execute(events)
        assert [e["id"] for e in result.events] == [1, 3]
        # Index 1 was filtered; the kept events came from original positions 0 and 2.
        assert result.alert_event_origin_indices == [0, 2]
        # Each kept origin index must correspond to an EventTrace with outcome=alert.
        traces_by_index = {et.event_index: et for et in result.trace.event_traces}
        for origin in result.alert_event_origin_indices:
            assert traces_by_index[origin].outcome == "alert"


class _RecordingSource(QuerySource):
    default_time_field = "_time"
    default_time_format = "iso8601"

    def __init__(self, results=None):
        self.results = results or []
        self.calls = []

    def execute_query(self, query, start_time, end_time, timeout, source_options=None):
        self.calls.append({
            "query": query,
            "start_time": start_time,
            "end_time": end_time,
            "source_options": source_options,
        })
        return list(self.results)


class _EpochSource(QuerySource):
    default_time_field = "ts"
    default_time_format = "epoch"

    def __init__(self, results=None):
        self.results = results or []
        self.calls = []

    def execute_query(self, query, start_time, end_time, timeout, source_options=None):
        self.calls.append({
            "query": query,
            "start_time": start_time,
            "end_time": end_time,
            "source_options": source_options,
        })
        return list(self.results)


@pytest.fixture
def _clean_registry():
    clear_query_sources()
    try:
        yield
    finally:
        clear_query_sources()


@pytest.mark.unit
class TestSourceAwareTimeDefaults:
    """Verify that the engine threads hunt_source_type into query commands so
    relative_time_field/format can be omitted on YAML when the source declares defaults."""

    def test_hunt_source_type_supplies_default_field_for_event_query(self, _clean_registry, tmpdir):
        splunk = _RecordingSource(results=[])
        register_query_source("splunk", splunk)

        # event-transform query with time_range that omits relative_time_field/format;
        # engine must default to splunk's `_time` / iso8601 because hunt_source_type is "splunk".
        config = _make_config([
            {
                "transform": {
                    "type": "event",
                    "method": "property",
                    "property_name": "lookup",
                    "command": {
                        "type": "query",
                        "source": "splunk",
                        "query": "search index=main",
                        "time_range": {"before": "1h", "after": "1h"},
                    },
                },
            },
        ])
        hunt_time = datetime.datetime(2024, 6, 1, 12, 0, tzinfo=datetime.timezone.utc)
        engine = CorrelationEngine(config, [], hunt_time, hunt_source_type="splunk")
        events = [{"_time": "2024-06-01T00:00:00+00:00"}]
        engine.execute(events)

        assert len(splunk.calls) == 1
        ref = datetime.datetime(2024, 6, 1, 0, 0, tzinfo=datetime.timezone.utc)
        assert splunk.calls[0]["start_time"] == ref - datetime.timedelta(hours=1)
        assert splunk.calls[0]["end_time"] == ref + datetime.timedelta(hours=1)

    def test_missing_default_field_routes_event_to_alert_with_error(self, _clean_registry, tmpdir):
        splunk = _RecordingSource(results=[])
        register_query_source("splunk", splunk)

        config = _make_config([
            {
                "transform": {
                    "type": "event",
                    "method": "property",
                    "property_name": "lookup",
                    "command": {
                        "type": "query",
                        "source": "splunk",
                        "query": "search index=main",
                        "time_range": {"before": "1h", "after": "1h"},
                    },
                },
            },
        ])
        hunt_time = datetime.datetime(2024, 6, 1, 12, 0, tzinfo=datetime.timezone.utc)
        engine = CorrelationEngine(config, [], hunt_time, hunt_source_type="splunk")
        # event lacks the default `_time` field
        events = [{"host": "web1"}]
        result = engine.execute(events)

        assert len(splunk.calls) == 0  # query never reached because resolution failed
        assert len(result.trace.event_traces) == 1
        assert result.trace.event_traces[0].outcome == "error"
        # event still produces an alert per the fail-safe error policy
        assert len(result.events) == 1

    def test_stream_mutate_query_switches_current_source(self, _clean_registry, tmpdir):
        splunk = _RecordingSource(results=[{"_time": "2099-01-01T00:00:00+00:00"}])
        epoch = _EpochSource(results=[{"ts": "1717200000"}])  # 2024-06-01 00:00:00 UTC
        register_query_source("splunk", splunk)
        register_query_source("epoch_src", epoch)

        # step 1: stream-mutate query against epoch_src replaces the stream and
        # switches current source to epoch_src.
        # step 2: event-transform query against splunk; because current source is now
        # epoch_src, default field is `ts` (epoch). The new event's `ts` should anchor
        # the time range; if defaults still pointed to splunk's `_time` we'd fail
        # because the new event has no `_time`.
        config = _make_config([
            {
                "transform": {
                    "type": "stream",
                    "method": "mutate",
                    "command": {
                        "type": "query",
                        "source": "epoch_src",
                        "query": "epoch search",
                        "time_range": {"before": "1h"},
                    },
                },
            },
            {
                "transform": {
                    "type": "event",
                    "method": "property",
                    "property_name": "context",
                    "command": {
                        "type": "query",
                        "source": "splunk",
                        "query": "search lookup",
                        "time_range": {"before": "30m", "after": "30m"},
                    },
                },
            },
        ])
        hunt_time = datetime.datetime(2024, 6, 1, 12, 0, tzinfo=datetime.timezone.utc)
        engine = CorrelationEngine(config, [], hunt_time, hunt_source_type="splunk")
        # initial event has _time so the stream-mutate query (anchored to hunt_time) runs fine
        engine.execute([{"_time": "2024-05-31T00:00:00+00:00"}])

        # second query (after the stream mutate) should be anchored to ts=1717200000
        assert len(splunk.calls) == 1
        ref = datetime.datetime.fromtimestamp(1717200000, tz=datetime.timezone.utc)
        assert splunk.calls[0]["start_time"] == ref - datetime.timedelta(minutes=30)
        assert splunk.calls[0]["end_time"] == ref + datetime.timedelta(minutes=30)

    def test_resolve_command_source_handles_defined_query(self, _clean_registry):
        splunk = _RecordingSource()
        register_query_source("splunk", splunk)

        from saq.collectors.hunter.correlation.schema import CommandConfig

        predef = PredefinedCommandConfig(
            name="splunk_lookup", type="query", source="splunk", query="search foo",
        )
        engine = CorrelationEngine(
            _make_config([]), [predef], datetime.datetime.now(datetime.timezone.utc),
            hunt_source_type="splunk",
        )
        defined_cmd = CommandConfig(type="defined", name="splunk_lookup")
        assert engine._resolve_command_source(defined_cmd) == "splunk"
        # executable defined commands return None (don't switch source on stream mutate)
        exec_predef = PredefinedCommandConfig(name="ext", type="executable", path="/bin/true")
        engine.predefined_commands = [exec_predef]
        defined_exec = CommandConfig(type="defined", name="ext")
        assert engine._resolve_command_source(defined_exec) is None
