import datetime
from unittest.mock import MagicMock, patch

import pytest

from saq.collectors.hunter.correlation.engine import CorrelationEngine, CorrelationResult
from saq.collectors.hunter.correlation.schema import CorrelateConfig, StepConfig


def _make_config(logic_data, timeout="15m"):
    """Helper to create a CorrelateConfig from raw logic data."""
    return CorrelateConfig.model_validate({
        "timeout": timeout,
        "logic": logic_data,
    })


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
                "execute": [{"action": {"type": "log", "message": "found special"}}],
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
            {"action": {"type": "log", "message": "logging {{ id }}", "level": "INFO"}},
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
