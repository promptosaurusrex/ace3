import logging

import pytest

from saq.collectors.hunter.correlation.actions import ActionResult, execute_action
from saq.collectors.hunter.correlation.schema import ActionConfig


@pytest.mark.unit
class TestActionResult:

    @pytest.mark.parametrize("action_type,expected", [
        ("filter", True),
        ("stop", True),
        ("discard", True),
        ("alert", True),
        ("log", False),
    ])
    def test_is_interrupt(self, action_type, expected):
        result = ActionResult(action_type=action_type)
        assert result.is_interrupt is expected

    @pytest.mark.parametrize("action_type,expected", [
        ("stop", True),
        ("discard", True),
        ("filter", False),
        ("alert", False),
        ("log", False),
    ])
    def test_is_stream_interrupt(self, action_type, expected):
        result = ActionResult(action_type=action_type)
        assert result.is_stream_interrupt is expected


@pytest.mark.unit
class TestExecuteAction:

    def test_filter(self):
        action = ActionConfig(type="filter")
        result = execute_action(action, {}, [])
        assert result.action_type == "filter"

    def test_stop(self):
        action = ActionConfig(type="stop")
        result = execute_action(action, {}, [])
        assert result.action_type == "stop"

    def test_discard(self):
        action = ActionConfig(type="discard")
        result = execute_action(action, {}, [])
        assert result.action_type == "discard"

    def test_alert_with_overrides(self):
        action = ActionConfig(type="alert", queue="my_queue", analysis_mode="deep")
        result = execute_action(action, {}, [])
        assert result.action_type == "alert"
        assert result.queue_override == "my_queue"
        assert result.analysis_mode_override == "deep"

    def test_alert_no_overrides(self):
        action = ActionConfig(type="alert")
        result = execute_action(action, {}, [])
        assert result.queue_override is None
        assert result.analysis_mode_override is None

    def test_log(self, caplog):
        action = ActionConfig(type="log", message="user={{ _event.user }}", level="WARNING")
        event = {"user": "admin"}
        with caplog.at_level(logging.WARNING):
            result = execute_action(action, event, [event])
        assert result.action_type == "log"
        assert "user=admin" in caplog.text

    def test_log_default_level(self, caplog):
        action = ActionConfig(type="log", message="test message")
        with caplog.at_level(logging.INFO):
            result = execute_action(action, {}, [])
        assert result.action_type == "log"
        assert "test message" in caplog.text
