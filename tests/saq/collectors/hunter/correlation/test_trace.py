import datetime
from unittest.mock import MagicMock, patch

import pytest

from saq.collectors.hunter.correlation.engine import CorrelationEngine
from saq.collectors.hunter.correlation.expressions import evaluate_expression_traced
from saq.collectors.hunter.correlation.schema import CorrelateConfig, ExpressionConfig
from saq.collectors.hunter.correlation.trace import (
    ActionTrace,
    ConditionTrace,
    TransformTrace,
    sanitize_value,
)


def _make_config(logic_data, timeout="15m"):
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
class TestSanitizeValue:

    def test_no_secrets(self):
        assert sanitize_value("hello world", {}) == "hello world"

    def test_none_value(self):
        assert sanitize_value(None, {"key": "secret"}) is None

    def test_replaces_secret(self):
        assert sanitize_value("token=abc123", {"api_key": "abc123"}) == "token=***"

    def test_nested_secrets(self):
        secrets = {"outer": {"inner": "secret_val"}}
        assert sanitize_value("my secret_val here", secrets) == "my *** here"

    def test_empty_secret_ignored(self):
        assert sanitize_value("hello", {"key": ""}) == "hello"

    def test_multiple_occurrences(self):
        assert sanitize_value("abc abc", {"k": "abc"}) == "*** ***"


@pytest.mark.unit
class TestExpressionTraced:

    def test_jinja_true(self):
        expr = ExpressionConfig(type="jinja", value="{{ _event.name }}")
        result, trace = evaluate_expression_traced(expr, {"name": "admin"}, [])
        assert result is True
        assert trace.expression_type == "jinja"
        assert trace.result is True
        assert trace.rendered_value == "admin"

    def test_jinja_false(self):
        expr = ExpressionConfig(type="jinja", value="{{ _event.missing }}")
        result, trace = evaluate_expression_traced(expr, {}, [])
        assert result is False
        assert trace.result is False
        assert trace.rendered_value == ""

    def test_equals(self):
        expr = ExpressionConfig(type="equals", value="admin", property="user")
        result, trace = evaluate_expression_traced(expr, {"user": "admin"}, [])
        assert result is True
        assert trace.expression_type == "equals"
        assert trace.property_name == "user"
        assert trace.property_value == "admin"
        assert trace.compare_value == "admin"

    def test_equals_mismatch(self):
        expr = ExpressionConfig(type="equals", value="admin", property="user")
        result, trace = evaluate_expression_traced(expr, {"user": "guest"}, [])
        assert result is False
        assert trace.property_value == "guest"

    def test_glob(self):
        expr = ExpressionConfig(type="glob", value="*.exe", property="file")
        result, trace = evaluate_expression_traced(expr, {"file": "malware.exe"}, [])
        assert result is True
        assert trace.expression_type == "glob"
        assert trace.property_value == "malware.exe"

    def test_regex(self):
        expr = ExpressionConfig(type="regex", value=r"\d+", property="code")
        result, trace = evaluate_expression_traced(expr, {"code": "error 404"}, [])
        assert result is True
        assert trace.expression_type == "regex"

    def test_and_all_true(self):
        expr = ExpressionConfig(type="and", value=[
            {"type": "equals", "value": "admin", "property": "user"},
            {"type": "equals", "value": "login", "property": "action"},
        ])
        result, trace = evaluate_expression_traced(expr, {"user": "admin", "action": "login"}, [])
        assert result is True
        assert trace.expression_type == "and"
        assert len(trace.sub_expressions) == 2
        assert all(s.result for s in trace.sub_expressions)

    def test_and_short_circuits(self):
        expr = ExpressionConfig(type="and", value=[
            {"type": "equals", "value": "admin", "property": "user"},
            {"type": "equals", "value": "login", "property": "action"},
        ])
        result, trace = evaluate_expression_traced(expr, {"user": "guest", "action": "login"}, [])
        assert result is False
        # Short-circuits: only the first sub-expression is evaluated
        assert len(trace.sub_expressions) == 1
        assert trace.sub_expressions[0].result is False

    def test_or_short_circuits(self):
        expr = ExpressionConfig(type="or", value=[
            {"type": "equals", "value": "admin", "property": "user"},
            {"type": "equals", "value": "root", "property": "user"},
        ])
        result, trace = evaluate_expression_traced(expr, {"user": "admin"}, [])
        assert result is True
        assert len(trace.sub_expressions) == 1
        assert trace.sub_expressions[0].result is True

    def test_not(self):
        expr = ExpressionConfig(type="not", value={"type": "equals", "value": "admin", "property": "user"})
        result, trace = evaluate_expression_traced(expr, {"user": "guest"}, [])
        assert result is True
        assert trace.expression_type == "not"
        assert trace.result is True
        assert len(trace.sub_expressions) == 1
        assert trace.sub_expressions[0].result is False

    def test_jinja_error(self):
        expr = ExpressionConfig(type="jinja", value="{{ _event.x | bad_filter }}")
        result, trace = evaluate_expression_traced(expr, {"x": "val"}, [])
        assert result is False
        assert trace.error is not None


@pytest.mark.unit
class TestEngineTrace:

    def test_no_logic_produces_trace(self):
        config = _make_config([])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        result = engine.execute([{"id": 1}, {"id": 2}])
        assert result.trace is not None
        assert len(result.trace.event_traces) == 2
        assert all(et.outcome == "alert" for et in result.trace.event_traces)
        assert all(len(et.steps) == 0 for et in result.trace.event_traces)

    def test_condition_filter_trace(self):
        config = _make_config([
            {
                "when": {"type": "equals", "value": "admin", "property": "user"},
                "execute": [{"action": "filter"}],
            },
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        result = engine.execute([{"user": "admin"}, {"user": "guest"}])

        assert result.trace is not None
        traces = result.trace.event_traces
        assert len(traces) == 2

        # First event: admin, filtered
        et0 = traces[0]
        assert et0.outcome == "filter"
        assert len(et0.steps) == 1
        cond = et0.steps[0].step
        assert isinstance(cond, ConditionTrace)
        assert cond.expression.result is True
        assert cond.branch_taken == "execute"
        assert len(cond.branch_steps) == 1
        assert isinstance(cond.branch_steps[0].step, ActionTrace)
        assert cond.branch_steps[0].step.action_type == "filter"

        # Second event: guest, alert (condition false, no else)
        et1 = traces[1]
        assert et1.outcome == "alert"
        cond1 = et1.steps[0].step
        assert isinstance(cond1, ConditionTrace)
        assert cond1.expression.result is False
        assert cond1.branch_taken == "none"

    def test_condition_else_branch_trace(self):
        config = _make_config([
            {
                "when": {"type": "equals", "value": "admin", "property": "user"},
                "execute": [{"action": "filter"}],
                "else": [{"action": {"type": "log", "log_message": "not admin: {{ _event.user }}"}}],
            },
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        result = engine.execute([{"user": "guest"}])

        et = result.trace.event_traces[0]
        cond = et.steps[0].step
        assert isinstance(cond, ConditionTrace)
        assert cond.branch_taken == "else"
        assert len(cond.branch_steps) == 1
        action_trace = cond.branch_steps[0].step
        assert isinstance(action_trace, ActionTrace)
        assert action_trace.action_type == "log"
        assert action_trace.rendered_log_message == "not admin: guest"

    def test_nested_condition_trace(self):
        config = _make_config([
            {
                "when": {"type": "equals", "value": "admin", "property": "user"},
                "execute": [
                    {
                        "when": {"type": "equals", "value": "login", "property": "action"},
                        "execute": [{"action": "filter"}],
                    },
                ],
            },
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        result = engine.execute([{"user": "admin", "action": "login"}])

        et = result.trace.event_traces[0]
        assert et.outcome == "filter"
        outer = et.steps[0].step
        assert isinstance(outer, ConditionTrace)
        assert outer.branch_taken == "execute"
        inner = outer.branch_steps[0].step
        assert isinstance(inner, ConditionTrace)
        assert inner.branch_taken == "execute"
        assert isinstance(inner.branch_steps[0].step, ActionTrace)

    def test_action_trace_with_log_message(self):
        config = _make_config([
            {"action": {"type": "log", "log_message": "event id={{ _event.id }}"}},
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        result = engine.execute([{"id": 42}])

        et = result.trace.event_traces[0]
        action = et.steps[0].step
        assert isinstance(action, ActionTrace)
        assert action.action_type == "log"
        assert action.rendered_log_message == "event id=42"

    def test_discard_trace(self):
        config = _make_config([
            {
                "when": {"type": "equals", "value": "bad", "property": "status"},
                "execute": [{"action": "discard"}],
            },
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        result = engine.execute([{"status": "ok"}, {"status": "bad"}, {"status": "ok"}])

        assert result.discarded is True
        assert result.trace is not None
        # Should have traces for the first event (alert) and second event (discard)
        assert len(result.trace.event_traces) == 2
        assert result.trace.event_traces[0].outcome == "alert"
        assert result.trace.event_traces[1].outcome == "discard"
        # Stream-level discard event
        assert len(result.trace.stream_events) == 1
        assert result.trace.stream_events[0].event_type == "discard"
        assert result.trace.stream_events[0].at_event_index == 1

    def test_stop_trace(self):
        config = _make_config([
            {
                "when": {"type": "equals", "value": "stop_here", "property": "action"},
                "execute": [{"action": "stop"}],
            },
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        result = engine.execute([
            {"action": "continue", "id": 1},
            {"action": "stop_here", "id": 2},
            {"action": "continue", "id": 3},
        ])

        assert result.trace is not None
        traces = result.trace.event_traces
        assert len(traces) == 2
        assert traces[0].outcome == "alert"
        assert traces[1].outcome == "stop"

    def test_timeout_trace(self):
        config = _make_config([], timeout="0s")
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        # Force timeout to zero
        engine.timeout = datetime.timedelta(seconds=0)
        result = engine.execute([{"id": 1}, {"id": 2}])

        assert result.trace is not None
        assert len(result.trace.stream_events) == 1
        assert result.trace.stream_events[0].event_type == "timeout"
        assert all(et.outcome == "timeout" for et in result.trace.event_traces)

    def test_description_in_trace(self):
        config = _make_config([
            {
                "description": "Check for admin users",
                "when": {"type": "equals", "value": "admin", "property": "user"},
                "execute": [{"action": "filter"}],
            },
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        result = engine.execute([{"user": "admin"}])

        et = result.trace.event_traces[0]
        assert et.steps[0].description == "Check for admin users"

    def test_expression_trace_equals_details(self):
        """Verify that equals expression traces capture property details."""
        config = _make_config([
            {
                "when": {"type": "equals", "value": "admin", "property": "user"},
                "execute": [{"action": "filter"}],
            },
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        result = engine.execute([{"user": "guest"}])

        cond = result.trace.event_traces[0].steps[0].step
        assert isinstance(cond, ConditionTrace)
        expr = cond.expression
        assert expr.expression_type == "equals"
        assert expr.property_name == "user"
        assert expr.property_value == "guest"
        assert expr.compare_value == "admin"
        assert expr.result is False

    def test_compound_expression_trace(self):
        """Verify and/or expression traces include sub-expression details."""
        config = _make_config([
            {
                "when": {
                    "type": "and",
                    "value": [
                        {"type": "equals", "value": "admin", "property": "user"},
                        {"type": "equals", "value": "login", "property": "action"},
                    ],
                },
                "execute": [{"action": "filter"}],
            },
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        result = engine.execute([{"user": "admin", "action": "login"}])

        cond = result.trace.event_traces[0].steps[0].step
        expr = cond.expression
        assert expr.expression_type == "and"
        assert expr.result is True
        assert len(expr.sub_expressions) == 2
        assert expr.sub_expressions[0].expression_type == "equals"
        assert expr.sub_expressions[0].property_value == "admin"
        assert expr.sub_expressions[1].property_value == "login"

    def test_transform_with_property_trace(self):
        """Verify transform traces capture property name and value."""
        config = _make_config([
            {
                "transform": {
                    "type": "event",
                    "method": "property",
                    "property_name": "enriched",
                    "property_type": "str",
                    "command": {
                        "type": "executable",
                        "path": "/bin/echo",
                        "args": ["enriched_value"],
                    },
                },
            },
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        result = engine.execute([{"id": 1}])

        assert result.trace is not None
        et = result.trace.event_traces[0]
        assert len(et.steps) == 1
        transform = et.steps[0].step
        assert isinstance(transform, TransformTrace)
        assert transform.transform_type == "event"
        assert transform.method == "property"
        assert transform.command_type == "executable"
        assert transform.property_name == "enriched"
        assert "enriched_value" in transform.property_value
        assert transform.result_count == 1
        assert transform.error is None
        assert "/bin/echo enriched_value" in transform.rendered_command

    def test_transform_error_short_circuits_to_alert(self):
        """A failing transform stops step processing for the event and alerts it."""
        config = _make_config([
            {
                "transform": {
                    "type": "event",
                    "method": "property",
                    "property_name": "result",
                    "property_type": "str",
                    "command": {
                        "type": "executable",
                        "path": "/bin/false",
                    },
                },
            },
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        result = engine.execute([{"id": 1}])

        et = result.trace.event_traces[0]
        assert et.outcome == "error"
        assert result.event_actions[0].action_type == "alert"
        assert len(result.events) == 1
        transform = et.steps[0].step
        assert isinstance(transform, TransformTrace)
        assert transform.error is not None

    def test_transform_error_skips_remaining_steps(self):
        """An error stops processing — subsequent filter steps must not run."""
        config = _make_config([
            {
                "transform": {
                    "type": "event",
                    "method": "property",
                    "property_name": "result",
                    "property_type": "str",
                    "command": {
                        "type": "executable",
                        "path": "/bin/false",
                    },
                },
            },
            {"action": "filter"},
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        result = engine.execute([{"id": 1}])

        et = result.trace.event_traces[0]
        # The filter action would have produced "filter" outcome; error short-circuits first.
        assert et.outcome == "error"
        assert result.event_actions[0].action_type == "alert"
        # Only the failing transform step is recorded — the filter never ran.
        assert len(et.steps) == 1
        assert isinstance(et.steps[0].step, TransformTrace)
        assert et.steps[0].step.error is not None

    def test_condition_expression_error_short_circuits(self):
        """A condition whose expression raises short-circuits to alert."""
        config = _make_config([
            {
                "when": "{{ _event.x | bad_filter }}",
                "execute": [{"action": "filter"}],
            },
            {"action": "filter"},
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        result = engine.execute([{"x": "val"}])

        et = result.trace.event_traces[0]
        assert et.outcome == "error"
        assert result.event_actions[0].action_type == "alert"
        cond = et.steps[0].step
        assert isinstance(cond, ConditionTrace)
        assert cond.error is not None
        assert cond.expression.error is not None
        # The trailing filter step never executed.
        assert len(et.steps) == 1

    def test_nested_transform_error_surfaces_through_condition(self):
        """A transform failure inside a condition branch short-circuits the whole event."""
        config = _make_config([
            {
                "when": {"type": "equals", "value": "admin", "property": "user"},
                "execute": [
                    {
                        "transform": {
                            "type": "event",
                            "method": "property",
                            "property_name": "result",
                            "property_type": "str",
                            "command": {
                                "type": "executable",
                                "path": "/bin/false",
                            },
                        },
                    },
                    {"action": "filter"},
                ],
            },
            {"action": "filter"},
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        result = engine.execute([{"user": "admin"}])

        et = result.trace.event_traces[0]
        assert et.outcome == "error"
        assert result.event_actions[0].action_type == "alert"
        # The condition step is present at the top level with the transform error nested inside.
        assert len(et.steps) == 1
        cond = et.steps[0].step
        assert isinstance(cond, ConditionTrace)
        assert cond.branch_taken == "execute"
        # Only the failing transform inside the branch is recorded, not the filter after it.
        assert len(cond.branch_steps) == 1
        nested = cond.branch_steps[0].step
        assert isinstance(nested, TransformTrace)
        assert nested.error is not None

    def test_action_error_recorded(self):
        """An exception from execute_action is recorded and short-circuits to alert."""
        config = _make_config([
            {"action": "filter"},
            {"action": "filter"},
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        with patch(
            "saq.collectors.hunter.correlation.engine.execute_action",
            side_effect=RuntimeError("boom"),
        ):
            result = engine.execute([{"id": 1}])

        et = result.trace.event_traces[0]
        assert et.outcome == "error"
        assert result.event_actions[0].action_type == "alert"
        # Only the first (failing) action is recorded; the second never ran.
        assert len(et.steps) == 1
        action_trace = et.steps[0].step
        assert isinstance(action_trace, ActionTrace)
        assert action_trace.error == "boom"

    def test_trace_serializes_to_json(self):
        """Verify that the trace can be serialized to JSON."""
        config = _make_config([
            {
                "when": {"type": "equals", "value": "admin", "property": "user"},
                "execute": [{"action": "filter"}],
                "else": [{"action": {"type": "log", "log_message": "not admin"}}],
            },
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        result = engine.execute([{"user": "admin"}, {"user": "guest"}])

        trace_dict = result.trace.model_dump()
        assert isinstance(trace_dict, dict)
        assert "event_traces" in trace_dict
        assert "stream_events" in trace_dict
        assert len(trace_dict["event_traces"]) == 2

    def test_jinja_expression_trace_with_rendered_value(self):
        config = _make_config([
            {
                "when": "{{ _event.count | int > 5 }}",
                "execute": [{"action": "filter"}],
            },
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        result = engine.execute([{"count": "10"}])

        cond = result.trace.event_traces[0].steps[0].step
        assert isinstance(cond, ConditionTrace)
        assert cond.expression.expression_type == "jinja"
        assert cond.expression.result is True
        assert cond.expression.rendered_value == "True"


@pytest.mark.unit
class TestSecretSanitizationInTrace:

    def test_secrets_stripped_from_expression_trace(self):
        mock_raw = MagicMock()
        mock_raw._data = {}
        with patch("saq.collectors.hunter.correlation.engine.export_encrypted_passwords", return_value={"api_key": "supersecret"}), \
             patch("saq.collectors.hunter.correlation.engine.get_config", return_value=MagicMock(raw=mock_raw)):
            config = _make_config([
                {
                    "when": "{{ _secrets.api_key }}",
                    "execute": [{"action": "filter"}],
                },
            ])
            engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
            result = engine.execute([{"id": 1}])

            cond = result.trace.event_traces[0].steps[0].step
            assert "supersecret" not in (cond.expression.rendered_value or "")
            assert "***" in (cond.expression.rendered_value or "")

    def test_secrets_stripped_from_action_log_message(self):
        mock_raw = MagicMock()
        mock_raw._data = {}
        with patch("saq.collectors.hunter.correlation.engine.export_encrypted_passwords", return_value={"api_key": "supersecret"}), \
             patch("saq.collectors.hunter.correlation.engine.get_config", return_value=MagicMock(raw=mock_raw)):
            config = _make_config([
                {"action": {"type": "log", "log_message": "key={{ _secrets.api_key }}"}},
            ])
            engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
            result = engine.execute([{"id": 1}])

            action = result.trace.event_traces[0].steps[0].step
            assert isinstance(action, ActionTrace)
            assert "supersecret" not in (action.rendered_log_message or "")
            assert "***" in (action.rendered_log_message or "")
