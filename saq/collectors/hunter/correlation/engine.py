import datetime
import logging
import tempfile
from dataclasses import dataclass, field
from typing import Optional

from jinja2.sandbox import SandboxedEnvironment

from saq.collectors.hunter.correlation.actions import ActionResult, execute_action
from saq.collectors.hunter.correlation.commands import execute_command
from saq.configuration.config import get_config
from saq.configuration.encryption import export_encrypted_passwords
from saq.collectors.hunter.correlation.expressions import build_jinja_context, evaluate_expression
from saq.collectors.hunter.correlation.schema import (
    ActionConfig,
    ConditionConfig,
    CorrelateConfig,
    PredefinedCommandConfig,
    StepConfig,
    TransformConfig,
)
from saq.collectors.hunter.correlation.timespec import parse_timespec
from saq.collectors.hunter.correlation.transforms import apply_transform

_jinja_env = SandboxedEnvironment()


class _StreamReset(Exception):
    """Internal signal that a stream transform occurred."""
    def __init__(self, new_stream: list[dict], resume_step_index: int):
        self.new_stream = new_stream
        self.resume_step_index = resume_step_index


@dataclass
class CorrelationResult:
    """Result of running correlation on an event stream."""
    events: list[dict] = field(default_factory=list)
    event_actions: dict[int, ActionResult] = field(default_factory=dict)
    discarded: bool = False


class CorrelationEngine:
    """Main correlation engine that orchestrates expressions, transforms, and actions."""

    def __init__(
        self,
        correlate_config: CorrelateConfig,
        predefined_commands: list[PredefinedCommandConfig],
        hunt_time: datetime.datetime,
        max_result_count: Optional[int] = None,
    ):
        self.config = correlate_config
        self.predefined_commands = predefined_commands or []
        self.hunt_time = hunt_time
        self.max_result_count = max_result_count
        self.timeout = parse_timespec(correlate_config.timeout)
        self.stream_query_cache: dict[str, str] = {}

    def execute(self, events: list[dict]) -> CorrelationResult:
        """Execute correlation logic on the event stream."""
        # Fetch secrets and config once per execution
        try:
            self._secrets = export_encrypted_passwords()
        except Exception:
            logging.error("unable to load secrets for correlation context", exc_info=True)
            self._secrets = {}

        try:
            self._config = get_config().raw._data
        except Exception:
            logging.error("unable to load config for correlation context", exc_info=True)
            self._config = {}

        result = CorrelationResult()
        start_time = datetime.datetime.now(datetime.timezone.utc)
        alert_events = []
        event_index = 0
        # When a stream transform resets the stream, we skip steps before this index
        start_step_index = 0

        while event_index < len(events):
            elapsed = datetime.datetime.now(datetime.timezone.utc) - start_time
            if elapsed >= self.timeout:
                logging.warning("correlation timeout reached after %s, remaining events will fall through to alert", elapsed)
                for i in range(event_index, len(events)):
                    alert_events.append((i, events[i]))
                    result.event_actions[i] = ActionResult(action_type="alert")
                break

            event = events[event_index]

            try:
                action_result = self._process_event_steps(
                    self.config.logic, event, events, event_index, start_time, start_step_index
                )
            except _StreamReset as sr:
                events = sr.new_stream
                event_index = 0
                start_step_index = sr.resume_step_index
                # Clear accumulated alerts since stream changed
                alert_events = []
                result.event_actions = {}
                continue

            if action_result is None:
                action_result = ActionResult(action_type="alert")

            if action_result.action_type == "alert":
                alert_events.append((event_index, event))
                result.event_actions[event_index] = action_result
            elif action_result.action_type == "filter":
                pass
            elif action_result.action_type == "stop":
                break
            elif action_result.action_type == "discard":
                result.discarded = True
                return result
            elif action_result.action_type == "log":
                alert_events.append((event_index, event))
                result.event_actions[event_index] = ActionResult(action_type="alert")

            event_index += 1

        result.events = [event for _, event in alert_events]
        return result

    def _process_event_steps(
        self,
        steps: list[StepConfig],
        event: dict,
        events: list[dict],
        event_index: int,
        start_time: datetime.datetime,
        start_step_index: int = 0,
    ) -> Optional[ActionResult]:
        """Process an event through a list of steps.

        Returns an ActionResult if an interrupt occurred, None otherwise.
        Raises _StreamReset if a stream transform replaces the event stream.
        """
        for step_idx in range(start_step_index, len(steps)):
            step = steps[step_idx]

            elapsed = datetime.datetime.now(datetime.timezone.utc) - start_time
            if elapsed >= self.timeout:
                return None

            if step.debug:
                self._render_debug(step.debug, event, events)

            if isinstance(step.step, ConditionConfig):
                action_result = self._execute_condition(
                    step.step, event, events, event_index, start_time
                )
                if action_result is not None and action_result.is_interrupt:
                    return action_result

            elif isinstance(step.step, TransformConfig):
                action_result = self._execute_transform(
                    step.step, event, events, event_index, step_idx
                )
                if action_result is not None and action_result.is_interrupt:
                    return action_result
                # Note: if _StreamReset is raised, it propagates up

            elif isinstance(step.step, ActionConfig):
                action_result = execute_action(step.step, event, events, self._secrets, self._config)
                if action_result.is_interrupt:
                    return action_result

        return None

    def _execute_condition(
        self,
        condition: ConditionConfig,
        event: dict,
        events: list[dict],
        event_index: int,
        start_time: datetime.datetime,
    ) -> Optional[ActionResult]:
        """Execute a condition step."""
        expr_result = evaluate_expression(condition.when, event, events, self._secrets, self._config)

        if expr_result:
            return self._process_event_steps(
                condition.execute, event, events, event_index, start_time
            )
        elif condition.else_:
            return self._process_event_steps(
                condition.else_, event, events, event_index, start_time
            )

        return None

    def _execute_transform(
        self,
        transform: TransformConfig,
        event: dict,
        events: list[dict],
        event_index: int,
        current_step_index: int,
    ) -> Optional[ActionResult]:
        """Execute a transform step.

        Returns ActionResult if on_error produced an interrupt.
        Raises _StreamReset if a stream transform succeeded.
        """
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                output = execute_command(
                    transform.command,
                    event,
                    events,
                    transform.type,
                    self.predefined_commands,
                    self.hunt_time,
                    temp_dir,
                    self.stream_query_cache,
                    self._secrets,
                    self._config,
                )

            updated_event, new_stream = apply_transform(transform, output, event, events)

            if new_stream is not None:
                # Stream transform - signal reset, resume at next step
                raise _StreamReset(new_stream, current_step_index + 1)
            elif updated_event is not None:
                events[event_index] = updated_event

            return None

        except _StreamReset:
            raise  # Re-raise stream reset signals
        except Exception as e:
            logging.error("error executing transform command: %s", e, exc_info=True)

            if transform.command.on_error:
                for action_data in transform.command.on_error:
                    action = ActionConfig.model_validate(action_data)
                    action_result = execute_action(action, event, events, self._secrets, self._config)
                    if action_result.is_interrupt:
                        return action_result
            return None

    def _render_debug(self, template: str, event: dict, events: list[dict]):
        """Render and log a debug message."""
        try:
            context = build_jinja_context(event, events, self._secrets, self._config)
            message = _jinja_env.from_string(template).render(**context)
            logging.debug("correlation debug: %s", message)
        except Exception:
            logging.debug("failed to render debug template: %s", template, exc_info=True)
