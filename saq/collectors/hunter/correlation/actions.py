import logging
from dataclasses import dataclass
from typing import Optional

from jinja2.sandbox import SandboxedEnvironment

from saq.collectors.hunter.correlation.expressions import build_jinja_context
from saq.collectors.hunter.correlation.schema import ActionConfig

_jinja_env = SandboxedEnvironment()


@dataclass
class ActionResult:
    """Result of executing an action."""
    action_type: str  # filter, stop, discard, alert, log, continue
    queue_override: Optional[str] = None
    analysis_mode_override: Optional[str] = None

    @property
    def is_interrupt(self) -> bool:
        """Returns True if this action interrupts event processing."""
        return self.action_type in ("filter", "stop", "discard", "alert")

    @property
    def is_stream_interrupt(self) -> bool:
        """Returns True if this action stops the entire stream."""
        return self.action_type in ("stop", "discard")


def execute_action(
    action: ActionConfig,
    event: dict,
    events: list[dict],
    secrets: dict | None = None,
    config: dict | None = None,
) -> ActionResult:
    """Execute an action and return the result."""
    if action.type == "filter":
        return ActionResult(action_type="filter")
    elif action.type == "stop":
        return ActionResult(action_type="stop")
    elif action.type == "discard":
        return ActionResult(action_type="discard")
    elif action.type == "alert":
        return ActionResult(
            action_type="alert",
            queue_override=action.queue,
            analysis_mode_override=action.analysis_mode,
        )
    elif action.type == "log":
        _execute_log(action, event, events, secrets, config)
        return ActionResult(action_type="log")
    else:
        raise ValueError(f"unknown action type: {action.type!r}")


def _execute_log(
    action: ActionConfig,
    event: dict,
    events: list[dict],
    secrets: dict | None = None,
    config: dict | None = None,
):
    """Execute a log action."""
    context = build_jinja_context(event, events, secrets, config)
    try:
        message = _jinja_env.from_string(action.message).render(**context)
    except Exception:
        logging.error("failed to render log message template: %s", action.message, exc_info=True)
        return

    level = getattr(logging, action.level.upper(), logging.INFO)
    logging.log(level, "correlation log: %s", message)
