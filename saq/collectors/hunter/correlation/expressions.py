import fnmatch
import logging
import re

from jinja2.sandbox import SandboxedEnvironment

from saq.collectors.hunter.correlation.schema import ExpressionConfig

_jinja_env = SandboxedEnvironment()


def build_jinja_context(event: dict, events: list[dict]) -> dict:
    """Build a Jinja template context from event data."""
    return {**event, "_events": events}


def evaluate_expression(expr: ExpressionConfig, event: dict, events: list[dict]) -> bool:
    """Evaluate an expression against an event and event stream.

    Returns True or False based on the expression type and value.
    """
    if expr.type == "jinja":
        return _evaluate_jinja(expr, event, events)
    elif expr.type == "equals":
        return _evaluate_equals(expr, event)
    elif expr.type == "glob":
        return _evaluate_glob(expr, event)
    elif expr.type == "regex":
        return _evaluate_regex(expr, event)
    elif expr.type == "and":
        return _evaluate_and(expr, event, events)
    elif expr.type == "or":
        return _evaluate_or(expr, event, events)
    elif expr.type == "not":
        return _evaluate_not(expr, event, events)
    else:
        raise ValueError(f"unknown expression type: {expr.type!r}")


def _evaluate_jinja(expr: ExpressionConfig, event: dict, events: list[dict]) -> bool:
    context = build_jinja_context(event, events)
    try:
        template = _jinja_env.from_string(str(expr.value))
        result = template.render(**context)
        return bool(result and result.strip() and result.strip().lower() not in ("false", "0", "none", ""))
    except Exception:
        logging.error("error evaluating jinja expression: %s", expr.value, exc_info=True)
        return False


def _get_property_value(expr: ExpressionConfig, event: dict):
    """Get the property value from the event, applying case sensitivity."""
    value = event.get(expr.property)
    if value is None:
        return None
    value = str(value)
    if not expr.case_sensitive:
        value = value.lower()
    return value


def _normalize_expr_value(expr: ExpressionConfig) -> str:
    """Normalize the expression value for comparison."""
    value = str(expr.value)
    if not expr.case_sensitive:
        value = value.lower()
    return value


def _evaluate_equals(expr: ExpressionConfig, event: dict) -> bool:
    prop_value = _get_property_value(expr, event)
    if prop_value is None:
        return False
    return prop_value == _normalize_expr_value(expr)


def _evaluate_glob(expr: ExpressionConfig, event: dict) -> bool:
    prop_value = _get_property_value(expr, event)
    if prop_value is None:
        return False
    return fnmatch.fnmatch(prop_value, _normalize_expr_value(expr))


def _evaluate_regex(expr: ExpressionConfig, event: dict) -> bool:
    prop_value = _get_property_value(expr, event)
    if prop_value is None:
        return False
    flags = 0 if expr.case_sensitive else re.IGNORECASE
    return bool(re.search(str(expr.value), prop_value, flags))


def _parse_sub_expression(value) -> ExpressionConfig:
    """Parse a sub-expression value into an ExpressionConfig."""
    if isinstance(value, ExpressionConfig):
        return value
    if isinstance(value, str):
        return ExpressionConfig(type="jinja", value=value)
    if isinstance(value, dict):
        return ExpressionConfig.model_validate(value)
    raise ValueError(f"invalid sub-expression: {value!r}")


def _evaluate_and(expr: ExpressionConfig, event: dict, events: list[dict]) -> bool:
    for sub in expr.value:
        sub_expr = _parse_sub_expression(sub)
        if not evaluate_expression(sub_expr, event, events):
            return False
    return True


def _evaluate_or(expr: ExpressionConfig, event: dict, events: list[dict]) -> bool:
    for sub in expr.value:
        sub_expr = _parse_sub_expression(sub)
        if evaluate_expression(sub_expr, event, events):
            return True
    return False


def _evaluate_not(expr: ExpressionConfig, event: dict, events: list[dict]) -> bool:
    sub_expr = _parse_sub_expression(expr.value)
    return not evaluate_expression(sub_expr, event, events)
