import datetime
import json
import logging
import subprocess
from typing import Optional

from jinja2.sandbox import SandboxedEnvironment

from saq.collectors.hunter.correlation.cache import get_cached_result, set_cached_result
from saq.collectors.hunter.correlation.expressions import build_jinja_context
from saq.collectors.hunter.correlation.registry import get_query_source
from saq.collectors.hunter.correlation.schema import CommandConfig, PredefinedCommandConfig
from saq.collectors.hunter.correlation.timespec import parse_timespec

_jinja_env = SandboxedEnvironment()


def execute_command(
    command: CommandConfig,
    event: dict,
    events: list[dict],
    transform_type: str,
    predefined_commands: list[PredefinedCommandConfig],
    hunt_time: datetime.datetime,
    temp_dir: str,
    stream_query_cache: Optional[dict] = None,
) -> str:
    """Execute a command and return its output as a string.

    Args:
        command: The command configuration to execute.
        event: The current event being processed.
        events: The full event stream.
        transform_type: Either 'event' or 'stream'.
        predefined_commands: List of predefined commands.
        hunt_time: The time the hunt was executed.
        temp_dir: Temporary directory for command execution.
        stream_query_cache: Cache for stream query results (memoization within a correlation run).

    Returns:
        Command output as a string.
    """
    if command.type == "defined":
        return _execute_defined(command, event, events, transform_type, predefined_commands, hunt_time, temp_dir, stream_query_cache)
    elif command.type == "query":
        return _execute_query(command, event, events, transform_type, hunt_time, stream_query_cache)
    elif command.type == "executable":
        return _execute_executable(command, event, events, transform_type, temp_dir)
    else:
        raise ValueError(f"unknown command type: {command.type!r}")


def _execute_defined(
    command: CommandConfig,
    event: dict,
    events: list[dict],
    transform_type: str,
    predefined_commands: list[PredefinedCommandConfig],
    hunt_time: datetime.datetime,
    temp_dir: str,
    stream_query_cache: Optional[dict],
) -> str:
    """Execute a predefined command by name."""
    predef = None
    for cmd in predefined_commands:
        if cmd.name == command.name:
            predef = cmd
            break

    if predef is None:
        raise ValueError(f"predefined command not found: {command.name!r}")

    resolved = predef.to_command_config(command.arguments)
    return execute_command(resolved, event, events, transform_type, predefined_commands, hunt_time, temp_dir, stream_query_cache)


def _execute_query(
    command: CommandConfig,
    event: dict,
    events: list[dict],
    transform_type: str,
    hunt_time: datetime.datetime,
    stream_query_cache: Optional[dict],
) -> str:
    """Execute a query command."""
    # For stream transforms, memoize the result
    if transform_type == "stream" and stream_query_cache is not None:
        cache_key = f"query:{command.source}:{command.query}"
        if cache_key in stream_query_cache:
            return stream_query_cache[cache_key]

    # Check persistent cache
    if command.cache:
        cache_args = {"type": "query", "source": command.source, "query": command.query}
        cached = get_cached_result(cache_args)
        if cached is not None:
            return cached

    # Build time range
    start_time, end_time = _resolve_time_range(command, event, transform_type, hunt_time)

    # Render query with jinja
    context = build_jinja_context(event, events)
    query_str = _jinja_env.from_string(command.query).render(**context)

    timeout = parse_timespec(command.timeout)

    source = get_query_source(command.source)
    results = source.execute_query(query_str, start_time, end_time, timeout)

    output = "\n".join(json.dumps(row) for row in results)

    # Store in persistent cache
    if command.cache:
        ttl = int(parse_timespec(command.cache).total_seconds())
        cache_args = {"type": "query", "source": command.source, "query": command.query}
        set_cached_result(cache_args, output, ttl)

    # Store in stream query cache
    if transform_type == "stream" and stream_query_cache is not None:
        cache_key = f"query:{command.source}:{command.query}"
        stream_query_cache[cache_key] = output

    return output


def _resolve_time_range(
    command: CommandConfig,
    event: dict,
    transform_type: str,
    hunt_time: datetime.datetime,
) -> tuple[datetime.datetime, datetime.datetime]:
    """Resolve the time range for a query command."""
    reference_time = hunt_time

    if transform_type == "event" and command.time_range and command.time_range.relative_time_field:
        field_value = event.get(command.time_range.relative_time_field)
        if field_value is not None:
            reference_time = _parse_time_value(field_value, command.time_range.relative_time_format)

    before = parse_timespec(command.time_range.before) if command.time_range and command.time_range.before else datetime.timedelta(0)
    after = parse_timespec(command.time_range.after) if command.time_range and command.time_range.after else datetime.timedelta(0)

    start_time = reference_time - before
    end_time = reference_time + after

    return start_time, end_time


def _parse_time_value(value, format_str: Optional[str] = None) -> datetime.datetime:
    """Parse a time value based on the format string."""
    if format_str == "epoch":
        return datetime.datetime.fromtimestamp(float(value), tz=datetime.timezone.utc)
    elif format_str == "epoch_ms":
        return datetime.datetime.fromtimestamp(float(value) / 1000, tz=datetime.timezone.utc)
    elif format_str == "epoch_ns":
        return datetime.datetime.fromtimestamp(float(value) / 1_000_000_000, tz=datetime.timezone.utc)
    elif format_str == "iso8601":
        return datetime.datetime.fromisoformat(str(value))
    elif format_str:
        return datetime.datetime.strptime(str(value), format_str)
    else:
        return datetime.datetime.fromisoformat(str(value))


def _execute_executable(
    command: CommandConfig,
    event: dict,
    events: list[dict],
    transform_type: str,
    temp_dir: str,
) -> str:
    """Execute an executable command."""
    context = build_jinja_context(event, events)
    timeout = parse_timespec(command.timeout)

    # Build args with jinja interpolation
    args = [command.path]
    if command.args:
        for arg in command.args:
            rendered = _jinja_env.from_string(arg).render(**context)
            args.append(rendered)

    # Prepare stdin
    stdin_data = None
    if transform_type == "stream":
        # Stream transform: pass all events as JSONL
        stdin_data = "\n".join(json.dumps(e) for e in events)
    elif command.stdin:
        # Event transform with stdin enabled
        stdin_data = json.dumps(event)

    try:
        result = subprocess.run(
            args,
            cwd=temp_dir,
            timeout=timeout.total_seconds(),
            capture_output=True,
            text=True,
            input=stdin_data,
        )
        if result.returncode != 0:
            raise RuntimeError(f"command exited with code {result.returncode}: {result.stderr}")
        return result.stdout
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"command timed out after {timeout}")
