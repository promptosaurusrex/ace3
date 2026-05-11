import datetime
import json
import os
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
    secrets: dict | None = None,
    config: dict | None = None,
    current_source: Optional[str] = None,
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
        secrets: Decrypted secrets dict for jinja context.
        config: Configuration dict for jinja context.
        current_source: Name of the source that produced the current event stream;
            used to supply default `relative_time_field`/`relative_time_format` when
            the YAML omits them.

    Returns:
        Command output as a string.
    """
    if command.type == "defined":
        return _execute_defined(command, event, events, transform_type, predefined_commands, hunt_time, temp_dir, stream_query_cache, secrets, config, current_source)
    elif command.type == "query":
        return _execute_query(command, event, events, transform_type, hunt_time, stream_query_cache, secrets, config, current_source)
    elif command.type == "executable":
        return _execute_executable(command, event, events, transform_type, temp_dir, secrets, config)
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
    secrets: dict | None = None,
    config: dict | None = None,
    current_source: Optional[str] = None,
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
    return execute_command(resolved, event, events, transform_type, predefined_commands, hunt_time, temp_dir, stream_query_cache, secrets, config, current_source)


def _execute_query(
    command: CommandConfig,
    event: dict,
    events: list[dict],
    transform_type: str,
    hunt_time: datetime.datetime,
    stream_query_cache: Optional[dict],
    secrets: dict | None = None,
    config: dict | None = None,
    current_source: Optional[str] = None,
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
    start_time, end_time = _resolve_time_range(command, event, transform_type, hunt_time, current_source)

    # Render query with jinja
    context = build_jinja_context(event, events, secrets, config)
    query_str = _jinja_env.from_string(command.query).render(**context)

    timeout = parse_timespec(command.timeout)

    source = get_query_source(command.source)
    results = source.execute_query(query_str, start_time, end_time, timeout, source_options=command.source_options)

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
    current_source: Optional[str] = None,
) -> tuple[datetime.datetime, datetime.datetime]:
    """Resolve the time range for a query command.

    Field/format resolution precedence:
      - explicit value on `command.time_range` -> default from `current_source`
      - QuerySource (if registered) -> None.

    For event transforms, when a field is resolved (explicit or default) the
    event must contain that key; otherwise a KeyError is raised so the failure
    surfaces as a step error and the affected event short-circuits to alert.

    For stream transforms, or when no field can be resolved, the reference time
    falls back to `hunt_time`.
    """
    reference_time = hunt_time

    field, fmt = _resolve_time_field_and_format(command, current_source)

    if transform_type == "event" and field is not None:
        if field not in event:
            raise KeyError(
                f"event missing time field {field} required by query time_range "
                f"(source={current_source})"
            )
        reference_time = _parse_time_value(event[field], fmt)

    before = parse_timespec(command.time_range.before) if command.time_range and command.time_range.before else datetime.timedelta(0)
    after = parse_timespec(command.time_range.after) if command.time_range and command.time_range.after else datetime.timedelta(0)

    start_time = reference_time - before
    end_time = reference_time + after

    return start_time, end_time


def _resolve_time_field_and_format(
    command: CommandConfig,
    current_source: Optional[str],
) -> tuple[Optional[str], Optional[str]]:
    """Resolve relative_time_field and relative_time_format using source defaults."""
    explicit_field = command.time_range.relative_time_field if command.time_range else None
    explicit_format = command.time_range.relative_time_format if command.time_range else None

    if explicit_field is not None and explicit_format is not None:
        return explicit_field, explicit_format

    source_default_field = None
    source_default_format = None
    if current_source is not None:
        try:
            source = get_query_source(current_source)
        except ValueError:
            source = None
        if source is not None:
            source_default_field = getattr(source, "default_time_field", None)
            source_default_format = getattr(source, "default_time_format", None)

    field = explicit_field if explicit_field is not None else source_default_field
    fmt = explicit_format if explicit_format is not None else source_default_format

    return field, fmt


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
    secrets: dict | None = None,
    config: dict | None = None,
) -> str:
    """Execute an executable command."""
    context = build_jinja_context(event, events, secrets, config)
    timeout = parse_timespec(command.timeout)

    # Build args with jinja interpolation
    rendered_args = []
    if command.args:
        for arg in command.args:
            rendered_args.append(_jinja_env.from_string(arg).render(**context))

    args = [command.path] + rendered_args

    # Build environment variables with jinja interpolation
    rendered_env = None
    env_vars = None
    if command.env:
        rendered_env = {}
        env_vars = dict(os.environ)
        for key, value in command.env.items():
            rendered_env[key] = _jinja_env.from_string(value).render(**context)
            env_vars[key] = rendered_env[key]

    # Check persistent cache
    if command.cache:
        cache_args = {"type": "executable", "path": command.path, "args": rendered_args, "env": rendered_env}
        cached = get_cached_result(cache_args)
        if cached is not None:
            return cached

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
            env=env_vars,
        )
        if result.returncode != 0:
            raise RuntimeError(f"command exited with code {result.returncode}: {result.stderr}")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"command timed out after {timeout}")

    # Store in persistent cache
    if command.cache:
        ttl = int(parse_timespec(command.cache).total_seconds())
        cache_args = {"type": "executable", "path": command.path, "args": rendered_args, "env": rendered_env}
        set_cached_result(cache_args, result.stdout, ttl)

    return result.stdout
