import json
import logging
from typing import Optional

from saq.collectors.hunter.correlation.schema import TransformConfig, MergeTimeSpecConfig
from saq.collectors.hunter.correlation.commands import _parse_time_value


def apply_transform(
    transform: TransformConfig,
    command_output: str,
    event: dict,
    events: list[dict],
) -> tuple[Optional[dict], Optional[list[dict]], Optional[int]]:
    """Apply a transform to an event or event stream.

    Returns:
        (updated_event, updated_stream, merge_dropped) - the first two are mutually
        exclusive depending on type.
        For event transforms: returns (updated_event, None, None)
        For stream transforms: returns (None, new_stream, merge_dropped)
        merge_dropped is the count of incoming events discarded by a merge for a
        missing/unparseable timestamp; it is None for event and mutate transforms.
    """
    if transform.type == "event":
        updated_event = _apply_event_transform(transform, command_output, event)
        return updated_event, None, None
    else:
        new_stream, merge_dropped = _apply_stream_transform(transform, command_output, events)
        return None, new_stream, merge_dropped


def _apply_event_transform(
    transform: TransformConfig,
    command_output: str,
    event: dict,
) -> dict:
    """Apply an event transform (property method)."""
    if transform.method != "property":
        raise ValueError(f"invalid event transform method: {transform.method}")

    value = _parse_property_value(command_output, transform.property_type)
    event[transform.property_name] = value
    return event


def _parse_property_value(output: str, property_type: str):
    """Parse command output according to the property_type."""
    if property_type == "list":
        # JSONL -> list of dicts
        result = []
        for line in output.strip().splitlines():
            line = line.strip()
            if line:
                result.append(json.loads(line))
        return result
    elif property_type == "dict":
        return json.loads(output)
    elif property_type == "int":
        return int(output.strip())
    elif property_type == "float":
        return float(output.strip())
    elif property_type == "bool":
        return output.strip().lower() in ("true", "1", "yes")
    else:
        # default to str
        return output.strip()


def _apply_stream_transform(
    transform: TransformConfig,
    command_output: str,
    events: list[dict],
) -> tuple[list[dict], Optional[int]]:
    """Apply a stream transform (merge or mutate).

    Returns (new_stream, merge_dropped). merge_dropped is None for mutate.
    """
    if transform.method == "mutate":
        return _apply_mutate(command_output), None
    elif transform.method == "merge":
        return _apply_merge(command_output, events, transform.merge_time_spec)
    else:
        raise ValueError(f"invalid stream transform method: {transform.method}")


def _apply_mutate(command_output: str) -> list[dict]:
    """Replace the entire stream with JSONL output."""
    result = []
    for line in command_output.strip().splitlines():
        line = line.strip()
        if line:
            result.append(json.loads(line))
    return result


def _apply_merge(
    command_output: str,
    existing_events: list[dict],
    merge_time_spec: MergeTimeSpecConfig,
) -> tuple[list[dict], int]:
    """Merge new events into existing events by timestamp.

    Returns (merged_stream, dropped) where dropped is the count of incoming
    events discarded because their timestamp field was missing or unparseable.
    """
    new_events = []
    dropped = 0

    for line in command_output.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        event = json.loads(line)
        if merge_time_spec.r_field not in event:
            dropped += 1
            continue
        new_events.append(event)

    if dropped > 0:
        logging.warning("dropped %s events during merge due to missing timestamp field '%s'", dropped, merge_time_spec.r_field)

    # Parse timestamps for existing events
    existing_with_times = []
    for e in existing_events:
        ts = None
        if merge_time_spec.l_field in e:
            try:
                ts = _parse_time_value(e[merge_time_spec.l_field], merge_time_spec.l_format)
            except Exception:
                pass
        existing_with_times.append((ts, e))

    # Parse timestamps for new events
    new_with_times = []
    for e in new_events:
        try:
            ts = _parse_time_value(e[merge_time_spec.r_field], merge_time_spec.r_format)
        except Exception:
            dropped += 1
            continue
        new_with_times.append((ts, e))

    # Merge by time - existing events first for same timestamp
    all_events = [(ts, "existing", e) for ts, e in existing_with_times if ts is not None]
    all_events += [(ts, "new", e) for ts, e in new_with_times]

    # Sort by timestamp, with existing before new for ties
    all_events.sort(key=lambda x: (x[0], 0 if x[1] == "existing" else 1))

    # Add back existing events without timestamps at the beginning
    result = [e for ts, e in existing_with_times if ts is None]
    result += [e for _, _, e in all_events]

    return result, dropped
