# vim: sw=4:ts=4:et:cc=120
"""Field-lookup primitives — extract values from an event by field path.

This is distinct from template rendering (``saq/query/template_rendering.py``):
field lookup is "give me ``event[X]``" (used by ``ObservableMapping.fields``,
``required_fields``, ``dedup_fields``), template rendering is "interpolate
event data into this string" (used by ``tags``, ``pivot_links``, etc.).

Two lookup modes:

- :data:`FIELD_LOOKUP_TYPE_KEY` (default) — direct ``event[field_path]``
  lookup. Use for flat events with literal dotted keys
  (``event["device.hostname"]``).
- :data:`FIELD_LOOKUP_TYPE_DOT` — glom dotted-path traversal. Use for
  nested-dict events where ``event["device"]["hostname"]`` is the access
  pattern.
"""

from typing import List

from glom import Path, PathAccessError, glom


FIELD_LOOKUP_TYPE_KEY = "key"
FIELD_LOOKUP_TYPE_DOT = "dot"


_MISSING = object()


def extract_event_value(event: dict, lookup_type: str, field_path: str) -> tuple[bool, object]:
    """Extract ``field_path`` from ``event`` using the configured ``lookup_type``.

    Returns ``(success, value)``; ``success=False`` means the field is missing.
    """
    if lookup_type == FIELD_LOOKUP_TYPE_KEY:
        resolved_value = event.get(field_path, _MISSING)
        if resolved_value is _MISSING:
            return (False, None)
        return (True, resolved_value)

    # FIELD_LOOKUP_TYPE_DOT
    components = _build_path_components(field_path)
    if components is None:
        return (False, None)
    try:
        return (True, glom(event, Path(*components)))
    except PathAccessError:
        return (False, None)


def _build_path_components(path: str) -> List[object] | None:
    """Split ``path`` on ``.`` and coerce integer-looking segments to int indices.

    Returns ``None`` if any segment is empty or whitespace-only (so empty paths
    and stray double-dots are rejected).
    """
    components: List[object] = []
    for raw_part in path.split("."):
        part = raw_part.strip()
        if not part:
            return None
        try:
            components.append(int(part))
        except ValueError:
            components.append(part)
    return components


__all__ = [
    "FIELD_LOOKUP_TYPE_KEY",
    "FIELD_LOOKUP_TYPE_DOT",
    "extract_event_value",
]
