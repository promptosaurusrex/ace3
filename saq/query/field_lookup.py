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

A dotted path may include a ``*`` wildcard segment to iterate every item of a
list field and pluck a sub-key from each — e.g. ``logs.*.cid`` returns the
``cid`` of every dict in ``event["logs"]``. List items missing the trailing
sub-key are silently skipped; an empty list yields ``[]``; a missing top-level
list key is treated as field-not-present. ``*`` only applies to ``dot`` lookups.
"""

from glom import Coalesce, Path, PathAccessError, SKIP, T, glom


FIELD_LOOKUP_TYPE_KEY = "key"
FIELD_LOOKUP_TYPE_DOT = "dot"

WILDCARD = "*"


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
    spec = _build_glom_spec(field_path)
    if spec is None:
        return (False, None)
    try:
        return (True, glom(event, spec))
    except PathAccessError:
        return (False, None)


def _coerce(part: str) -> object:
    """Coerce an integer-looking path segment to an int index, else leave as a key."""
    try:
        return int(part)
    except ValueError:
        return part


def _build_glom_spec(path: str):
    """Build a glom spec from a dotted ``path``, supporting a ``*`` wildcard segment.

    Returns ``None`` if any segment is empty or whitespace-only (so empty paths
    and stray double-dots are rejected). A path without ``*`` produces a flat
    ``Path`` (backward compatible). A ``*`` segment becomes a branch spec that
    iterates the list and resolves the remaining path against each item, dropping
    items where it doesn't resolve.
    """
    parts: list[str] = []
    for raw_part in path.split("."):
        part = raw_part.strip()
        if not part:
            return None
        parts.append(part)
    return _spec_from_parts(parts)


def _spec_from_parts(parts: list[str]):
    """Recursively turn path segments into a glom spec, branching at each ``*``."""
    if WILDCARD not in parts:
        return Path(*[_coerce(p) for p in parts])

    idx = parts.index(WILDCARD)
    before, after = parts[:idx], parts[idx + 1:]
    inner = _spec_from_parts(after) if after else T
    # Coalesce(..., default=SKIP) drops list items that don't resolve the inner
    # spec instead of raising, so a sub-key absent from some items is non-fatal.
    branch = [Coalesce(inner, default=SKIP)]
    if before:
        return (Path(*[_coerce(p) for p in before]), branch)
    return branch


__all__ = [
    "FIELD_LOOKUP_TYPE_KEY",
    "FIELD_LOOKUP_TYPE_DOT",
    "extract_event_value",
]
