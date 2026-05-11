#
# in hunt definitions you can use a special syntax to interpolate event data into the results
# the syntax is $TYPE{LOOKUP} where TYPE is the style of interpolation to use
# and LOOKUP is some kind of key to use to lookup the value in the event data
#
# TYPE is OPTIONAL and supports the following values:
# - key: the LOOKUP is used as a key to lookup the value in the event data
# - dot: the LOOKUP is treated as a dotted string path to access the field in the event data (using the glom library)
# 
# if not specified, the default for TYPE is "key"
#
# If LOOKUP needs to contain a literal { or } character, then it must be escaped using a backslash
#
# Examples:
#
# - ${field_name} -> equivalent to event[field_name]
# - $key{field_name} -> same as above
# - $dot{device.hostname} -> equivalent to event["device"]["hostname"]
# - $dot{device.hostname}@${file_path} -> equivalent to event["device"]["hostname"] + "@" + event["file_path"]
# - $key{device.hostname}@${file_path} -> equivalent to event["device.hostname"] + "@" + event["file_path"]
# 

import re
from typing import List

from glom import Path, PathAccessError, glom

# pattern to match $TYPE{LOOKUP} or ${LOOKUP}
_FIELD_PATTERN = re.compile(r"\$(?:([a-z]+))?\{((?:\\.|[^\\}])*)\}")

FIELD_LOOKUP_TYPE_KEY = "key"
FIELD_LOOKUP_TYPE_DOT = "dot"


def contains_unresolved_placeholders(value: str) -> bool:
    """Returns True if the value contains unresolved ${...} placeholder patterns."""
    return bool(_FIELD_PATTERN.search(value))


def parse_field_reference(field_spec: str) -> tuple[str, str]:
    """Parse a field reference that may use $dot{path} or $key{name} syntax, or a plain key name.

    Returns (lookup_type, field_path).
    """
    m = _FIELD_PATTERN.fullmatch(field_spec)
    if m:
        lookup_type = m.group(1) or FIELD_LOOKUP_TYPE_KEY
        field_path = _unescape_lookup_value(m.group(2).strip())
        return (lookup_type, field_path)
    # plain key name
    return (FIELD_LOOKUP_TYPE_KEY, field_spec)


def strip_unresolved_placeholders(value: str) -> str:
    """Replace any remaining ${...} patterns with empty string."""
    return _FIELD_PATTERN.sub("", value)


def _unescape_lookup_value(field_path: str) -> str:
    """Converts escaped brace characters back to their literal form."""
    if "\\" not in field_path:
        return field_path

    return (
        field_path.replace("\\{", "{")
        .replace("\\}", "}")
    )

def _build_path_components(path: str) -> List[object] | None:
    """Converts the dotted string path into glom Path components."""
    components: List[object] = []
    for raw_part in path.split("."):
        part = raw_part.strip()
        if not part:
            return None

        try:
            index = int(part)
        except ValueError:
            components.append(part)
        else:
            components.append(index)

    return components


def extract_event_value(event: dict, lookup_type: str, field_path: str) -> tuple[bool, object]:
    """Extracts a value from the event data based on the lookup type and field path.

    Args:
        event: the event dictionary to extract from
        lookup_type: the type of lookup to perform (FIELD_LOOKUP_TYPE_KEY or FIELD_LOOKUP_TYPE_DOT)
        field_path: the path to the field to extract

    Returns:
        tuple of (success, value) where success is True if the value was found, False otherwise
    """
    if lookup_type == FIELD_LOOKUP_TYPE_KEY:
        # direct key lookup: event[field_path]
        # use a sentinel to distinguish between None value and missing key
        _MISSING = object()
        resolved_value = event.get(field_path, _MISSING)
        if resolved_value is _MISSING:
            return (False, None)
        return (True, resolved_value)
    else:  # lookup_type == FIELD_LOOKUP_TYPE_DOT
        # dotted path lookup using glom
        components = _build_path_components(field_path)
        if components is None:
            return (False, None)

        try:
            resolved_value = glom(event, Path(*components))
        except PathAccessError:
            return (False, None)

        return (True, resolved_value)


def interpolate_event_value(value: str, event: dict) -> list[str]:
    """Interpolates event data into the given value.

    Delegates to ``interpolate_event_values`` so that multiple references to the
    same field within the template stay paired (e.g. ``${a}-${a}`` with
    ``a=["x","y"]`` yields ``["x-x","y-y"]``, not the cartesian product).
    References to *different* fields still expand as a cartesian product.
    """
    return [row[0] for row in interpolate_event_values([value], event)]


def interpolate_event_values(templates: list[str], event: dict) -> list[list[str]]:
    """Interpolates event data into a list of templates, pairing same-field refs.

    Returns ``list[list[str]]`` where each inner list has one entry per input
    template, aligned positionally. References to the same field (canonicalized
    as ``(lookup_type, field_path)``) — within one template or across templates —
    share the same iteration index, so they always resolve to the same value.
    References to different fields are combined via cartesian product, matching
    the historical single-template behavior.

    Edge cases:
    - Missing field: keep the original ``${...}`` text in templates that
      reference it; do not affect other templates.
    - Resolved ``None``: rendered as empty string.
    - Resolved empty list: short-circuits to ``[]``.
    - Scalar values act as length-1 axes.
    """
    assert isinstance(templates, list)
    assert isinstance(event, dict)

    # Parsed segments per template. Each segment is one of:
    #   ("literal", text)        - literal text or an unresolved placeholder
    #                              kept verbatim
    #   ("field", field_id)      - reference to a resolved field, looked up by
    #                              the index assigned to that field
    template_segments: list[list[tuple]] = []

    # Maps (lookup_type, field_path) -> field_id (0-indexed).
    field_ids: dict[tuple[str, str], int] = {}
    # field_id -> list of string options (length 1 for scalars; N for lists).
    field_values: list[list[str]] = []

    for template in templates:
        assert isinstance(template, str)
        segments: list[tuple] = []
        last_index = 0

        for match in _FIELD_PATTERN.finditer(template):
            if match.start() > last_index:
                segments.append(("literal", template[last_index : match.start()]))

            raw_lookup_type = match.group(1)
            raw_field_path = match.group(2).strip()
            literal_passthrough = ("literal", match.group(0))

            if not raw_field_path:
                segments.append(literal_passthrough)
                last_index = match.end()
                continue

            field_path = _unescape_lookup_value(raw_field_path)
            lookup_type = raw_lookup_type or FIELD_LOOKUP_TYPE_KEY

            if lookup_type not in (FIELD_LOOKUP_TYPE_KEY, FIELD_LOOKUP_TYPE_DOT):
                segments.append(literal_passthrough)
                last_index = match.end()
                continue

            key = (lookup_type, field_path)
            if key in field_ids:
                segments.append(("field", field_ids[key]))
                last_index = match.end()
                continue

            success, resolved_value = extract_event_value(event, lookup_type, field_path)
            if not success:
                segments.append(literal_passthrough)
                last_index = match.end()
                continue

            if resolved_value is None:
                options = [""]
            elif isinstance(resolved_value, list):
                if not resolved_value:
                    return []
                options = [
                    "" if item is None else str(item) for item in resolved_value
                ]
            else:
                options = [str(resolved_value)]

            field_id = len(field_values)
            field_ids[key] = field_id
            field_values.append(options)
            segments.append(("field", field_id))
            last_index = match.end()

        if last_index < len(template):
            segments.append(("literal", template[last_index:]))

        template_segments.append(segments)

    def render(segments: list[tuple], indices: tuple[int, ...]) -> str:
        parts: list[str] = []
        for segment in segments:
            if segment[0] == "literal":
                parts.append(segment[1])
            else:
                parts.append(field_values[segment[1]][indices[segment[1]]])
        return "".join(parts)

    if not field_values:
        return [[render(segments, ()) for segments in template_segments]]

    results: list[list[str]] = []
    indices = [0] * len(field_values)
    while True:
        results.append(
            [render(segments, tuple(indices)) for segments in template_segments]
        )
        # Increment indices like an odometer (rightmost field varies fastest).
        carry = len(indices) - 1
        while carry >= 0:
            indices[carry] += 1
            if indices[carry] < len(field_values[carry]):
                break
            indices[carry] = 0
            carry -= 1
        if carry < 0:
            break

    return results