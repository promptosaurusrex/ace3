from typing import Any


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Deeply merges two dictionaries.

    For each key in override:
    - If the value is a simple value (not dict or list), it replaces the base value
    - If the value is a list, new items are added to the base list, avoiding duplicates
    - If the value is a dict, it recursively merges with the base dict

    Args:
        base: The base dictionary to merge into
        override: The dictionary whose values will override/extend the base

    Returns:
        The merged dictionary
    """
    result = base.copy()

    for key, value in override.items():
        if key not in result:
            result[key] = value
        elif isinstance(value, dict) and isinstance(result[key], dict):
            result[key] = deep_merge(result[key], value)
        elif isinstance(value, list) and isinstance(result[key], list):
            for item in value:
                if item not in result[key]:
                    result[key].append(item)
        else:
            result[key] = value

    return result
