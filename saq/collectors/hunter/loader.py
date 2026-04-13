import logging
import os
from typing import TYPE_CHECKING, Any, Type

import yaml

if TYPE_CHECKING:
    from saq.collectors.hunter.base_hunter import HuntConfig

INCLUDE_DIRECTIVE = "include"


def _get_observable_mapping_identity(item: Any) -> tuple[str, frozenset[str]] | None:
    """Returns a hashable identity for observable mapping dicts, or None.

    Identity is (type, frozenset(fields)) where fields is normalized from
    either the 'fields' list or the singular 'field' string. When both are
    present, 'fields' takes precedence (matching Pydantic validation behavior).
    """
    if not isinstance(item, dict) or "type" not in item:
        return None
    fields = item.get("fields")
    if not fields:
        field = item.get("field")
        if field:
            fields = [field]
        else:
            return None
    return (item["type"], frozenset(fields))


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
            # key doesn't exist in base, just add it
            result[key] = value
        elif isinstance(value, dict) and isinstance(result[key], dict):
            # both are dicts, recursively merge
            result[key] = deep_merge(result[key], value)
        elif isinstance(value, list) and isinstance(result[key], list):
            # copy the list to avoid mutating the original base dict's list
            result[key] = list(result[key])
            # build identity map for observable mapping entries in the base list
            identity_map: dict[tuple[str, frozenset[str]], int] = {}
            for i, existing in enumerate(result[key]):
                identity = _get_observable_mapping_identity(existing)
                if identity is not None:
                    identity_map[identity] = i
            # merge override items
            for item in value:
                identity = _get_observable_mapping_identity(item)
                if identity is not None and identity in identity_map:
                    # replace matching observable mapping entry in place
                    result[key][identity_map[identity]] = item
                elif item not in result[key]:
                    result[key].append(item)
        else:
            # simple value or type mismatch, override
            result[key] = value

    return result

def _load_and_merge_yaml(path: str, resolved_history: set[str]) -> dict[str, Any]:
    """Recursively loads and merges a YAML file with its includes.

    Args:
        path: the path to the YAML file to load
        resolved_history: set of already resolved file paths to prevent circular references

    Returns:
        The merged dictionary from this file and all its includes
    """
    logging.debug(f"loading {path}")

    try:
        with open(path, "r") as fp:
            loaded_dict = yaml.safe_load(fp)
    except Exception as e:
        logging.error(f"unable to load file {path}: {e}")
        raise

    # start with empty result
    result: dict[str, Any] = {}

    # are there any include directives?
    if INCLUDE_DIRECTIVE in loaded_dict:
        # include directives must be a list of strings
        if not isinstance(loaded_dict[INCLUDE_DIRECTIVE], list):
            raise ValueError(f"include directives must be a list of strings in {path}")

        # process includes in order
        for include_path in loaded_dict[INCLUDE_DIRECTIVE]:
            # paths that are relative are relative to the current file
            if not os.path.isabs(include_path):
                include_path = os.path.join(os.path.dirname(path), include_path)

            # skip if we've already resolved this file (prevents circular references)
            if include_path in resolved_history:
                logging.debug(f"skipping already resolved {include_path}")
                continue

            # add to resolved history before recursing
            resolved_history.add(include_path)

            # recursively load and merge the included file
            logging.debug(f"including {include_path} from {path}")
            included_result = _load_and_merge_yaml(include_path, resolved_history)

            # merge the included file's result into our result
            result = deep_merge(result, included_result)

        # remove the include directive from the loaded dictionary
        loaded_dict.pop(INCLUDE_DIRECTIVE)

    # finally, merge the current file's content (which will override includes)
    result = deep_merge(result, loaded_dict)

    return result


def load_from_yaml(path: str, config_type: Type["HuntConfig"]) -> tuple["HuntConfig", set[str]]:
    """Loads a hunt configuration from a YAML file.

    Args:
        path: the path to the YAML file to load
        config_type: the type of configuration to load

    Returns:
        A tuple of (the loaded configuration object, set of all file paths that were loaded including the main file and all included files).
    """

    logging.debug(f"loading {path} from {config_type.__name__}")

    # track resolved files to prevent circular references
    resolved_history: set[str] = set()
    resolved_history.add(path)

    # recursively load and merge
    result = _load_and_merge_yaml(path, resolved_history)

    # and then return the validated configuration object and all file paths that were loaded
    return config_type.model_validate(result["rule"]), resolved_history
