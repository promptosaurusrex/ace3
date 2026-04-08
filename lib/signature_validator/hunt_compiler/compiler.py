import base64
import os
import re
import stat
from typing import Any

import yaml

from hunt_compiler._yaml_utils import deep_merge
from hunt_compiler.models import CompiledHunt, EmbeddedFile

INCLUDE_DIRECTIVE = "include"
QUERY_INCLUDE_PATTERN = re.compile(r"<include:([^>]+)>")


def compile_hunt(file_path: str, root_dir: str) -> CompiledHunt:
    """Compile a hunt YAML file into a self-contained CompiledHunt.

    Args:
        file_path: Path to the main hunt YAML file.
        root_dir: Root directory for resolving paths. All embedded file paths
                  will be stored relative to this directory.

    Returns:
        A CompiledHunt containing all files needed to load the hunt.
    """
    file_path = os.path.abspath(file_path)
    root_dir = os.path.abspath(root_dir)

    # Phase 1: Collect YAML files (main + includes)
    yaml_files_dict: dict[str, str] = {}
    _collect_yaml_files(root_dir, file_path, yaml_files_dict, set())

    # Phase 2: Merge YAML to discover referenced files
    merged = _merge_yaml_contents(root_dir, file_path, yaml_files_dict)

    # Phase 3: Discover and read referenced files
    query_files = _collect_query_files(merged, root_dir)
    query_inline_includes = _collect_query_inline_includes(merged, query_files, root_dir)
    executable_files = _collect_executable_files(merged, root_dir)

    # Phase 4: Assemble
    target = os.path.relpath(file_path, root_dir)

    return CompiledHunt(
        target=target,
        root_dir=root_dir,
        yaml_files=[
            EmbeddedFile(path=path, content=content)
            for path, content in yaml_files_dict.items()
        ],
        query_files=query_files,
        query_inline_includes=query_inline_includes,
        executable_files=executable_files,
    )


def _collect_yaml_files(
    root_dir: str,
    file_path: str,
    collected: dict[str, str],
    history: set[str],
) -> None:
    """Recursively collect YAML files following include directives."""
    abs_path = os.path.abspath(file_path)
    if abs_path in history:
        return

    history.add(abs_path)
    with open(abs_path, "r") as fp:
        content = fp.read()

    rel_path = os.path.relpath(abs_path, root_dir)
    collected[rel_path] = content

    parsed = yaml.safe_load(content)
    if not isinstance(parsed, dict):
        return

    for include_path in parsed.get(INCLUDE_DIRECTIVE, []):
        if not os.path.isabs(include_path):
            include_path = os.path.join(os.path.dirname(abs_path), include_path)

        _collect_yaml_files(root_dir, include_path, collected, history)


def _merge_yaml_contents(
    root_dir: str,
    file_path: str,
    yaml_files_dict: dict[str, str],
) -> dict[str, Any]:
    """Merge all YAML files to produce the full config dict."""
    abs_path = os.path.abspath(file_path)

    def _load_and_merge(path: str, history: set[str]) -> dict[str, Any]:
        if path in history:
            return {}

        history.add(path)

        rel = os.path.relpath(path, root_dir)
        content = yaml_files_dict.get(rel)

        if content is None:
            with open(path, "r") as fp:
                content = fp.read()

        loaded = yaml.safe_load(content)
        if not isinstance(loaded, dict):
            return {}

        result: dict[str, Any] = {}
        if INCLUDE_DIRECTIVE in loaded:
            for include_path in loaded[INCLUDE_DIRECTIVE]:
                if not os.path.isabs(include_path):
                    include_path = os.path.join(os.path.dirname(path), include_path)
                include_path = os.path.abspath(include_path)
                included = _load_and_merge(include_path, history)
                result = deep_merge(result, included)
            loaded.pop(INCLUDE_DIRECTIVE)

        result = deep_merge(result, loaded)
        return result

    return _load_and_merge(abs_path, set())


def _collect_query_files(merged: dict[str, Any], root_dir: str) -> list[EmbeddedFile]:
    """Collect query files referenced by search:/query_file_path."""
    rule = merged.get("rule", {})
    query_path = rule.get("search") or rule.get("query_file_path")
    if not query_path:
        return []

    abs_path = _resolve_path(query_path, root_dir)
    if not os.path.isfile(abs_path):
        return []

    with open(abs_path, "r") as fp:
        content = fp.read()

    rel_path = os.path.relpath(abs_path, root_dir)
    return [EmbeddedFile(path=rel_path, content=content)]


def _collect_query_inline_includes(
    merged: dict[str, Any],
    query_files: list[EmbeddedFile],
    root_dir: str,
) -> list[EmbeddedFile]:
    """Collect files referenced by <include:path> in query text."""
    # Gather all query text sources
    query_texts = []

    rule = merged.get("rule", {})
    inline_query = rule.get("query")
    if inline_query:
        query_texts.append(inline_query)

    for qf in query_files:
        query_texts.append(qf.content)

    # Find all <include:path> references
    seen: set[str] = set()
    result: list[EmbeddedFile] = []

    for text in query_texts:
        for match in QUERY_INCLUDE_PATTERN.finditer(text):
            include_path = match.group(1)
            abs_path = _resolve_path(include_path, root_dir)
            if abs_path in seen or not os.path.isfile(abs_path):
                continue

            seen.add(abs_path)
            with open(abs_path, "r") as fp:
                content = fp.read()

            rel_path = os.path.relpath(abs_path, root_dir)
            result.append(EmbeddedFile(path=rel_path, content=content))

    return result


def _collect_executable_files(merged: dict[str, Any], root_dir: str) -> list[EmbeddedFile]:
    """Collect executable scripts from correlation commands."""
    paths: set[str] = set()

    # From predefined commands (top-level)
    for cmd in merged.get("commands", []):
        if cmd.get("type") == "executable" and cmd.get("path"):
            paths.add(cmd["path"])
        for f in cmd.get("files") or []:
            paths.add(f)

    # From correlation logic steps
    rule = merged.get("rule", {})
    correlate = rule.get("correlate", {})
    if correlate:
        logic = correlate.get("logic", [])
        _find_executable_paths_in_steps(logic, paths)

    result: list[EmbeddedFile] = []
    for path in sorted(paths):
        abs_path = _resolve_path(path, root_dir)
        if not os.path.isfile(abs_path):
            continue

        content, encoding = _read_file_content(abs_path)
        file_stat = os.stat(abs_path)
        permissions = stat.S_IMODE(file_stat.st_mode)
        rel_path = os.path.relpath(abs_path, root_dir)
        result.append(
            EmbeddedFile(path=rel_path, content=content, encoding=encoding, permissions=permissions)
        )

    return result


def _find_executable_paths_in_steps(steps: list[dict], paths: set[str]) -> None:
    """Recursively walk correlation logic steps to find executable command paths."""
    for step in steps:
        if "transform" in step:
            transform = step["transform"]
            cmd = transform.get("command", {}) if isinstance(transform, dict) else {}
            if cmd.get("type") == "executable" and cmd.get("path"):
                paths.add(cmd["path"])
            for f in cmd.get("files") or []:
                paths.add(f)
        if "when" in step:
            _find_executable_paths_in_steps(step.get("execute", []), paths)
            _find_executable_paths_in_steps(step.get("else", []), paths)


def _read_file_content(abs_path: str) -> tuple[str, str]:
    """Read a file, returning (content, encoding).

    Tries text mode first. If the file contains non-text bytes, falls back to
    binary mode with base64 encoding so the content can be stored in JSON.
    """
    try:
        with open(abs_path, "r") as fp:
            return fp.read(), "text"
    except (UnicodeDecodeError, ValueError):
        with open(abs_path, "rb") as fp:
            return base64.b64encode(fp.read()).decode("ascii"), "base64"


def _resolve_path(path: str, root_dir: str) -> str:
    """Resolve a path that may be absolute or relative to root_dir."""
    if os.path.isabs(path):
        return path

    return os.path.join(root_dir, path)
