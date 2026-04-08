import base64
import os

from hunt_compiler.models import CompiledHunt


def load_compiled_hunt(compiled: CompiledHunt, temp_dir: str) -> str:
    """Write all files from a CompiledHunt to temp_dir and return the target path.

    For executable scripts, file permissions are restored from stored mode bits.
    Paths in YAML content that reference the original root_dir are rewritten to
    point to the temp_dir so that load_from_yaml() can resolve them.

    Args:
        compiled: The compiled hunt to materialize on disk.
        temp_dir: Directory to write files into.

    Returns:
        Absolute path to the target YAML file within temp_dir.
    """
    # Build path rewrite map: original absolute path -> temp dir path
    rewrite_map: dict[str, str] = {}

    for embedded in compiled.query_files + compiled.query_inline_includes + compiled.executable_files:
        original_abs = os.path.join(compiled.root_dir, embedded.path)
        temp_abs = os.path.join(temp_dir, embedded.path)
        rewrite_map[original_abs] = temp_abs

    # Write YAML files (with path rewriting applied to content)
    for embedded in compiled.yaml_files:
        content = _rewrite_paths(embedded.content, rewrite_map)
        _write_file(temp_dir, embedded.path, content)

    # Write query files
    for embedded in compiled.query_files:
        _write_file(temp_dir, embedded.path, embedded.content)

    # Write query inline include files
    for embedded in compiled.query_inline_includes:
        _write_file(temp_dir, embedded.path, embedded.content)

    # Write executable files with permissions
    for embedded in compiled.executable_files:
        file_path = _write_file(temp_dir, embedded.path, embedded.content, embedded.encoding)
        if embedded.permissions is not None:
            os.chmod(file_path, embedded.permissions)

    return os.path.join(temp_dir, compiled.target)


def _write_file(temp_dir: str, rel_path: str, content: str, encoding: str = "text") -> str:
    """Write content to temp_dir/rel_path, creating directories as needed.

    Args:
        temp_dir: Base directory to write into.
        rel_path: Relative path within temp_dir.
        content: File content (plain text or base64-encoded).
        encoding: 'text' for plain text, 'base64' for binary content.

    Returns the absolute path of the written file.
    """
    abs_path = os.path.join(temp_dir, rel_path)
    os.makedirs(os.path.dirname(abs_path), exist_ok=True)
    if encoding == "base64":
        with open(abs_path, "wb") as fp:
            fp.write(base64.b64decode(content))
    else:
        with open(abs_path, "w") as fp:
            fp.write(content)
    return abs_path


def _rewrite_paths(content: str, rewrite_map: dict[str, str]) -> str:
    """Replace original absolute paths with temp dir paths in file content."""
    for original, replacement in rewrite_map.items():
        content = content.replace(original, replacement)
    return content
