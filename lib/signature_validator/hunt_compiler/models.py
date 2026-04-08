from typing import Optional

from pydantic import BaseModel, Field


class EmbeddedFile(BaseModel):
    """A file whose content has been captured at compile time."""

    path: str = Field(..., description="Path relative to root_dir")
    content: str = Field(
        ...,
        description="File content. Plain text when encoding='text', base64-encoded when encoding='base64'.",
    )
    encoding: str = Field(
        default="text",
        description="Content encoding: 'text' for plain text, 'base64' for binary files.",
    )
    permissions: Optional[int] = Field(
        default=None,
        description="POSIX file mode bits (e.g. 0o755 stored as 493). Only set for executable scripts.",
    )


class CompiledHunt(BaseModel):
    """Self-contained, serializable representation of a hunt and all its dependencies."""

    version: int = Field(default=1, description="Schema version for forward compatibility")
    target: str = Field(..., description="Relative path to the main hunt YAML file")
    root_dir: str = Field(..., description="Original root directory (provenance only)")
    yaml_files: list[EmbeddedFile] = Field(
        default_factory=list,
        description="All YAML files (main + includes) with relative paths and raw content",
    )
    query_files: list[EmbeddedFile] = Field(
        default_factory=list,
        description="External query files referenced by hunt config via search:/query_file_path",
    )
    query_inline_includes: list[EmbeddedFile] = Field(
        default_factory=list,
        description="Files referenced by <include:path> directives in query text",
    )
    executable_files: list[EmbeddedFile] = Field(
        default_factory=list,
        description="Executable scripts from correlation commands (content + permissions)",
    )
