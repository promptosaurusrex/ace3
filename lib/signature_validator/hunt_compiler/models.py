from typing import Literal, Optional

from pydantic import BaseModel, Field

AssetKind = Literal["yaml", "query", "query_include", "executable", "support"]


class EmbeddedFile(BaseModel):
    """A file whose content has been captured at compile time."""

    kind: AssetKind = Field(
        ...,
        description="The role this file plays in the hunt (yaml, query, query_include, executable, support).",
    )
    path: str = Field(..., description="Path relative to CompiledHunt.package_root")
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
    original_abs: Optional[str] = Field(
        default=None,
        description="Absolute path on the compiling machine. Provenance only; never consulted at load time.",
    )


class CompiledHunt(BaseModel):
    """Self-contained, serializable representation of a hunt and all its dependencies."""

    version: int = Field(default=2, description="Schema version")
    target: str = Field(..., description="Path to the main hunt YAML file, relative to package_root")
    package_root: str = Field(
        ...,
        description="Absolute path to the package root on the compiling machine. Provenance only; the loader does not need it.",
    )
    assets: list[EmbeddedFile] = Field(
        default_factory=list,
        description="Every file needed to materialize the hunt, tagged by kind.",
    )
