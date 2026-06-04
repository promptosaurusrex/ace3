# vim: sw=4:ts=4:et:cc=120

import logging
import re
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from saq.constants import (
    SUMMARY_DETAIL_FORMAT_JINJA,
    SUMMARY_DETAIL_FORMAT_MD,
    SUMMARY_DETAIL_FORMAT_PRE,
    SUMMARY_DETAIL_FORMAT_TXT,
)
from saq.observables.mapping import (
    ObservableMapping,
    compile_ignored_value_patterns,
    is_ignored_value,
)
from saq.util import abs_path

SUMMARY_DETAIL_LIMIT_DEFAULT = 100

VALID_SUMMARY_DETAIL_FORMATS = {
    SUMMARY_DETAIL_FORMAT_MD, SUMMARY_DETAIL_FORMAT_PRE,
    SUMMARY_DETAIL_FORMAT_TXT, SUMMARY_DETAIL_FORMAT_JINJA,
}


class SummaryDetailConfig(BaseModel):
    model_config = {"extra": "forbid"}

    content: str
    header: Optional[str] = None
    format: str = SUMMARY_DETAIL_FORMAT_MD
    limit: int = SUMMARY_DETAIL_LIMIT_DEFAULT
    grouped: bool = False
    dedup_fields: Optional[list[str]] = None
    required_fields: Optional[list[str]] = Field(
        default=None,
        description="Field names that must be present AND non-empty for an event to contribute "
                    "to this summary detail. Empty values (None, '', [], {}) count as missing, "
                    "so the pane/row is suppressed. Uses key lookup (literal event[name]), not "
                    "dotted traversal.",
    )

    @field_validator("format")
    @classmethod
    def validate_format(cls, value: str) -> str:
        if value not in VALID_SUMMARY_DETAIL_FORMATS:
            logging.error(
                "invalid summary_detail format %s - must be one of %s - defaulting to %s",
                value, VALID_SUMMARY_DETAIL_FORMATS, SUMMARY_DETAIL_FORMAT_MD,
            )
            return SUMMARY_DETAIL_FORMAT_MD
        return value


PIVOT_LINK_TARGET_ANALYSIS = "analysis"
PIVOT_LINK_TARGET_ROOT = "root"
VALID_PIVOT_LINK_TARGETS = {PIVOT_LINK_TARGET_ANALYSIS, PIVOT_LINK_TARGET_ROOT}


class PivotLinkOverflowConfig(BaseModel):
    """A single 'see more' link emitted when a pivot link's `limit` truncates the result set."""
    model_config = {"extra": "forbid"}

    url: str = Field(..., description="Jinja template for the overflow link URL, rendered against the "
                                      "first query-result event plus `overflow_count` (the number of "
                                      "qualifying links beyond `limit` that were not shown).")
    text: str = Field(..., description="Jinja template for the overflow link display text, rendered "
                                       "against the same context as `url`.")
    icon: Optional[str] = Field(default=None, description="Optional icon for the overflow link. "
                                                          "Defaults to the parent pivot link's icon.")


class PivotLinkConfig(BaseModel):
    model_config = {"extra": "forbid"}

    url: str = Field(..., description="Jinja template for the pivot link URL, rendered against each event.")
    text: str = Field(..., description="Jinja template for the pivot link display text, rendered against each event.")
    icon: Optional[str] = Field(default=None, description="Optional icon name for the pivot link.")
    target: str = Field(
        default=PIVOT_LINK_TARGET_ROOT,
        description="Where to attach the rendered link: 'root' (the root alert) or 'analysis' (the analysis node).",
    )
    limit: Optional[int] = Field(
        default=None, ge=0,
        description="Maximum number of links this entry emits per analysis run. None means unlimited. "
                    "Links are emitted in query-result order, so a query that sorts most-recent-first "
                    "yields the most recent `limit` links.",
    )
    overflow: Optional[PivotLinkOverflowConfig] = Field(
        default=None,
        description="A single 'see more' link emitted only when `limit` truncates the result set "
                    "(i.e. there were more qualifying links than `limit`). Requires `limit`.",
    )

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        if value not in VALID_PIVOT_LINK_TARGETS:
            logging.error(
                "invalid pivot_link target %s - must be one of %s - defaulting to %s",
                value, VALID_PIVOT_LINK_TARGETS, PIVOT_LINK_TARGET_ROOT,
            )
            return PIVOT_LINK_TARGET_ROOT
        return value

    @model_validator(mode="after")
    def validate_overflow_requires_limit(self):
        if self.overflow is not None and self.limit is None:
            logging.error(
                "pivot_link has `overflow` configured without `limit`; the overflow link will "
                "never be emitted (overflow only fires when `limit` truncates the result set)"
            )
        return self


class TimeRangeConfig(BaseModel):
    """Configuration for a named TIMESPEC token's time range."""
    model_config = {"extra": "forbid"}

    duration_before: Optional[str] = Field(default=None, description="Lookback duration from anchor time")
    duration_after: Optional[str] = Field(default=None, description="Lookahead duration from anchor time")


class BaseQueryConfig(BaseModel):
    """Shared query configuration mixin for hunts and API analysis modules."""
    model_config = {"extra": "forbid"}

    query: Optional[str] = Field(default=None, description="The query to execute.")
    query_path: Optional[str] = Field(default=None, description="The path to the query file.")
    observable_mapping: list[ObservableMapping] = Field(
        default_factory=list,
        description="The mapping of fields to observables."
    )
    max_result_count: Optional[int] = Field(default=None, description="The maximum number of results to return.")
    ignored_values: list[str] = Field(
        default_factory=list,
        description="A global list of regex patterns to ignore that applies to all observable mappings. "
                    "Patterns are matched with re.fullmatch()."
    )
    summary_details: list[SummaryDetailConfig] = Field(
        default_factory=list,
        description="Summary details to add to submissions/analysis. Each definition generates one or more "
                    "SummaryDetail objects."
    )
    query_prefix: Optional[str] = Field(
        default=None,
        description="Text to prepend to the resolved query.",
    )
    query_suffix: Optional[str] = Field(
        default=None,
        description="Text to append to the resolved query (before auto_append).",
    )
    pivot_links: list[PivotLinkConfig] = Field(
        default_factory=list,
        description="Pivot links to add to analysis or the root alert. Each entry's url/text "
                    "are Jinja templates rendered against each query-result event."
    )
    time_ranges: Optional[dict[str, TimeRangeConfig]] = Field(
        default=None,
        description="Named time ranges for TIMESPEC tokens. Values can be a duration string (lookback only) "
                    "or a dict with duration_before/duration_after."
    )
    _ignored_value_patterns: list[re.Pattern] = []

    @field_validator('time_ranges', mode='before')
    @classmethod
    def normalize_time_ranges(cls, v):
        """Normalize plain string values to TimeRangeConfig dicts."""
        if v is None:
            return v
        result = {}
        for key, val in v.items():
            if isinstance(val, str):
                result[key] = {'duration_before': val, 'duration_after': None}
            else:
                result[key] = val
        return result

    @model_validator(mode='after')
    def compile_ignored_value_patterns(self):
        """Pre-compile ignored_values into regex patterns."""
        self._ignored_value_patterns = compile_ignored_value_patterns(self.ignored_values)
        return self

    def is_ignored_value(self, value: str) -> bool:
        """Check if a value matches any ignored_values regex pattern."""
        return is_ignored_value(self._ignored_value_patterns, value)


def load_query_from_file(path: str) -> str:
    """Load a query string from a file path (resolved via abs_path)."""
    with open(abs_path(path), 'r') as fp:
        return fp.read()


def resolve_query(inline_query: Optional[str], query_file_path: Optional[str], context_name: str) -> str:
    """Resolve a query from inline string or file path. Raises ValueError if neither provided."""
    if inline_query is not None:
        return inline_query

    if query_file_path is not None:
        return load_query_from_file(query_file_path)

    raise ValueError(f"no query specified for {context_name}")
