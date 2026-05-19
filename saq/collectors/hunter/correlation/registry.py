import datetime
import logging
from abc import ABC, abstractmethod
from typing import Optional

_query_source_registry: dict[str, "QuerySource"] = {}


class QuerySource(ABC):
    """Abstract base class for query sources used by correlation commands.

    Subclasses must declare class-level defaults `default_time_field` and
    `default_time_format`. These describe how events returned by this source
    encode their event time, and are used by the correlation engine to anchor
    relative time ranges when the hunt YAML omits explicit values.
    """

    default_time_field: str
    default_time_format: str

    @abstractmethod
    def execute_query(
        self,
        query: str,
        start_time: datetime.datetime,
        end_time: datetime.datetime,
        timeout: datetime.timedelta,
        source_options: Optional[dict] = None,
    ) -> list[dict]:
        """Execute a query and return results as a list of dicts.

        `source_options` is the `command.source_options` dict from the hunt YAML,
        or `None`/`{}` if the YAML omitted it. Sources should treat unrecognized
        keys as a no-op (forward-compat) and missing keys as "use my defaults".
        """
        raise NotImplementedError()

    def format_timespec_for_display(
        self,
        start_time: datetime.datetime,
        end_time: datetime.datetime,
    ) -> Optional[str]:
        """Return a query-language-valid prefix for the resolved time bounds, in
        this source's native syntax. The Correlation Trace UI inlines the result
        at the front of the rendered query so analysts can copy/paste the whole
        thing into the data source.

        Return None if this source can't represent its time bounds as a literal
        query-language prefix — e.g. LogScale and Rapid7 take time bounds as API
        parameters rather than as query terms, so prepending anything to the
        query body would break the syntax. In that case the UI falls back to a
        separate decorative "Time range" block built from the raw datetimes
        stored on the trace.
        """
        return None


def register_query_source(name: str, source: QuerySource):
    """Register a query source by name."""
    if name in _query_source_registry:
        logging.warning("overwriting existing query source registration: %s", name)
    _query_source_registry[name] = source
    logging.info("registered query source: %s", name)


def get_query_source(name: str) -> QuerySource:
    """Get a registered query source by name."""
    if name not in _query_source_registry:
        raise ValueError(f"query source not registered: {name!r}")
    return _query_source_registry[name]


def clear_query_sources():
    """Clear all registered query sources. Primarily for testing."""
    _query_source_registry.clear()


def get_registered_sources() -> dict[str, "QuerySource"]:
    """Return the current registry (read-only view)."""
    return dict(_query_source_registry)
