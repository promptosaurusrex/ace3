import datetime
import logging
from abc import ABC, abstractmethod

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
    ) -> list[dict]:
        """Execute a query and return results as a list of dicts."""
        raise NotImplementedError()


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
