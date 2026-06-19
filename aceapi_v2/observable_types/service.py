"""Observable type service for ACE API v2."""

from saq.observables.type_hierarchy import get_all_valid_types


async def get_observable_types() -> list[str]:
    """Return the list of valid observable types from the configured registry.

    The single source of truth is the configured ``observable_types.yaml``
    (plus any Python-registered observable classes), surfaced via
    :func:`get_all_valid_types`. Observable types that only exist in old/stale
    database rows are intentionally excluded.

    Returns:
        List of observable type names, sorted alphabetically
    """
    return sorted(get_all_valid_types())
