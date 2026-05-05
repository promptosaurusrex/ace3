"""Observable type service for ACE API v2."""

from sqlalchemy import distinct, select
from sqlalchemy.ext.asyncio import AsyncSession

from saq.database.model import Observable
from saq.observables.type_hierarchy import get_all_valid_types


async def get_observable_types(session: AsyncSession) -> list[str]:
    """Return a list of unique observable types from the database.

    Args:
        session: AsyncSession for database access

    Returns:
        List of observable type names, sorted alphabetically
    """
    result = await session.execute(select(distinct(Observable.type)))
    db_types = [row[0] for row in result.all()]
    all_types = set(db_types) | set(get_all_valid_types())

    return sorted(all_types)
