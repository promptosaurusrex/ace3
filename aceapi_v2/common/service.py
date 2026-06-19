"""Common service for ACE API v2."""

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.observable_types.service import get_observable_types
from saq.constants import DIRECTIVE_DESCRIPTIONS, VALID_DIRECTIVES
from saq.database.model import Company
from saq.observables.type_hierarchy import get_type_hierarchy


async def get_valid_companies(session: AsyncSession) -> list[Company]:
    result = await session.execute(select(Company).order_by(Company.name))
    return list(result.scalars().all())


async def get_valid_observables(session: AsyncSession) -> list[dict]:
    all_types = await get_observable_types()
    hierarchy = get_type_hierarchy()
    active = [t for t in all_types if not hierarchy.is_deprecated(t)]
    return [
        {"name": t, "description": hierarchy.description_for(t) or "unknown"}
        for t in active
    ]


async def get_valid_directives() -> list[dict]:
    items = []
    for directive in VALID_DIRECTIVES:
        try:
            items.append(
                {"name": directive, "description": DIRECTIVE_DESCRIPTIONS[directive]}
            )
        except KeyError:
            logging.warning(
                'Missing directive description for the "%s" directive.', directive
            )
    return items
