"""Observable service for ACE API v2."""

import hashlib

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from saq.database.model import Observable as DBObservable


def _compute_sha256(value: str) -> bytes:
    """Compute SHA256 hash bytes from an observable value string."""
    return hashlib.sha256(value.encode("utf8", errors="ignore")).digest()


async def observable_is_interesting(
    session: AsyncSession, observable_type: str, sha256_bytes: bytes
) -> bool:
    """Returns True if the observable is marked as interesting in the database."""
    result = await session.execute(
        select(DBObservable.is_interesting).where(
            DBObservable.type == observable_type,
            DBObservable.sha256 == sha256_bytes,
        )
    )
    row = result.scalar_one_or_none()
    if row is None:
        return False
    return bool(row)


async def set_observable_interesting(
    session: AsyncSession,
    observable_type: str,
    observable_value: str,
    is_interesting: bool,
) -> None:
    """Sets or clears the is_interesting flag on an observable."""
    sha256_bytes = _compute_sha256(observable_value)

    result = await session.execute(
        select(DBObservable).where(
            DBObservable.type == observable_type,
            DBObservable.sha256 == sha256_bytes,
        )
    )
    db_observable = result.scalar_one_or_none()

    if db_observable is None:
        if not is_interesting:
            return
        db_observable = DBObservable(
            type=observable_type,
            sha256=sha256_bytes,
            value=observable_value.encode("utf8", errors="ignore"),
            is_interesting=True,
        )
        session.add(db_observable)
    else:
        db_observable.is_interesting = is_interesting

    await session.flush()


async def get_interesting_observables_by_hashes(
    session: AsyncSession, sha256_list: list[bytes]
) -> list[DBObservable]:
    """Returns all interesting DB observables matching any of the given sha256 hashes."""
    if not sha256_list:
        return []

    result = await session.execute(
        select(DBObservable).where(
            DBObservable.sha256.in_(sha256_list),
            DBObservable.is_interesting == True,
        )
    )
    return list(result.scalars().all())
