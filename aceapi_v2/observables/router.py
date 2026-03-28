"""Observable router for ACE API v2."""

from typing import Annotated

from fastapi import APIRouter, Depends, Security
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.database import get_async_session
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.observables import service
from aceapi_v2.observables.schemas import SetInterestingRequest

router = APIRouter(dependencies=[Security(get_current_auth)])


@router.patch("/interesting")
async def set_interesting(
    body: SetInterestingRequest,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[None, Depends(require_permission("observable", "write"))],
) -> dict:
    await service.set_observable_interesting(
        session, body.observable_type, body.observable_value, body.is_interesting
    )
    status = "marked" if body.is_interesting else "unmarked"
    return {"message": f"Observable {status} as interesting"}
