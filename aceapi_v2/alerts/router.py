"""Alert router for ACE API v2."""

import logging
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Security

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.alerts import service
from aceapi_v2.alerts.schemas import BulkAddObservableRequest, BulkAddObservableResult

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[Security(get_current_auth)])


@router.post("/bulk-add-observable", response_model=BulkAddObservableResult)
async def bulk_add_observable(
    body: BulkAddObservableRequest,
    auth: Annotated[ApiAuthResult, Depends(require_permission("alert", "write"))],
) -> BulkAddObservableResult:
    """Add an observable to multiple alerts at once."""
    if not body.alert_uuids:
        raise HTTPException(status_code=400, detail="No alert UUIDs provided")

    if not body.observable_value:
        raise HTTPException(status_code=400, detail="Missing observable value")

    # Parse time if provided
    o_time = None
    if body.observable_time:
        try:
            o_time = datetime.strptime(body.observable_time, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Invalid time format. Expected YYYY-MM-DD HH:MM:SS",
            )

    return await service.bulk_add_observable(
        alert_uuids=body.alert_uuids,
        o_type=body.observable_type,
        o_value=body.observable_value,
        o_time=o_time,
        directives=body.directives,
        username=auth.auth_name or "unknown",
    )
