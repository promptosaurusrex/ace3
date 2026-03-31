"""Alert service for ACE API v2."""

import asyncio
import logging
import uuid as uuidlib
from datetime import datetime

from saq.constants import ANALYSIS_MODE_CORRELATION, VALID_DIRECTIVES
from saq.database.pool import get_db
from saq.database.util.locking import acquire_lock, release_lock
from saq.database.util.workload import add_workload
from saq.gui.alert import GUIAlert

from aceapi_v2.alerts.schemas import BulkAddObservableResult

logger = logging.getLogger(__name__)


def _add_observable_to_alert(
    alert_uuid: str,
    o_type: str,
    o_value: str,
    o_time: datetime | None,
    directives: list[str],
) -> str | None:
    """Add an observable to a single alert. Returns None on success, or a failure reason string.

    This is a synchronous function that performs filesystem lock/load/sync
    operations. It uses the sync get_db() because Alert.sync()
    (saq/database/model.py) calls Session.object_session(self) to get a sync
    session for its session.add(self) + session.commit() — meaning the Alert
    ORM object must be loaded from a sync session to begin with.

    TODO: refactor Alert.sync() to separate filesystem save from the sync DB
    commit so this service can use AsyncSession end-to-end.
    """
    alert = get_db().query(GUIAlert).filter(GUIAlert.uuid == alert_uuid).one_or_none()
    if alert is None:
        logger.error("alert %s not found in database", alert_uuid)
        return "alert not found"

    lock_uuid = str(uuidlib.uuid4())
    try:
        if not acquire_lock(uuid=str(alert.uuid), lock_uuid=lock_uuid):
            logger.warning("unable to acquire lock on alert %s", alert_uuid)
            return "alert is currently locked"

        alert.lock_uuid = lock_uuid
        alert.load()

        observable = alert.root_analysis.add_observable_by_spec(o_type, o_value, o_time)

        if observable and directives:
            for directive in directives:
                if directive in VALID_DIRECTIVES:
                    observable.add_directive(directive)

        alert.root_analysis.analysis_mode = ANALYSIS_MODE_CORRELATION
        alert.sync()
        add_workload(alert.root_analysis)
        return None

    except Exception as e:
        logger.error("unable to add observable to alert %s: %s", alert_uuid, e)
        return f"unexpected error: {e}"

    finally:
        try:
            if alert.lock_uuid:
                release_lock(str(alert.uuid), alert.lock_uuid)
        except Exception:
            logger.error("unable to release lock on alert %s", alert_uuid)


async def bulk_add_observable(
    alert_uuids: list[str],
    o_type: str,
    o_value: str,
    o_time: datetime | None,
    directives: list[str],
    username: str,
) -> BulkAddObservableResult:
    """Add an observable to multiple alerts.

    Runs sync filesystem operations in a thread pool via asyncio.to_thread().
    """
    logger.info(
        f"AUDIT: user {username} bulk-added observable "
        f"({o_type},{o_value},{o_time}) to alerts {alert_uuids}"
    )

    # Validate directives
    valid_directives = [d for d in directives if d in VALID_DIRECTIVES]

    success_count = 0
    failed_uuids = []
    failed_details = {}

    for alert_uuid in alert_uuids:
        failure_reason = await asyncio.to_thread(
            _add_observable_to_alert, alert_uuid, o_type, o_value, o_time, valid_directives
        )
        if failure_reason is None:
            success_count += 1
        else:
            failed_uuids.append(alert_uuid)
            failed_details[alert_uuid] = failure_reason

    return BulkAddObservableResult(
        success_count=success_count,
        failed_count=len(failed_uuids),
        failed_uuids=failed_uuids,
        failed_details=failed_details,
    )
