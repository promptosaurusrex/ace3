"""Alert service for ACE API v2."""

import asyncio
import logging
import os
import subprocess
import uuid as uuidlib
from datetime import datetime

from fastapi import HTTPException

from saq.constants import ANALYSIS_MODE_CORRELATION, VALID_DIRECTIVES
from saq.database.pool import get_db
from saq.database.util.locking import acquire_lock, release_lock
from saq.database.util.workload import add_workload
from saq.environment import get_base_dir, get_temp_dir
from saq.gui.alert import GUIAlert
from saq.util.uuid import is_uuid

from aceapi_v2.alerts.schemas import BulkAddObservableResult

logger = logging.getLogger(__name__)


ALERT_ZIP_PASSWORD = "infected"


def _resolve_alert_storage_path(alert_uuid: str) -> str:
    """Look up an alert by UUID and return the absolute path to its storage directory.

    Raises HTTPException with appropriate status for invalid UUID, missing alert,
    archived alert, or storage directory missing on disk.
    """
    if not is_uuid(alert_uuid):
        raise HTTPException(status_code=400, detail="invalid alert UUID")

    alert = get_db().query(GUIAlert).filter(GUIAlert.uuid == alert_uuid).one_or_none()
    if alert is None:
        raise HTTPException(status_code=404, detail="alert not found")

    if alert.archived:
        raise HTTPException(
            status_code=410,
            detail="alert has been archived; storage has been cleaned up",
        )

    abs_path = os.path.join(get_base_dir(), alert.storage_dir)
    if not os.path.isdir(abs_path):
        raise HTTPException(
            status_code=410,
            detail="alert storage directory no longer exists on disk",
        )

    return abs_path


def create_encrypted_alert_zip(alert_uuid: str) -> str:
    """Build an encrypted (password='infected') zip of the alert's storage
    directory under the configured temp dir. Returns the absolute path to
    the resulting zip file. Caller is responsible for cleaning it up.
    """
    storage_dir = _resolve_alert_storage_path(alert_uuid)

    dest = os.path.join(get_temp_dir(), f"{alert_uuid}.zip")
    # If a stale file is hanging around, remove it so zip doesn't try to update it.
    if os.path.exists(dest):
        try:
            os.remove(dest)
        except OSError:
            pass

    parent_dir = os.path.dirname(storage_dir)
    if os.path.basename(storage_dir) != alert_uuid:
        logger.error(
            "storage dir basename %s does not match alert uuid %s",
            os.path.basename(storage_dir),
            alert_uuid,
        )
        raise HTTPException(status_code=500, detail="unexpected alert storage layout")

    proc = subprocess.run(
        ["zip", "-e", "-P", ALERT_ZIP_PASSWORD, "-r", dest, "--", alert_uuid],
        cwd=parent_dir,
        check=False,
        capture_output=True,
    )
    if proc.returncode != 0:
        logger.error(
            "zip failed for alert %s (rc=%s): %s",
            alert_uuid,
            proc.returncode,
            proc.stderr.decode(errors="replace"),
        )
        try:
            os.remove(dest)
        except OSError:
            pass
        raise HTTPException(status_code=500, detail="failed to create alert zip")

    return dest


def resolve_alert_log_path(alert_uuid: str) -> str:
    """Return the absolute path to the alert's saq.log file."""
    storage_dir = _resolve_alert_storage_path(alert_uuid)
    log_path = os.path.join(storage_dir, "saq.log")
    if not os.path.isfile(log_path):
        raise HTTPException(
            status_code=404, detail="saq.log not present for this alert"
        )
    return log_path


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
