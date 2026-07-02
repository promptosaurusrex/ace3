"""Tests for DatabaseWorkloadManager.transfer_work_target.

These cover the failure handling of the remote ``clear`` step. Historically a
benign ``clear`` failure (the remote lock had already expired, or the item was
already cleared -- both return HTTP 400) was treated as a fatal transfer error:
it reported an exception (one error.report record per failure -- a flood during
a mass node drain), deleted the freshly-downloaded local copy the database now
pointed at, and leaked the work lock. The remote clear is best-effort cleanup;
a failure there must not fail the (already committed) transfer.
"""

import os
import uuid as uuidlib
from unittest.mock import Mock

import pytest
import requests

from saq.database.pool import get_db_connection
from saq.database.util.locking import acquire_lock
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.lock_manager.distributed import DistributedLockManager
from saq.engine.node_manager.node_manager_interface import NodeManagerInterface
from saq.engine.workload_manager.database import DatabaseWorkloadManager
from saq.environment import get_base_dir, get_global_runtime_settings
from saq.util import storage_dir_from_uuid
from tests.saq.helpers import create_root_analysis

pytestmark = pytest.mark.integration

ANALYSIS_MODE = "analysis"


def local_node_id() -> int:
    return get_global_runtime_settings().saq_node_id


def insert_remote_node() -> int:
    """Inserts a node row distinct from the local node and returns its id."""
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute(
            """INSERT INTO nodes ( name, location, company_id, last_update, status, any_mode )
               VALUES ( %s, %s, %s, NOW(), 'running', 1 )""",
            ("remote_scanner", "remote_scanner:443", get_global_runtime_settings().company_id),
        )
        db.commit()
        return cursor.lastrowid


def insert_workload(uuid: str, node_id: int) -> None:
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute(
            """INSERT INTO workload ( uuid, node_id, analysis_mode, company_id, storage_dir, insert_date )
               VALUES ( %s, %s, %s, %s, %s, NOW() )""",
            (uuid, node_id, ANALYSIS_MODE, get_global_runtime_settings().company_id,
             storage_dir_from_uuid(uuid)),
        )
        db.commit()


def workload_node_id(uuid: str):
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT node_id FROM workload WHERE uuid = %s", (uuid,))
        row = cursor.fetchone()
        return row[0] if row else None


def lock_row(uuid: str):
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT lock_uuid FROM locks WHERE uuid = %s", (uuid,))
        return cursor.fetchone()


def make_manager(lock_manager: DistributedLockManager) -> DatabaseWorkloadManager:
    config_manager = Mock(spec=ConfigurationManager)
    config_manager.config = Mock()
    node_manager = Mock(spec=NodeManagerInterface)
    return DatabaseWorkloadManager(
        lock_manager=lock_manager,
        configuration_manager=config_manager,
        node_manager=node_manager,
    )


def fake_download(uuid, target_dir, remote_host=None):
    """Materialize a valid root at the transfer target directory, standing in
    for pulling it off the remote node."""
    root = create_root_analysis(uuid=uuid, storage_dir=target_dir, analysis_mode=ANALYSIS_MODE)
    root.initialize_storage()
    root.save()


def abs_target(uuid: str) -> str:
    return os.path.join(get_base_dir(), storage_dir_from_uuid(uuid))


@pytest.fixture
def item(monkeypatch):
    """A work item queued on a remote node, ready to be transferred locally."""
    import ace_api

    uuid = str(uuidlib.uuid4())
    remote_id = insert_remote_node()
    insert_workload(uuid, remote_id)
    monkeypatch.setattr(ace_api, "download", fake_download)
    return uuid, remote_id


def test_transfer_survives_benign_clear_failure(item, monkeypatch):
    """A 400 from the remote clear must not fail the transfer, delete the local
    copy, report an exception, or release the (now-owned) lock."""
    import ace_api
    from saq.engine.workload_manager import database as db_module

    uuid, _ = item

    def fake_clear(*args, **kwargs):
        raise requests.exceptions.HTTPError("400 Client Error: BAD REQUEST")

    monkeypatch.setattr(ace_api, "clear", fake_clear)
    report_exception_mock = Mock()
    monkeypatch.setattr(db_module, "report_exception", report_exception_mock)

    manager = make_manager(DistributedLockManager())
    result = manager.transfer_work_target(uuid, workload_node_id(uuid))

    # the transfer still succeeds -- we are the authoritative owner now
    assert result is not None
    assert result.uuid == uuid
    # the downloaded local copy is retained (the database points at it)
    assert os.path.isdir(abs_target(uuid))
    # a benign clear failure must not be reported as an exception
    report_exception_mock.assert_not_called()
    # the workload row has moved to the local node
    assert workload_node_id(uuid) == local_node_id()
    # on success we keep the lock so the engine can process the item
    row = lock_row(uuid)
    assert row is not None and row[0] == manager.lock_manager.lock_uuid


def test_transfer_succeeds_when_clear_succeeds(item, monkeypatch):
    """Regression: the normal path (clear returns True) still transfers."""
    import ace_api

    uuid, _ = item
    monkeypatch.setattr(ace_api, "clear", lambda *a, **k: True)

    manager = make_manager(DistributedLockManager())
    result = manager.transfer_work_target(uuid, workload_node_id(uuid))

    assert result is not None and result.uuid == uuid
    assert os.path.isdir(abs_target(uuid))
    assert workload_node_id(uuid) == local_node_id()


def test_transfer_releases_lock_when_download_fails(item, monkeypatch):
    """A genuine transfer failure (download raises) releases the lock and
    cleans up the partial local copy so the item can be retried."""
    import ace_api

    uuid, _ = item

    def fail_download(*args, **kwargs):
        raise RuntimeError("network is down")

    monkeypatch.setattr(ace_api, "download", fail_download)

    manager = make_manager(DistributedLockManager())
    result = manager.transfer_work_target(uuid, workload_node_id(uuid))

    assert result is None
    # the lock is not leaked -- another worker can pick the item back up
    assert lock_row(uuid) is None
    # the partial target directory was cleaned up
    assert not os.path.isdir(abs_target(uuid))


def test_transfer_bails_and_releases_lock_when_target_dir_exists(item, monkeypatch):
    """If the target dir already exists we bail -- but must still release the
    lock we just acquired rather than leaking it."""
    uuid, _ = item
    os.makedirs(abs_target(uuid))

    manager = make_manager(DistributedLockManager())
    result = manager.transfer_work_target(uuid, workload_node_id(uuid))

    assert result is False
    assert lock_row(uuid) is None
