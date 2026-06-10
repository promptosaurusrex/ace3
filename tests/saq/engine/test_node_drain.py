import os
import uuid as uuidlib

import pytest

from saq.constants import NODE_STATUS_DRAINED, NODE_STATUS_DRAINING, NODE_STATUS_RUNNING, NODE_STATUS_STOPPED
from saq.database.pool import get_db_connection
from saq.database.util.node import check_and_mark_drained, get_node_status, set_node_status
from saq.engine.node_manager.drain import get_compatible_transfer_target, transfer_delayed_analysis
from saq.environment import get_base_dir, get_global_runtime_settings
from tests.saq.helpers import create_root_analysis

pytestmark = pytest.mark.integration

ANALYSIS_MODE = "analysis"


def local_node_id() -> int:
    return get_global_runtime_settings().saq_node_id


def insert_node(name: str, status: str = NODE_STATUS_RUNNING, any_mode: bool = True) -> int:
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""INSERT INTO nodes ( name, location, company_id, last_update, status, any_mode )
                          VALUES ( %s, %s, %s, NOW(), %s, %s )""",
                       (name, f"{name}:443", get_global_runtime_settings().company_id, status, any_mode))
        db.commit()
        return cursor.lastrowid


def add_node_mode(node_id: int, analysis_mode: str, excluded: bool = False):
    table = "node_modes_excluded" if excluded else "node_modes"
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute(f"INSERT INTO {table} ( node_id, analysis_mode ) VALUES ( %s, %s )", (node_id, analysis_mode))
        db.commit()


def create_delayed_root() -> tuple[str, str]:
    """Creates a root analysis on disk with a delayed_analysis row pinned to
    the local node. Returns (uuid, relative storage_dir)."""
    _uuid = str(uuidlib.uuid4())
    root = create_root_analysis(uuid=_uuid, analysis_mode=ANALYSIS_MODE)
    root.initialize_storage()
    root.save()

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""INSERT INTO delayed_analysis ( uuid, observable_uuid, analysis_module, insert_date, delayed_until, node_id, storage_dir )
                          VALUES ( %s, %s, 'test_module', NOW(), NOW() + INTERVAL 1 HOUR, %s, %s )""",
                       (_uuid, str(uuidlib.uuid4()), local_node_id(), root.storage_dir))
        db.commit()

    return _uuid, root.storage_dir


def get_delayed_row(_uuid: str) -> tuple:
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT node_id, storage_dir, delayed_until FROM delayed_analysis WHERE uuid = %s", (_uuid,))
        return cursor.fetchone()


def lock_count() -> int:
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM locks")
        return cursor.fetchone()[0]


def test_get_compatible_transfer_target():
    # no other node exists
    assert get_compatible_transfer_target(ANALYSIS_MODE) is None

    # an any_mode running node is compatible
    target_id = insert_node("test_target_node", NODE_STATUS_RUNNING, any_mode=True)
    target = get_compatible_transfer_target(ANALYSIS_MODE)
    assert target is not None
    assert target[0] == target_id

    # but not when it excludes the mode
    add_node_mode(target_id, ANALYSIS_MODE, excluded=True)
    assert get_compatible_transfer_target(ANALYSIS_MODE) is None


def test_get_compatible_transfer_target_by_node_modes():
    target_id = insert_node("test_target_node", NODE_STATUS_RUNNING, any_mode=False)

    # no node_modes entry means not compatible
    assert get_compatible_transfer_target(ANALYSIS_MODE) is None

    # an explicit node_modes entry makes it compatible
    add_node_mode(target_id, ANALYSIS_MODE)
    target = get_compatible_transfer_target(ANALYSIS_MODE)
    assert target is not None
    assert target[0] == target_id


def test_get_compatible_transfer_target_excludes_non_running():
    insert_node("test_draining_node", NODE_STATUS_DRAINING, any_mode=True)
    insert_node("test_stopped_node", NODE_STATUS_STOPPED, any_mode=True)
    assert get_compatible_transfer_target(ANALYSIS_MODE) is None


def test_transfer_delayed_analysis(monkeypatch):
    target_id = insert_node("test_target_node", NODE_STATUS_RUNNING, any_mode=True)
    _uuid, storage_dir = create_delayed_root()
    remote_storage_dir = f"data/test_target_node/{_uuid[0:3]}/{_uuid}"

    upload_calls = []

    def fake_upload(uuid, source_dir, **kwargs):
        upload_calls.append((uuid, source_dir, kwargs))
        return {"result": True, "storage_dir": remote_storage_dir}

    import ace_api
    monkeypatch.setattr(ace_api, "upload", fake_upload)

    assert transfer_delayed_analysis() == (1, 0, 0)

    # the upload pushed the local storage to the target node
    assert len(upload_calls) == 1
    assert upload_calls[0][0] == _uuid
    assert upload_calls[0][2]["sync"] is False
    assert upload_calls[0][2]["overwrite"] is True
    assert upload_calls[0][2]["remote_host"] == "test_target_node:443"

    # the delayed analysis row points at the target node with the target's storage_dir
    node_id, new_storage_dir, delayed_until = get_delayed_row(_uuid)
    assert node_id == target_id
    assert new_storage_dir == remote_storage_dir
    assert delayed_until is not None

    # the local storage was removed and the lock released
    assert not os.path.isdir(os.path.join(get_base_dir(), storage_dir))
    assert lock_count() == 0


def test_transfer_delayed_analysis_no_compatible_node(caplog):
    _uuid, storage_dir = create_delayed_root()

    transferred, untransferable, skipped = transfer_delayed_analysis()
    assert (transferred, untransferable, skipped) == (0, 1, 0)
    assert "no compatible node available" in caplog.text

    # nothing moved
    node_id, unchanged_storage_dir, _ = get_delayed_row(_uuid)
    assert node_id == local_node_id()
    assert unchanged_storage_dir == storage_dir
    assert os.path.isdir(os.path.join(get_base_dir(), storage_dir))

    # untransferable delayed analysis does not block the drain
    set_node_status(local_node_id(), NODE_STATUS_DRAINING)
    assert check_and_mark_drained(local_node_id(), expected_delayed_count=untransferable)
    assert get_node_status(local_node_id()) == NODE_STATUS_DRAINED


def test_transfer_delayed_analysis_skips_workload(monkeypatch):
    insert_node("test_target_node", NODE_STATUS_RUNNING, any_mode=True)
    _uuid, storage_dir = create_delayed_root()

    # a workload row for the same uuid means the root moves through the normal transfer path
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""INSERT INTO workload ( uuid, node_id, analysis_mode, company_id, storage_dir, insert_date )
                          VALUES ( %s, %s, %s, %s, %s, NOW() )""",
                       (_uuid, local_node_id(), ANALYSIS_MODE, get_global_runtime_settings().company_id, storage_dir))
        db.commit()

    def fail_upload(*args, **kwargs):
        raise AssertionError("upload should not be called")

    import ace_api
    monkeypatch.setattr(ace_api, "upload", fail_upload)

    assert transfer_delayed_analysis() == (0, 0, 0)


def test_transfer_delayed_analysis_skips_locked(monkeypatch):
    insert_node("test_target_node", NODE_STATUS_RUNNING, any_mode=True)
    _uuid, storage_dir = create_delayed_root()

    from saq.database.util.locking import acquire_lock, release_lock
    lock_uuid = str(uuidlib.uuid4())
    assert acquire_lock(_uuid, lock_uuid)

    try:
        def fail_upload(*args, **kwargs):
            raise AssertionError("upload should not be called")

        import ace_api
        monkeypatch.setattr(ace_api, "upload", fail_upload)

        assert transfer_delayed_analysis() == (0, 0, 0)
    finally:
        release_lock(_uuid, lock_uuid)


def test_transfer_delayed_analysis_missing_storage_dir_response(monkeypatch):
    insert_node("test_target_node", NODE_STATUS_RUNNING, any_mode=True)
    _uuid, storage_dir = create_delayed_root()

    def fake_upload(uuid, source_dir, **kwargs):
        # simulate a target node running an older version that does not return the storage_dir
        return {"result": True}

    import ace_api
    monkeypatch.setattr(ace_api, "upload", fake_upload)

    assert transfer_delayed_analysis() == (0, 0, 1)

    # nothing moved and the local storage is intact for the retry
    node_id, unchanged_storage_dir, _ = get_delayed_row(_uuid)
    assert node_id == local_node_id()
    assert unchanged_storage_dir == storage_dir
    assert os.path.isdir(os.path.join(get_base_dir(), storage_dir))
    assert lock_count() == 0


def test_transfer_delayed_analysis_upload_failure(monkeypatch):
    insert_node("test_target_node", NODE_STATUS_RUNNING, any_mode=True)
    _uuid, storage_dir = create_delayed_root()

    def fake_upload(uuid, source_dir, **kwargs):
        raise RuntimeError("connection refused")

    import ace_api
    monkeypatch.setattr(ace_api, "upload", fake_upload)

    assert transfer_delayed_analysis() == (0, 0, 1)

    # nothing moved and the lock was released for the retry
    node_id, unchanged_storage_dir, _ = get_delayed_row(_uuid)
    assert node_id == local_node_id()
    assert os.path.isdir(os.path.join(get_base_dir(), storage_dir))
    assert lock_count() == 0


@pytest.mark.integration
def test_get_work_target_remote_pull_blocked_while_draining():
    from saq.database.util.node import clear_node_status_cache
    from saq.engine.configuration_manager import ConfigurationManager
    from saq.engine.engine_configuration import EngineConfiguration
    from saq.engine.node_manager.node_manager_factory import create_node_manager
    from saq.engine.workload_manager.database import DatabaseWorkloadManager

    class StubLockManager:
        lock_uuid = "00000000-0000-0000-0000-000000000000"

        def __init__(self):
            self.acquire_count = 0

        def acquire_lock(self, uuid):
            self.acquire_count += 1
            return False

        def release_lock(self, uuid):
            pass

    configuration_manager = ConfigurationManager(EngineConfiguration())
    node_manager = create_node_manager(configuration_manager)
    node_manager.initialize_node()

    lock_manager = StubLockManager()
    workload_manager = DatabaseWorkloadManager(
        lock_manager=lock_manager,
        configuration_manager=configuration_manager,
        node_manager=node_manager)

    # remote work available on another node
    # the analysis mode must be one the engine supports locally (see local_analysis_modes in the unittest config)
    supported_mode = configuration_manager.config.local_analysis_modes[0]
    remote_node_id = insert_node("test_remote_node", NODE_STATUS_RUNNING, any_mode=True)
    _uuid = str(uuidlib.uuid4())
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""INSERT INTO workload ( uuid, node_id, analysis_mode, company_id, storage_dir, insert_date )
                          VALUES ( %s, %s, %s, %s, %s, NOW() )""",
                       (_uuid, remote_node_id, supported_mode, get_global_runtime_settings().company_id, f"data/test/{_uuid}"))
        db.commit()

    try:
        # a draining node does not pull remote work at all
        set_node_status(local_node_id(), NODE_STATUS_DRAINING)
        clear_node_status_cache()
        assert workload_manager.get_work_target(priority=False, local=False) is None
        assert lock_manager.acquire_count == 0

        # a running node does (the lock attempt proves the work was selected)
        set_node_status(local_node_id(), NODE_STATUS_RUNNING)
        clear_node_status_cache()
        assert workload_manager.get_work_target(priority=False, local=False) is None
        assert lock_manager.acquire_count == 1

        # local work acquisition is unaffected by draining
        set_node_status(local_node_id(), NODE_STATUS_DRAINING)
        clear_node_status_cache()
        with get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("UPDATE workload SET node_id = %s WHERE uuid = %s", (local_node_id(), _uuid))
            db.commit()

        assert workload_manager.get_work_target(priority=False, local=True) is None
        assert lock_manager.acquire_count == 2
    finally:
        clear_node_status_cache()
