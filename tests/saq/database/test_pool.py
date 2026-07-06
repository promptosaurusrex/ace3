from multiprocessing import Pipe, Process
import threading
import pytest

from saq.configuration.config import get_config, get_database_config
from saq.constants import DB_ACE
from saq.database.pool import execute_with_db_cursor, get_db_connection, get_pool, reset_pools
from saq.environment import get_global_runtime_settings, get_spawn_init_hooks, spawn_process_target
from tests.saq.helpers import log_count

@pytest.mark.unit
def test_execute_with_db_cursor():
    def _target(db, cursor, param1):
        assert param1 == "test"
        cursor.execute("SELECT 1")
        assert cursor.fetchone() == (1,)
        db.commit()

    execute_with_db_cursor(DB_ACE, _target, "test")

@pytest.mark.unit
def test_connection():
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT 1")

@pytest.mark.unit
def test_pooling():
    get_pool().clear()
    with get_db_connection() as db_1:
        # we should have one database connection ready
        assert get_pool().in_use_count == 1
        assert get_pool().available_count == 0
        with get_db_connection() as db_2:
            assert get_pool().in_use_count == 2
            assert get_pool().available_count ==0
            assert db_1 is not db_2

        assert get_pool().in_use_count == 1
        assert get_pool().available_count == 1

    assert get_pool().in_use_count == 0
    assert get_pool().available_count == 2

@pytest.mark.integration
def test_pooling_old_connection():
    get_pool().clear()

    # make them invalid immediately
    get_database_config(DB_ACE).max_connection_lifetime = "00:00:00"

    # this is needed to reset the timeouts on the existing connections
    reset_pools()

    with get_db_connection() as _:
        pass

    assert log_count('got new database connection to') ==  1

    with get_db_connection() as _:
        pass

    assert log_count('got new database connection to') == 2

    # change it back and then we should start re-using the connections again
    get_database_config(DB_ACE).max_connection_lifetime = "00:01:00"
    reset_pools()

    with get_db_connection() as _:
        pass

    assert log_count('got new database connection to') == 3

    with get_db_connection() as _:
        pass

    assert log_count('got new database connection to') == 3

@pytest.mark.integration
def test_pooling_without_contextmanager():
    get_pool().clear()
    db = get_pool().get_connection()

    assert get_pool().in_use_count == 1
    assert get_pool().available_count == 0

    c = db.cursor()
    c.execute("SELECT 1")
    db.commit()
    get_pool().return_connection(db)

    assert get_pool().in_use_count == 0
    assert get_pool().available_count == 1

@pytest.mark.integration
def test_pooling_bad_sql():
    get_pool().clear()
    with get_db_connection() as db_1:

        assert get_pool().in_use_count == 1
        assert get_pool().available_count == 0

        with pytest.raises(Exception):
            c = db_1.cursor()
            c.execute("INVALID SQL")

    assert get_pool().in_use_count == 0
    assert get_pool().available_count == 1

    with get_db_connection() as db_1:

        assert get_pool().in_use_count == 1
        assert get_pool().available_count == 0

        c = db_1.cursor()
        c.execute("SELECT 1")
        c.fetchone()
        db_1.commit()

    assert get_pool().in_use_count == 0
    assert get_pool().available_count == 1

@pytest.mark.integration
def test_pooling_broken_connection():
    get_pool().clear()
    with get_db_connection() as db_1:

        assert get_pool().in_use_count == 1
        assert get_pool().available_count == 0
        db_1.close()

    assert get_pool().in_use_count == 0
    assert get_pool().available_count == 0

    with get_db_connection() as db_1:

        assert get_pool().in_use_count == 1
        assert get_pool().available_count == 0

        c = db_1.cursor()
        c.execute("SELECT 1")
        c.fetchone()
        db_1.commit()

    assert get_pool().in_use_count == 0
    assert get_pool().available_count == 1

    # close the connection while not being used
    for connection in get_pool().available:
        connection.close()

    with get_db_connection() as db_1:

        assert get_pool().in_use_count == 1
        assert get_pool().available_count == 0

        c = db_1.cursor()
        c.execute("SELECT 1")
        c.fetchone()
        db_1.commit()

@pytest.mark.integration
def test_pooling_threaded():
    get_pool().clear()

    with get_db_connection() as conn_1:
        assert get_pool().in_use_count == 1
        assert get_pool().available_count == 0

        def f():
            with get_db_connection() as conn_2:
                assert conn_1 is not conn_2
                assert get_pool().in_use_count == 2
                assert get_pool().available_count == 0

            # but asked a second time this should be the same as before
            with get_db_connection() as conn_3:
                assert conn_3 is conn_2
                assert get_pool().in_use_count == 2
                assert get_pool().available_count == 0
            
        assert get_pool().in_use_count == 1
        assert get_pool().available_count == 0
        t = threading.Thread(target=f)
        t.start()
        t.join()
                
    assert get_pool().in_use_count == 0
    assert get_pool().available_count == 2

    # make sure we can get, and use, the connection created in the other thread

    conn_1 = get_pool().get_connection()
    conn_2 = get_pool().get_connection()

    assert get_pool().in_use_count == 2
    assert get_pool().available_count == 0

    c = conn_2.cursor()
    c.execute("SELECT 1")
    c.fetchone()

    get_pool().return_connection(conn_1)
    get_pool().return_connection(conn_2)

    assert get_pool().in_use_count == 0
    assert get_pool().available_count == 2

def _pooling_multi_process_child(child_pipe, parent_conn_id):
    # runs in a spawned child (module-level so it is picklable under forkserver); verifies the
    # connection pool is process-isolated. The pipe end is passed as an argument rather than
    # inherited via fork, and the child is routed through spawn_process_target so it has a
    # fully initialized environment (config, database).
    # a freshly spawned process starts with an empty pool
    child_pipe.send(get_pool().in_use_count == 0)
    child_pipe.send(get_pool().available_count == 0)

    with get_db_connection() as conn_2:
        # the child must have its own distinct server-side connection, not the parent's
        cursor = conn_2.cursor()
        cursor.execute("SELECT CONNECTION_ID()")
        child_conn_id = cursor.fetchone()[0]
        child_pipe.send(child_conn_id != parent_conn_id)
        child_pipe.send(get_pool().in_use_count == 1)
        child_pipe.send(get_pool().available_count == 0)

    child_pipe.send(get_pool().in_use_count == 0)
    child_pipe.send(get_pool().available_count == 1)

@pytest.mark.system
def test_pooling_multi_process():
    get_pool().clear()
    parent_pipe, child_pipe = Pipe()
    with get_db_connection() as conn_1:
        assert get_pool().in_use_count == 1
        assert get_pool().available_count == 0

        cursor = conn_1.cursor()
        cursor.execute("SELECT CONNECTION_ID()")
        parent_conn_id = cursor.fetchone()[0]

        process = Process(
            target=spawn_process_target,
            args=(get_config(), get_global_runtime_settings(), get_spawn_init_hooks(),
                  _pooling_multi_process_child, child_pipe, parent_conn_id),
        )
        process.start()

        assert parent_pipe.recv()
        assert parent_pipe.recv()
        assert parent_pipe.recv()
        assert parent_pipe.recv()

        process.join()

    assert get_pool().in_use_count == 0
    assert get_pool().available_count == 1

    with get_db_connection() as conn_4:
        assert get_pool().in_use_count == 1
        assert get_pool().available_count == 0
        assert conn_1 is conn_4