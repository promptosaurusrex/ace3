"""Tests for aceapi_v2 async engine connection lifecycle / stale-connection recovery."""

import pytest
from sqlalchemy import text

from aceapi_v2.database import POOL_RECYCLE_SECONDS, _get_engine, create_engine_for


@pytest.mark.unit
@pytest.mark.asyncio
async def test_get_engine_same_loop_returns_same_engine():
    """repeated lookups within one event loop must return the identical engine

    the engine is cached per running loop, so two calls on the same loop share a
    pool rather than building a fresh engine each time."""
    assert _get_engine() is _get_engine()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_get_engine_distinct_per_event_loop():
    """each event loop must get its own engine/pool -- regression guard for the
    cross-loop binding hazard

    aiomysql connections are bound to the loop that created them, so a single
    process-global engine shared between uvicorn's serving loop and sync.py's
    background-thread loop would corrupt its pool. this drives _get_engine() from
    the running test loop and from sync.py's background loop and asserts the two
    engines (and their pools) are distinct objects."""
    from aceapi_v2.sync import run_async

    engine_this_loop = _get_engine()

    async def _engine_on_background_loop():
        return _get_engine()

    # run_async runs the coroutine on sync.py's persistent background-thread loop
    engine_background_loop = run_async(_engine_on_background_loop())

    assert engine_this_loop is not engine_background_loop
    assert engine_this_loop.sync_engine.pool is not engine_background_loop.sync_engine.pool


@pytest.mark.unit
def test_engine_configured_for_stale_connection_recovery():
    """the async engine must keep the pool settings that recover stale connections

    pool_pre_ping validates a connection on checkout (transparently reconnecting
    if it has gone stale) and pool_recycle proactively retires connections before
    MySQL closes them. guards against silently dropping either setting."""
    engine = create_engine_for("ace")
    try:
        pool = engine.sync_engine.pool
        assert pool._pre_ping is True
        assert pool._recycle == POOL_RECYCLE_SECONDS
    finally:
        engine.sync_engine.dispose()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_recovers_from_stale_pooled_connection():
    """a dead pooled connection must not surface an error to the caller

    simulates "MySQL server has gone away" by killing a pooled connection
    server-side (the realistic case of MySQL closing an idle connection), then
    asserts the next checkout still succeeds because pool_pre_ping detects the
    dead connection and transparently reconnects."""
    engine = create_engine_for("ace")
    # a separate engine (separate pool) so the KILL targets only the connection
    # pooled by ``engine``, not the connection issuing the KILL
    killer_engine = create_engine_for("ace")
    try:
        # check out a connection, record its server-side id, return it to the pool
        async with engine.connect() as conn:
            conn_id = (await conn.execute(text("SELECT CONNECTION_ID()"))).scalar()
            assert (await conn.execute(text("SELECT 1"))).scalar() == 1

        # kill that now-pooled connection from a different connection
        async with killer_engine.connect() as killer:
            await killer.execute(text("KILL %s" % conn_id))

        # the pooled connection is dead -- the next checkout must transparently
        # reconnect via pool_pre_ping rather than raising OperationalError
        async with engine.connect() as conn:
            assert (await conn.execute(text("SELECT 1"))).scalar() == 1
    finally:
        await engine.dispose()
        await killer_engine.dispose()
