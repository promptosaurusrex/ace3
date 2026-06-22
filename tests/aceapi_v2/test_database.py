"""Tests for aceapi_v2 async engine connection lifecycle / stale-connection recovery."""

import pytest
from sqlalchemy import text

from aceapi_v2.database import POOL_RECYCLE_SECONDS, create_engine_for


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
