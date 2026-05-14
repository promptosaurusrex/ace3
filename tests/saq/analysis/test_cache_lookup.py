"""Integration tests for saq.analysis.cache.get_cached_delta (Phase 3 Step 3.4)."""
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
import zstandard

from saq.analysis.blob_store import LocalHardlinkBlobStore
from saq.analysis.cache import (
    generate_cache_key,
    get_cached_delta,
    put_cached_delta,
)
from saq.analysis.module_execution_delta import (
    ModuleExecutionDelta,
    ObservableDiff,
    RootDiff,
)
from saq.configuration.config import get_config
from saq.database.pool import get_db_connection


@pytest.fixture
def blob_store(tmp_path):
    return LocalHardlinkBlobStore(str(tmp_path / "blob_store"))


def _make_module(name=None, ttl=timedelta(hours=1), version=1, extended=None):
    return SimpleNamespace(
        config=SimpleNamespace(name=name or f"mod_{uuid4().hex[:8]}"),
        version=version,
        cache_ttl=ttl,
        extended_version=extended or {},
    )


def _make_observable(o_type="url", value="https://example.com/", time=None):
    return SimpleNamespace(type=o_type, value=value, time=time)


def _make_delta(
    module,
    observable_type="url",
    observable_value="https://example.com/",
    analysis=None,
):
    obs = _make_observable(observable_type, observable_value)
    delta = ModuleExecutionDelta(
        module_path=f"saq.modules.test.{module.config.name}:{module.config.name}Analysis",
        module_instance=None,
        module_version=module.version,
        observable_uuid=str(uuid4()),
        observable_type=observable_type,
        observable_value=observable_value,
        created_at=datetime.now(timezone.utc).isoformat(),
        execution_time_ms=42,
        target_observable_diff=ObservableDiff(added_tags=["t1"]),
        new_observables=[],
        root_diff=RootDiff(),
        analysis=analysis,
    )
    delta.cache_key = generate_cache_key(obs, module)
    return delta


def _delete_cache_row(cache_key):
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("DELETE FROM blob_refs WHERE referrer_id = %s", (cache_key,))
        cursor.execute("DELETE FROM analysis_result_cache WHERE cache_key = %s", (cache_key,))
        db.commit()


def _set_expires_at(cache_key, sql_expr):
    """Force expires_at to a specific SQL expression for testing TTL paths."""
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute(
            f"UPDATE analysis_result_cache SET expires_at = {sql_expr} WHERE cache_key = %s",
            (cache_key,),
        )
        db.commit()


def _write_raw_row(cache_key, module, delta_dict, has_blob_refs=False):
    """Insert a raw row bypassing put_cached_delta — for testing legacy
    shapes and corruption paths.
    """
    delta_json = json.dumps(delta_dict, sort_keys=True, default=str).encode("utf-8")
    delta_zstd = zstandard.ZstdCompressor(level=3).compress(delta_json)
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO analysis_result_cache "
            "(cache_key, module_name, module_version, observable_type, observable_value, "
            " delta_zstd, delta_uncompressed_size, has_blob_refs, expires_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, DATE_ADD(NOW(), INTERVAL 1 HOUR))",
            (
                cache_key,
                module.config.name,
                module.version,
                "url",
                "https://example.com/",
                delta_zstd,
                len(delta_json),
                has_blob_refs,
            ),
        )
        db.commit()


class TestGetCachedDelta:

    @pytest.mark.integration
    def test_module_not_opted_in_returns_none(self, blob_store):
        module = _make_module(ttl=None)
        obs = _make_observable()
        assert get_cached_delta(obs, module, blob_store) is None

    @pytest.mark.integration
    def test_miss_logs_not_found(self, blob_store, caplog):
        module = _make_module()
        obs = _make_observable()
        with caplog.at_level(logging.INFO):
            assert get_cached_delta(obs, module, blob_store) is None
        misses = [r for r in caplog.records if "analysis cache miss" in r.getMessage()]
        assert misses
        msg = misses[0].getMessage()
        assert "reason=not_found" in msg
        assert f"module_name={module.config.name}" in msg
        assert "observable_value=https://example.com/" in msg
        # SimpleNamespace stub has no analysis_tree_manager — the defensive
        # getattr chain must fall back gracefully rather than raise.
        assert "root_uuid=<unknown>" in msg
        assert misses[0].observable_value == "https://example.com/"

    @pytest.mark.integration
    def test_hit_round_trips(self, blob_store):
        module = _make_module()
        obs = _make_observable()
        delta = _make_delta(
            module,
            analysis={
                "module_path": "saq.modules.test:Dummy",
                "details": {"foo": "bar"},
                "completed": True,
                "delayed": False,
            },
        )
        try:
            assert put_cached_delta(delta, module, blob_store) is True
            recovered = get_cached_delta(obs, module, blob_store)
            assert recovered is not None
            assert recovered.observable_value == "https://example.com/"
            assert recovered.target_observable_diff.added_tags == ["t1"]
            assert recovered.analysis["details"] == {"foo": "bar"}
        finally:
            _delete_cache_row(delta.cache_key)

    @pytest.mark.integration
    def test_expired_row_excluded(self, blob_store):
        module = _make_module()
        obs = _make_observable()
        delta = _make_delta(module, analysis={"module_path": "x", "details": {}})
        try:
            put_cached_delta(delta, module, blob_store)
            _set_expires_at(delta.cache_key, "DATE_SUB(NOW(), INTERVAL 1 HOUR)")
            assert get_cached_delta(obs, module, blob_store) is None
        finally:
            _delete_cache_row(delta.cache_key)

    @pytest.mark.integration
    def test_legacy_shape_returns_miss(self, blob_store, caplog):
        """Step 3.4 legacy guard: rows without `details` in analysis dict
        are pre-Step-3.1 and must be treated as cache miss with reason
        ``legacy_no_details`` so the executor falls through to the live
        run, which overwrites the row.
        """
        module = _make_module()
        obs = _make_observable()
        cache_key = generate_cache_key(obs, module)
        legacy_dict = {
            "module_path": "saq.modules.test.legacy:Legacy",
            "module_version": 1,
            "observable_uuid": str(uuid4()),
            "observable_type": "url",
            "observable_value": "https://example.com/",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "execution_time_ms": 10,
            "analysis": {
                "module_path": "saq.modules.test:LegacyAnalysis",
                "summary": "old shape",
                "completed": True,
                # NOTE: no "details" key — the legacy bug.
            },
        }
        try:
            _write_raw_row(cache_key, module, legacy_dict)
            with caplog.at_level(logging.INFO):
                assert get_cached_delta(obs, module, blob_store) is None
            misses = [r for r in caplog.records if "analysis cache miss" in r.getMessage()]
            assert misses
            assert "reason=legacy_no_details" in misses[0].getMessage()
        finally:
            _delete_cache_row(cache_key)

    @pytest.mark.integration
    def test_blob_ref_inlined_on_lookup(self, blob_store):
        """When a row has has_blob_refs=True, the lookup must fetch the
        blob and inline it back into ``delta.analysis['details']``.
        """
        module = _make_module()
        obs = _make_observable()
        # 32 KiB triggers the spill path (default threshold = 16 KiB)
        big_details = {"payload": "x" * (32 * 1024)}
        delta = _make_delta(
            module,
            analysis={
                "module_path": "saq.modules.test:Dummy",
                "details": big_details,
                "completed": True,
            },
        )
        try:
            assert put_cached_delta(delta, module, blob_store) is True
            recovered = get_cached_delta(obs, module, blob_store)
            assert recovered is not None
            # Details should be the original dict, not the {"__blob_ref__": ...} pointer.
            assert recovered.analysis["details"] == big_details
            assert "__blob_ref__" not in recovered.analysis["details"]
        finally:
            _delete_cache_row(delta.cache_key)

    @pytest.mark.integration
    def test_blob_missing_returns_miss(self, blob_store, caplog):
        """If the referenced blob has been GC'd, the lookup must treat the
        row as a miss (not silently return a delta with a blob-ref pointer).
        """
        module = _make_module()
        obs = _make_observable()
        big_details = {"payload": "x" * (32 * 1024)}
        delta = _make_delta(
            module,
            analysis={
                "module_path": "saq.modules.test:Dummy",
                "details": big_details,
                "completed": True,
            },
        )
        try:
            assert put_cached_delta(delta, module, blob_store) is True

            # Wipe the underlying blob — simulates GC ahead of cache TTL.
            blob_root = blob_store.root_dir
            for dirpath, _dirs, files in os.walk(blob_root):
                for f in files:
                    os.unlink(os.path.join(dirpath, f))

            with caplog.at_level(logging.INFO):
                assert get_cached_delta(obs, module, blob_store) is None
            warns = [r for r in caplog.records if "missing blob" in r.getMessage()]
            assert warns
            misses = [r for r in caplog.records if "analysis cache miss" in r.getMessage()]
            assert misses
            assert "reason=blob_missing" in misses[-1].getMessage()
        finally:
            _delete_cache_row(delta.cache_key)

    @pytest.mark.integration
    def test_kill_switch_disables_lookup(self, blob_store, monkeypatch):
        """Global ``analysis_cache.enabled`` flag covers reads as well as
        writes — no separate ``reads_enabled`` switch.
        """
        module = _make_module()
        obs = _make_observable()
        delta = _make_delta(
            module,
            analysis={"module_path": "x", "details": {}, "completed": True},
        )
        try:
            put_cached_delta(delta, module, blob_store)
            monkeypatch.setattr(get_config().analysis_cache, "enabled", False)
            assert get_cached_delta(obs, module, blob_store) is None
        finally:
            _delete_cache_row(delta.cache_key)
