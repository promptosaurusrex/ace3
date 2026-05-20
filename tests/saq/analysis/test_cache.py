"""Integration tests for saq.analysis.cache (put, prune, delete_for_module)."""
import json
import logging
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
import zstandard

from saq.analysis.blob_store import LocalHardlinkBlobStore, LocalHardlinkBlobStoreConfig
from saq.analysis.cache import (
    collect_stats,
    delete_for_module,
    generate_cache_key,
    prune,
    put_cached_delta,
)
from saq.analysis.module_execution_delta import (
    ModuleExecutionDelta,
    ObservableDiff,
    ObservableSpec,
    RootDiff,
)
from saq.configuration.config import get_config
from saq.constants import F_FILE
from saq.database.pool import get_db, get_db_connection


@pytest.fixture
def blob_store(tmp_path):
    return LocalHardlinkBlobStore(
        LocalHardlinkBlobStoreConfig(root_dir=str(tmp_path / "blob_store"))
    )


def _make_module(name=None, ttl=timedelta(hours=1), version=1, extended=None):
    return SimpleNamespace(
        config=SimpleNamespace(name=name or f"mod_{uuid4().hex[:8]}"),
        version=version,
        cache_ttl=ttl,
        extended_version=extended or {},
    )


def _make_delta(
    module,
    observable_type="url",
    observable_value="https://example.com/",
    analysis=None,
    has_removal=False,
    empty=False,
):
    obs = SimpleNamespace(type=observable_type, value=observable_value, time=None)
    if empty:
        target_diff = ObservableDiff()
    else:
        target_diff = ObservableDiff(
            added_tags=["t1"],
            removed_tags=["r1"] if has_removal else [],
        )
    delta = ModuleExecutionDelta(
        module_path=f"saq.modules.test.{module.config.name}:{module.config.name}Analysis",
        module_instance=None,
        module_version=module.version,
        observable_uuid=str(uuid4()),
        observable_type=observable_type,
        observable_value=observable_value,
        created_at=datetime.now(timezone.utc).isoformat(),
        execution_time_ms=42,
        target_observable_diff=target_diff,
        new_observables=[],
        root_diff=RootDiff(),
        analysis=analysis,
    )
    delta.cache_key = generate_cache_key(obs, module)
    return delta


def _row_count(cache_key):
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM analysis_result_cache WHERE cache_key = %s",
            (cache_key,),
        )
        return cursor.fetchone()[0]


def _blob_ref_count(cache_key):
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM blob_refs WHERE referrer_kind = 'cache_row' AND referrer_id = %s",
            (cache_key,),
        )
        return cursor.fetchone()[0]


def _delete_cache_row(cache_key):
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("DELETE FROM blob_refs WHERE referrer_id = %s", (cache_key,))
        cursor.execute("DELETE FROM analysis_result_cache WHERE cache_key = %s", (cache_key,))
        db.commit()


class TestPutCachedDelta:

    @pytest.mark.integration
    def test_happy_path_writes_row(self, blob_store, caplog):
        module = _make_module()
        delta = _make_delta(module)
        try:
            with caplog.at_level(logging.INFO):
                result = put_cached_delta(delta, module, blob_store)
            assert result is not None
            assert result.op == "insert"
            assert result.uncompressed_bytes > 0
            assert result.compressed_bytes > 0
            assert result.write_ms >= 0
            assert _row_count(delta.cache_key) == 1

            # Verify the payload round-trips through zstd → JSON → from_dict.
            with get_db_connection() as db:
                cursor = db.cursor()
                cursor.execute(
                    "SELECT delta_zstd, delta_uncompressed_size, has_blob_refs "
                    "FROM analysis_result_cache WHERE cache_key = %s",
                    (delta.cache_key,),
                )
                row = cursor.fetchone()
            decompressor = zstandard.ZstdDecompressor()
            dict_back = json.loads(decompressor.decompress(row[0]).decode("utf-8"))
            rebuilt = ModuleExecutionDelta.from_dict(dict_back)
            assert rebuilt.observable_value == delta.observable_value
            assert rebuilt.target_observable_diff.added_tags == ["t1"]
            assert row[1] > 0
            assert row[2] in (0, False)
        finally:
            _delete_cache_row(delta.cache_key)

    @pytest.mark.integration
    def test_repeat_write_returns_update_op(self, blob_store):
        """Second call with the same cache_key must return op=update, not insert."""
        module = _make_module()
        delta = _make_delta(module)
        try:
            first_result = put_cached_delta(delta, module, blob_store)
            assert first_result is not None
            assert first_result.op == "insert"
            # Second call — force a value change so MySQL reports rowcount=2.
            delta2 = _make_delta(
                module,
                observable_type=delta.observable_type,
                observable_value=delta.observable_value,
            )
            delta2.cache_key = delta.cache_key
            second_result = put_cached_delta(delta2, module, blob_store)
            assert second_result is not None
            assert second_result.op == "update"
        finally:
            _delete_cache_row(delta.cache_key)

    @pytest.mark.integration
    def test_skips_when_cache_ttl_is_none(self, blob_store):
        module = _make_module(ttl=None)
        delta = _make_delta(module)
        assert put_cached_delta(delta, module, blob_store) is None

    @pytest.mark.integration
    def test_refuses_delta_with_removals(self, blob_store):
        module = _make_module()
        delta = _make_delta(module, has_removal=True)
        assert put_cached_delta(delta, module, blob_store) is None
        assert _row_count(delta.cache_key) == 0

    @pytest.mark.integration
    def test_refuses_empty_delta(self, blob_store):
        """An empty delta has nothing to replay — caching it would write one
        row per observable the module merely looked at. put_cached_delta must
        refuse it, with no row written."""
        module = _make_module()
        delta = _make_delta(module, empty=True)
        assert delta.is_empty
        assert put_cached_delta(delta, module, blob_store) is None
        assert _row_count(delta.cache_key) == 0

    @pytest.mark.integration
    def test_skips_delta_with_delayed_analysis(self, blob_store, caplog):
        """Step 3.2: deltas captured mid-delay must not be cached.

        Replay would mark the analysis completed, lying about state.
        The skip is INFO-level — for delayed-analysis modules this fires
        once per intermediate cycle and is expected behavior.
        """
        module = _make_module()
        delta = _make_delta(
            module,
            analysis={
                "module_path": "saq.modules.test:Dummy",
                "details": {"x": 1},
                "delayed": True,
                "completed": False,
            },
        )
        with caplog.at_level(logging.INFO):
            assert put_cached_delta(delta, module, blob_store) is None
        assert _row_count(delta.cache_key) == 0
        skip_logs = [r for r in caplog.records if "skip_reason=still_delayed" in r.getMessage()]
        assert skip_logs
        assert skip_logs[0].levelno == logging.INFO
        # ExtraAwareFluentFormatter surfaces these as top-level JSON fields.
        assert skip_logs[0].skip_reason == "still_delayed"
        assert skip_logs[0].module_name == module.config.name

    @pytest.mark.integration
    def test_refuses_delta_with_file_observables(self, blob_store, caplog):
        """Step 3.3: file-observable replay is Phase 4 territory."""
        module = _make_module()
        delta = _make_delta(module)
        delta.new_observables = [
            ObservableSpec(
                uuid="00000000-0000-0000-0000-000000000001",
                type=F_FILE,
                value="some/file.txt",
            )
        ]
        with caplog.at_level(logging.WARNING):
            assert put_cached_delta(delta, module, blob_store) is None
        assert _row_count(delta.cache_key) == 0
        warn_logs = [r for r in caplog.records if "refusal_reason=file_observables" in r.getMessage()]
        assert warn_logs
        assert warn_logs[0].levelno == logging.WARNING
        assert warn_logs[0].refusal_reason == "file_observables"
        assert warn_logs[0].module_name == module.config.name

    @pytest.mark.integration
    def test_upsert_idempotent_on_duplicate_key(self, blob_store):
        module = _make_module()
        delta = _make_delta(module)
        try:
            put_cached_delta(delta, module, blob_store)
            # Rewrite with a different version — ON DUPLICATE KEY UPDATE
            # should update the row rather than throw.
            module2 = _make_module(name=module.config.name, version=2)
            delta2 = _make_delta(
                module2,
                observable_type=delta.observable_type,
                observable_value=delta.observable_value,
            )
            # Force the same key (even though bumping version normally mints a
            # different one) — we're testing the DB upsert contract, not key
            # derivation. Assign manually.
            delta2.cache_key = delta.cache_key
            assert put_cached_delta(delta2, module2, blob_store) is not None
            assert _row_count(delta.cache_key) == 1
            with get_db_connection() as db:
                cursor = db.cursor()
                cursor.execute(
                    "SELECT module_version FROM analysis_result_cache WHERE cache_key = %s",
                    (delta.cache_key,),
                )
                assert cursor.fetchone()[0] == 2
        finally:
            _delete_cache_row(delta.cache_key)

    @pytest.mark.integration
    def test_large_details_spill_to_blob_store(self, blob_store):
        module = _make_module()
        # 32 KiB is 2× the default analysis_cache.details_spill_bytes,
        # so this reliably triggers the blob-store spill path.
        big_details = {"payload": "x" * (32 * 1024)}
        analysis = {
            "type": "saq.modules.test:Dummy",
            "summary": "big",
            "details": big_details,
        }
        delta = _make_delta(module, analysis=analysis)
        try:
            assert put_cached_delta(delta, module, blob_store) is not None
            assert _blob_ref_count(delta.cache_key) == 1

            with get_db_connection() as db:
                cursor = db.cursor()
                cursor.execute(
                    "SELECT delta_zstd, has_blob_refs FROM analysis_result_cache "
                    "WHERE cache_key = %s",
                    (delta.cache_key,),
                )
                row = cursor.fetchone()
            assert row[1] in (1, True)
            decompressor = zstandard.ZstdDecompressor()
            dict_back = json.loads(decompressor.decompress(row[0]).decode("utf-8"))
            # Inline details should be a blob reference now, not the raw dict.
            assert "__blob_ref__" in dict_back["analysis"]["details"]
            sha = dict_back["analysis"]["details"]["__blob_ref__"]
            assert blob_store.exists(sha)
        finally:
            _delete_cache_row(delta.cache_key)

    @pytest.mark.integration
    def test_refuses_oversized_delta(self, blob_store, monkeypatch):
        # Drop the cap to something tiny so even a small analysis blows it.
        monkeypatch.setattr(
            get_config().analysis_cache, "max_compressed_bytes", 50
        )
        module = _make_module()
        delta = _make_delta(module)
        assert put_cached_delta(delta, module, blob_store) is None
        assert _row_count(delta.cache_key) == 0


class TestKillSwitch:

    @pytest.mark.integration
    def test_global_kill_switch_blocks_writes(self, blob_store, monkeypatch):
        monkeypatch.setattr(
            get_config().analysis_cache, "enabled", False
        )
        module = _make_module()
        delta = _make_delta(module)
        assert put_cached_delta(delta, module, blob_store) is None
        assert _row_count(delta.cache_key) == 0


class TestPrune:

    @pytest.mark.integration
    def test_deletes_expired_rows_and_leaves_fresh(self, blob_store):
        module = _make_module()
        fresh_delta = _make_delta(module)
        expired_delta = _make_delta(
            module, observable_value="https://expired.example/"
        )
        try:
            assert put_cached_delta(fresh_delta, module, blob_store)
            assert put_cached_delta(expired_delta, module, blob_store)

            # Force the "expired" row into the past.
            with get_db_connection() as db:
                cursor = db.cursor()
                cursor.execute(
                    "UPDATE analysis_result_cache SET expires_at = DATE_SUB(NOW(), INTERVAL 1 HOUR) "
                    "WHERE cache_key = %s",
                    (expired_delta.cache_key,),
                )
                db.commit()

            deleted = prune(blob_store)
            assert deleted >= 1
            assert _row_count(expired_delta.cache_key) == 0
            assert _row_count(fresh_delta.cache_key) == 1
        finally:
            _delete_cache_row(fresh_delta.cache_key)
            _delete_cache_row(expired_delta.cache_key)

    @pytest.mark.integration
    def test_prune_drops_blob_refs_in_same_tx(self, blob_store):
        module = _make_module()
        # 32 KiB is 2× the default analysis_cache.details_spill_bytes,
        # so this reliably triggers the blob-store spill path.
        big_details = {"payload": "x" * (32 * 1024)}
        analysis = {
            "type": "saq.modules.test:Dummy",
            "summary": "big",
            "details": big_details,
        }
        delta = _make_delta(module, analysis=analysis)
        try:
            put_cached_delta(delta, module, blob_store)
            assert _blob_ref_count(delta.cache_key) == 1

            with get_db_connection() as db:
                cursor = db.cursor()
                cursor.execute(
                    "UPDATE analysis_result_cache SET expires_at = DATE_SUB(NOW(), INTERVAL 1 HOUR) "
                    "WHERE cache_key = %s",
                    (delta.cache_key,),
                )
                db.commit()
            prune(blob_store)

            assert _row_count(delta.cache_key) == 0
            assert _blob_ref_count(delta.cache_key) == 0
        finally:
            _delete_cache_row(delta.cache_key)


class TestMaintainGlobal:

    @pytest.mark.integration
    def test_deletes_orphan_blobs_after_prune(self, blob_store):
        """maintain_global keeps referenced blobs and reclaims orphans (real blob_refs)."""
        import os
        import time

        module = _make_module()
        # 32 KiB reliably triggers the blob-store spill path
        big_details = {"payload": "x" * (32 * 1024)}
        analysis = {
            "type": "saq.modules.test:Dummy",
            "summary": "big",
            "details": big_details,
        }
        delta = _make_delta(module, analysis=analysis)
        try:
            put_cached_delta(delta, module, blob_store)
            assert _blob_ref_count(delta.cache_key) == 1

            # backdate every blob so the GC grace period doesn't protect them
            for _sha, _path in blob_store.iter_blobs():
                past = time.time() - 3600
                os.utime(_path, (past, past))

            # the blob is still referenced — maintain_global must not delete it
            stats = blob_store.maintain_global(timedelta(minutes=5))
            assert stats.blobs_deleted == 0
            assert stats.skipped_referenced == 1

            # expire and prune the cache row, dropping the blob_ref
            with get_db_connection() as db:
                cursor = db.cursor()
                cursor.execute(
                    "UPDATE analysis_result_cache SET expires_at = DATE_SUB(NOW(), INTERVAL 1 HOUR) "
                    "WHERE cache_key = %s",
                    (delta.cache_key,),
                )
                db.commit()
            prune(blob_store)
            assert _blob_ref_count(delta.cache_key) == 0

            # now the blob is an orphan — maintain_global reclaims it
            stats = blob_store.maintain_global(timedelta(minutes=5))
            assert stats.blobs_deleted == 1
        finally:
            _delete_cache_row(delta.cache_key)


class TestCollectStats:

    @pytest.mark.integration
    def test_stats_reflect_table_state(self, blob_store):
        module = _make_module()
        # 32 KiB is 2× the default analysis_cache.details_spill_bytes,
        # so this reliably triggers the blob-store spill path.
        big_details = {"payload": "x" * (32 * 1024)}
        delta_small = _make_delta(module, observable_value="https://small.example/")
        delta_big = _make_delta(
            module,
            observable_value="https://big.example/",
            analysis={"type": "saq.modules.test:Dummy", "summary": "big", "details": big_details},
        )
        try:
            before = collect_stats()
            put_cached_delta(delta_small, module, blob_store)
            put_cached_delta(delta_big, module, blob_store)
            after = collect_stats()

            assert after["total_rows"] >= before["total_rows"] + 2
            assert after["blob_refs_rows"] >= before["blob_refs_rows"] + 1
            assert after["total_uncompressed_bytes"] > before["total_uncompressed_bytes"]
            assert after["modules_with_entries"] >= 1
        finally:
            _delete_cache_row(delta_small.cache_key)
            _delete_cache_row(delta_big.cache_key)


class TestDeleteForModule:

    @pytest.mark.integration
    def test_deletes_all_rows_for_one_module(self, blob_store):
        module_name = f"dfm_{uuid4().hex[:8]}"
        module = _make_module(name=module_name)
        d1 = _make_delta(module, observable_value="https://a.example/")
        d2 = _make_delta(module, observable_value="https://b.example/")
        try:
            put_cached_delta(d1, module, blob_store)
            put_cached_delta(d2, module, blob_store)
            assert _row_count(d1.cache_key) == 1
            assert _row_count(d2.cache_key) == 1

            deleted = delete_for_module(module_name)
            assert deleted == 2
            assert _row_count(d1.cache_key) == 0
            assert _row_count(d2.cache_key) == 0
        finally:
            _delete_cache_row(d1.cache_key)
            _delete_cache_row(d2.cache_key)
