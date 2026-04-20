"""Analysis result cache — write path, key generation, pruning.

This module persists ``ModuleExecutionDelta`` records from successful module
executions so that future analyses of the same observable can reuse the work.
Phase 2 ships the write path only; reads/replay land in Phase 3.

Cacheability contract (design doc §A1): a module's output must be a pure
function of ``(observable.type, observable.value, observable.time,
module.name, module.version, module.extended_version)``. Modules that mutate
other observables or depend on surrounding tree state must leave
``cache_ttl = None``. The caller additionally refuses to cache deltas that
contain removals (§A4) as a safety net.

Size discipline (design doc §A3):

- Every delta is zstd-compressed before it hits the DB.
- ``analysis.details`` dicts larger than ``DETAILS_SPILL_THRESHOLD_BYTES``
  uncompressed are spilled to the blob store and replaced with a
  ``{"__blob_ref__": "<sha>"}`` pointer in the cached delta.
- Compressed deltas over ``MAX_COMPRESSED_DELTA_BYTES`` are refused outright
  and logged as a warning.
"""

import hashlib
import json
import logging
import time
from typing import TYPE_CHECKING, Optional

import zstandard
from sqlalchemy import delete, func, select, text
from sqlalchemy.dialects.mysql import insert as mysql_insert

from saq.analysis.blob_store import REFERRER_KIND_CACHE_ROW, BlobStore
from saq.configuration.config import get_config
from saq.database.model import AnalysisResultCache, BlobRef
from saq.database.pool import get_db

if TYPE_CHECKING:
    from saq.analysis.module_execution_delta import ModuleExecutionDelta
    from saq.analysis.observable import Observable


# zstd level 3 is a good default — the JSON-to-bytes ratio is near optimal by
# level 3 for our payload shape and the CPU cost is negligible next to the
# module execution we're avoiding on replay.
ZSTD_COMPRESSION_LEVEL = 3

# Spill analysis.details to the blob store when its uncompressed serialized
# size exceeds this. See design doc §A3 Layer 2.
DETAILS_SPILL_THRESHOLD_BYTES = 16 * 1024

# Refuse to cache compressed deltas above this size. See design doc §A3 Layer 3.
MAX_COMPRESSED_DELTA_BYTES = 1 * 1024 * 1024

# How many rows the prune sweep deletes per batch. Keeps lock windows short.
PRUNE_BATCH_SIZE = 1000


def generate_cache_key(observable: "Observable", module) -> Optional[str]:
    """Mirror of ace2-core's ``generate_cache_key`` — sha256 over observable
    identity + module identity + extended version.

    Returns None when the module hasn't opted into caching (``cache_ttl is
    None``), signalling that callers should skip cache operations entirely.
    """
    if module.cache_ttl is None:
        return None

    h = hashlib.sha256()
    h.update(observable.type.encode("utf-8", "ignore"))
    h.update(observable.value.encode("utf-8", "ignore"))
    if observable.time:
        h.update(str(observable.time.timestamp()).encode("utf-8", "ignore"))
    h.update(module.config.name.encode("utf-8", "ignore"))
    h.update(str(module.version).encode("utf-8", "ignore"))
    for key in sorted(module.extended_version):
        h.update(module.extended_version[key].encode("utf-8", "ignore"))
    return h.hexdigest()


def _maybe_spill_details(delta_dict: dict, blob_store: BlobStore, cache_key: str) -> bool:
    """Move ``delta_dict['analysis']['details']`` into the blob store when it's
    large enough to hurt the cache table.

    Mutates ``delta_dict`` in place: ``details`` is replaced with a
    ``{"__blob_ref__": "<sha>"}`` pointer, and a ``blob_refs`` row is written
    linking the blob to the cache key.

    Returns True if a spill happened (i.e. the cache row has blob refs).
    """
    analysis = delta_dict.get("analysis")
    if not isinstance(analysis, dict):
        return False
    details = analysis.get("details")
    if details is None:
        return False

    # Serialize separately so we can both measure and avoid double-serializing.
    details_bytes = json.dumps(details, sort_keys=True, default=str).encode("utf-8")
    if len(details_bytes) < DETAILS_SPILL_THRESHOLD_BYTES:
        return False

    sha = blob_store.put(details_bytes)
    blob_store.reference(sha, REFERRER_KIND_CACHE_ROW, cache_key)
    analysis["details"] = {"__blob_ref__": sha}
    return True


def put_cached_delta(
    delta: "ModuleExecutionDelta",
    module,
    blob_store: BlobStore,
) -> bool:
    """Persist a successful module execution's delta.

    Returns True if a cache row was written, False otherwise (caller passed a
    module with no ``cache_ttl``, the kill switch is off, the delta had
    removals, or the compressed payload exceeded the size cap).

    All DB failures are caught and logged — this function must never raise
    into the executor.
    """
    try:
        if module.cache_ttl is None:
            return False
        if delta.has_removals:
            logging.warning(
                "refusing to cache delta for %s on observable %s:%s — contains removals",
                module.config.name, delta.observable_type, delta.observable_value,
            )
            return False
        if not get_config().global_settings.analysis_cache_enabled:
            return False

        cache_key = delta.cache_key
        if cache_key is None:
            # Caller didn't set it — compute now.
            cache_key = generate_cache_key(_ObservableShim(delta), module)
            delta.cache_key = cache_key
        if cache_key is None:
            return False

        delta_dict = delta.to_dict()
        has_blob_refs = _maybe_spill_details(delta_dict, blob_store, cache_key)

        delta_json = json.dumps(delta_dict, sort_keys=True, default=str).encode("utf-8")
        uncompressed_size = len(delta_json)
        compressor = zstandard.ZstdCompressor(level=ZSTD_COMPRESSION_LEVEL)
        delta_zstd = compressor.compress(delta_json)

        if len(delta_zstd) > MAX_COMPRESSED_DELTA_BYTES:
            logging.warning(
                "refusing to cache delta for %s on %s:%s — compressed size %d exceeds cap %d",
                module.config.name, delta.observable_type, delta.observable_value,
                len(delta_zstd), MAX_COMPRESSED_DELTA_BYTES,
            )
            # If we spilled details but are bailing out, unreference the blob
            # so the prune/GC story doesn't hold onto it for a cache row that
            # never got written.
            if has_blob_refs:
                for sha in _extract_blob_refs(delta_dict):
                    try:
                        blob_store.unreference(sha, REFERRER_KIND_CACHE_ROW, cache_key)
                    except Exception:
                        logging.warning(
                            "failed to unreference blob %s after size-cap bailout",
                            sha, exc_info=True,
                        )
            return False

        ttl_seconds = int(module.cache_ttl.total_seconds())

        # INSERT ... ON DUPLICATE KEY UPDATE so concurrent fills and repeated
        # analyses of the same observable don't collide. Last write wins —
        # both results are valid by construction (design doc §open-question 5).
        # Compute expires_at on the DB to avoid Python-vs-DB clock drift.
        stmt = mysql_insert(AnalysisResultCache).values(
            cache_key=cache_key,
            module_name=module.config.name,
            module_version=module.version,
            observable_type=delta.observable_type,
            observable_value=delta.observable_value,
            delta_zstd=delta_zstd,
            delta_uncompressed_size=uncompressed_size,
            has_blob_refs=has_blob_refs,
            expires_at=func.date_add(
                func.now(),
                text("INTERVAL :ttl SECOND").bindparams(ttl=ttl_seconds),
            ),
        )
        stmt = stmt.on_duplicate_key_update(
            module_version=stmt.inserted.module_version,
            delta_zstd=stmt.inserted.delta_zstd,
            delta_uncompressed_size=stmt.inserted.delta_uncompressed_size,
            has_blob_refs=stmt.inserted.has_blob_refs,
            expires_at=stmt.inserted.expires_at,
        )
        write_start_ns = time.monotonic_ns()
        result = get_db().execute(stmt)
        get_db().commit()
        write_ms = (time.monotonic_ns() - write_start_ns) // 1_000_000

        # MySQL returns rowcount=1 for INSERT and rowcount=2 for an
        # ON DUPLICATE KEY UPDATE that actually changed values. Our update
        # always refreshes expires_at, so 2 reliably means "existing row
        # refreshed" and 1 means "new URL seen for the first time".
        op = "insert" if result.rowcount == 1 else "update"

        # Splunk-friendly size telemetry. Aggregate via, e.g.:
        #   index=ace "wrote analysis cache entry" | stats count,
        #     avg(compressed_bytes), p99(compressed_bytes), max(compressed_bytes) by module
        logging.info(
            "wrote analysis cache entry op=%s module=%s observable_type=%s "
            "uncompressed_bytes=%d compressed_bytes=%d has_blob_refs=%s "
            "ttl_seconds=%d write_ms=%d",
            op,
            module.config.name,
            delta.observable_type,
            uncompressed_size,
            len(delta_zstd),
            bool(has_blob_refs),
            ttl_seconds,
            write_ms,
        )
        return True
    except Exception:
        logging.warning(
            "failed to write analysis cache entry for module %s",
            getattr(getattr(module, "config", None), "name", "<unknown>"),
            exc_info=True,
        )
        try:
            get_db().rollback()
        except Exception:
            pass
        return False


def delete_for_module(module_name: str) -> int:
    """Delete all cache entries (and their blob refs) for a given module name.

    Used on rules-file reload when ``extended_version`` changes and the
    module wants to evict stale entries immediately rather than wait for TTL.
    Batched to keep lock windows short.
    """
    total = 0
    while True:
        cache_keys = get_db().scalars(
            select(AnalysisResultCache.cache_key)
            .where(AnalysisResultCache.module_name == module_name)
            .limit(PRUNE_BATCH_SIZE)
        ).all()
        if not cache_keys:
            return total

        get_db().execute(
            delete(BlobRef).where(
                BlobRef.referrer_kind == REFERRER_KIND_CACHE_ROW,
                BlobRef.referrer_id.in_(cache_keys),
            )
        )
        get_db().execute(
            delete(AnalysisResultCache).where(
                AnalysisResultCache.cache_key.in_(cache_keys)
            )
        )
        get_db().commit()

        total += len(cache_keys)
        if len(cache_keys) < PRUNE_BATCH_SIZE:
            return total


def prune(blob_store: BlobStore, batch_size: int = PRUNE_BATCH_SIZE) -> int:
    """Delete expired cache rows and drop their blob_refs in the same tx.

    Returns total rows deleted. Follows design doc §A8's sketch: SELECT ...
    FOR UPDATE SKIP LOCKED so redundant sweeps don't fight over rows; each
    batch is its own transaction so a crash mid-run doesn't lose progress.

    The backend's ``unreference`` is called *after* each batch commits for any
    housekeeping it needs — for the local backend this is a no-op (actual blob
    deletion lives in ``blob_store.gc()``).
    """
    total = 0
    while True:
        cache_keys = get_db().scalars(
            select(AnalysisResultCache.cache_key)
            .where(AnalysisResultCache.expires_at < func.now())
            .order_by(AnalysisResultCache.expires_at)
            .limit(batch_size)
            .with_for_update(skip_locked=True)
        ).all()
        if not cache_keys:
            return total

        blob_rows = get_db().execute(
            select(BlobRef.sha256, BlobRef.referrer_id).where(
                BlobRef.referrer_kind == REFERRER_KIND_CACHE_ROW,
                BlobRef.referrer_id.in_(cache_keys),
            )
        ).all()

        get_db().execute(
            delete(BlobRef).where(
                BlobRef.referrer_kind == REFERRER_KIND_CACHE_ROW,
                BlobRef.referrer_id.in_(cache_keys),
            )
        )
        get_db().execute(
            delete(AnalysisResultCache).where(
                AnalysisResultCache.cache_key.in_(cache_keys)
            )
        )
        get_db().commit()

        # Post-commit, invoke backend unreference so S3/remote backends can
        # do their own housekeeping. Local backend: no-op.
        for sha, referrer_id in blob_rows:
            try:
                blob_store.unreference(sha, REFERRER_KIND_CACHE_ROW, referrer_id)
            except Exception:
                logging.warning(
                    "blob_store.unreference failed for sha %s ref %s",
                    sha, referrer_id, exc_info=True,
                )

        total += len(cache_keys)
        if len(cache_keys) < batch_size:
            return total


def collect_stats() -> dict:
    """Snapshot the cache tables for observability.

    Returns a dict with row counts and size totals suitable for emission as
    a single Splunk log line. Runs in O(index scan) time — tiny tables plus
    the expires_at index keep this cheap even for a busy cache.
    """
    total_rows = get_db().scalar(
        select(func.count()).select_from(AnalysisResultCache)
    ) or 0
    expired_rows = get_db().scalar(
        select(func.count())
        .select_from(AnalysisResultCache)
        .where(AnalysisResultCache.expires_at < func.now())
    ) or 0
    total_uncompressed_bytes = get_db().scalar(
        select(func.coalesce(func.sum(AnalysisResultCache.delta_uncompressed_size), 0))
    ) or 0
    blob_refs_rows = get_db().scalar(
        select(func.count()).select_from(BlobRef)
    ) or 0
    modules_with_entries = get_db().scalar(
        select(func.count(func.distinct(AnalysisResultCache.module_name)))
    ) or 0
    return {
        "total_rows": int(total_rows),
        "expired_rows": int(expired_rows),
        "total_uncompressed_bytes": int(total_uncompressed_bytes),
        "blob_refs_rows": int(blob_refs_rows),
        "modules_with_entries": int(modules_with_entries),
    }


class _ObservableShim:
    """Minimal Observable-like object so ``generate_cache_key`` can accept
    either a real Observable or the denormalized fields on a
    ``ModuleExecutionDelta`` when recomputing a lost key.
    """

    __slots__ = ("type", "value", "time")

    def __init__(self, delta: "ModuleExecutionDelta"):
        self.type = delta.observable_type
        self.value = delta.observable_value
        self.time = None


def _extract_blob_refs(delta_dict: dict) -> list[str]:
    """Pull every ``__blob_ref__`` sha out of a serialized delta.

    Only used for cleanup when we abort a cache write after spilling. Keeps
    the shape shallow: we only spill ``analysis.details`` today.
    """
    refs = []
    analysis = delta_dict.get("analysis")
    if isinstance(analysis, dict):
        details = analysis.get("details")
        if isinstance(details, dict):
            sha = details.get("__blob_ref__")
            if sha:
                refs.append(sha)
    return refs
