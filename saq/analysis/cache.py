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

- Every delta is zstd-compressed before it hits the DB. Compression level is
  tunable via ``analysis_cache.zstd_level``.
- ``analysis.details`` dicts larger than
  ``analysis_cache.details_spill_bytes`` (uncompressed) are spilled
  to the blob store and replaced with a ``{"__blob_ref__": "<sha>"}``
  pointer in the cached delta.
- Compressed deltas over ``analysis_cache.max_compressed_bytes``
  are refused outright and logged as a warning.
"""

import hashlib
import importlib
import json
import logging
import time
from typing import TYPE_CHECKING, Optional

import zstandard
from sqlalchemy import delete, func, select, text
from sqlalchemy.dialects.mysql import insert as mysql_insert

from saq.analysis.analysis import Analysis as _Analysis, UnknownAnalysis
from saq.analysis.blob_store import (
    REFERRER_KIND_CACHE_ROW,
    BlobNotFound,
    BlobStore,
)
from saq.analysis.module_execution_delta import ModuleExecutionDelta
from saq.analysis.module_path import SPLIT_MODULE_PATH
from saq.configuration.config import get_config
from saq.database.model import AnalysisResultCache, BlobRef
from saq.database.pool import get_db
from saq.util import parse_event_time

if TYPE_CHECKING:
    from saq.analysis.observable import Observable
    from saq.analysis.root import RootAnalysis


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
    threshold = get_config().analysis_cache.details_spill_bytes
    if len(details_bytes) < threshold:
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
                "refusing to cache delta module_name=%s observable_type=%s "
                "observable_value=%s refusal_reason=removals",
                module.config.name, delta.observable_type, delta.observable_value,
                extra={
                    "module_name": module.config.name,
                    "observable_type": delta.observable_type,
                    "observable_value": delta.observable_value,
                    "refusal_reason": "removals",
                },
            )
            return False
        # Step 3.2: refuse to cache deltas captured mid-delay. Replay path
        # unconditionally marks the analysis completed — caching a delayed
        # analysis would lie. Combined with snapshot Step 3.0, the only
        # delta that survives this gate for a delayed-analysis module is
        # the final post-delay one, which is exactly what we want to cache.
        # INFO not WARNING — for delayed modules this fires once per
        # intermediate cycle and is expected behavior.
        if delta.analysis is not None and delta.analysis.get("delayed"):
            logging.info(
                "skipping cache write module_name=%s observable_type=%s "
                "observable_value=%s skip_reason=still_delayed",
                module.config.name, delta.observable_type, delta.observable_value,
                extra={
                    "module_name": module.config.name,
                    "observable_type": delta.observable_type,
                    "observable_value": delta.observable_value,
                    "skip_reason": "still_delayed",
                },
            )
            return False
        # Step 3.3: refuse to cache deltas that would spawn file
        # observables on replay. File-byte materialization is Phase 4
        # territory; until that lands, replaying a file-spawning delta
        # against a different alert would yield observables whose backing
        # bytes don't exist in the target storage_dir.
        if delta.has_file_observables:
            logging.warning(
                "refusing to cache delta module_name=%s observable_type=%s "
                "observable_value=%s refusal_reason=file_observables",
                module.config.name, delta.observable_type, delta.observable_value,
                extra={
                    "module_name": module.config.name,
                    "observable_type": delta.observable_type,
                    "observable_value": delta.observable_value,
                    "refusal_reason": "file_observables",
                },
            )
            return False
        if not get_config().analysis_cache.enabled:
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

        analysis_cache = get_config().analysis_cache
        zstd_level = analysis_cache.zstd_level
        max_compressed_bytes = analysis_cache.max_compressed_bytes

        delta_json = json.dumps(delta_dict, sort_keys=True, default=str).encode("utf-8")
        uncompressed_size = len(delta_json)
        compressor = zstandard.ZstdCompressor(level=zstd_level)
        delta_zstd = compressor.compress(delta_json)

        if len(delta_zstd) > max_compressed_bytes:
            logging.warning(
                "refusing to cache delta module_name=%s observable_type=%s "
                "observable_value=%s refusal_reason=size_cap compressed_bytes=%d "
                "max_compressed_bytes=%d",
                module.config.name, delta.observable_type, delta.observable_value,
                len(delta_zstd), max_compressed_bytes,
                extra={
                    "module_name": module.config.name,
                    "observable_type": delta.observable_type,
                    "observable_value": delta.observable_value,
                    "refusal_reason": "size_cap",
                    "compressed_bytes": len(delta_zstd),
                    "max_compressed_bytes": max_compressed_bytes,
                },
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
                            "failed to unreference blob sha256=%s after size-cap bailout",
                            sha, exc_info=True,
                            extra={"sha256": sha},
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

        # Splunk-friendly size telemetry. With ExtraAwareFluentFormatter the
        # extras land as top-level JSON fields, so aggregations like
        # ``| stats avg(compressed_bytes), p99(compressed_bytes) by module_name``
        # work without per-query rex.
        logging.info(
            "wrote analysis cache entry op=%s module_name=%s observable_type=%s "
            "observable_value=%s root_uuid=%s uncompressed_bytes=%d "
            "compressed_bytes=%d has_blob_refs=%s ttl_seconds=%d write_ms=%d",
            op,
            module.config.name,
            delta.observable_type,
            delta.observable_value,
            delta.root_uuid or "n/a",
            uncompressed_size,
            len(delta_zstd),
            bool(has_blob_refs),
            ttl_seconds,
            write_ms,
            extra={
                "op": op,
                "module_name": module.config.name,
                "observable_type": delta.observable_type,
                "observable_value": delta.observable_value,
                "root_uuid": delta.root_uuid or "n/a",
                "uncompressed_bytes": uncompressed_size,
                "compressed_bytes": len(delta_zstd),
                "has_blob_refs": bool(has_blob_refs),
                "ttl_seconds": ttl_seconds,
                "write_ms": write_ms,
            },
        )
        return True
    except Exception:
        module_name = getattr(getattr(module, "config", None), "name", "<unknown>")
        logging.warning(
            "failed to write analysis cache entry module_name=%s",
            module_name, exc_info=True,
            extra={"module_name": module_name},
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
    batch_size = get_config().analysis_cache.prune_batch_size
    total = 0
    while True:
        cache_keys = get_db().scalars(
            select(AnalysisResultCache.cache_key)
            .where(AnalysisResultCache.module_name == module_name)
            .limit(batch_size)
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
        if len(cache_keys) < batch_size:
            return total


def prune(blob_store: BlobStore, batch_size: Optional[int] = None) -> int:
    """Delete expired cache rows and drop their blob_refs in the same tx.

    Returns total rows deleted. Follows design doc §A8's sketch: SELECT ...
    FOR UPDATE SKIP LOCKED so redundant sweeps don't fight over rows; each
    batch is its own transaction so a crash mid-run doesn't lose progress.

    The backend's ``unreference`` is called *after* each batch commits for any
    housekeeping it needs — for the local backend this is a no-op (actual blob
    deletion lives in ``blob_store.gc()``).

    ``batch_size`` defaults to ``analysis_cache.prune_batch_size``;
    tests may override it for finer-grained control.
    """
    if batch_size is None:
        batch_size = get_config().analysis_cache.prune_batch_size
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
                    "blob_store.unreference failed sha256=%s referrer_id=%s",
                    sha, referrer_id, exc_info=True,
                    extra={"sha256": sha, "referrer_id": referrer_id},
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


def _inline_blob_refs(delta_dict: dict, blob_store: BlobStore) -> None:
    """Inverse of ``_maybe_spill_details`` — walk the delta dict and replace
    every ``{"__blob_ref__": sha}`` pointer with the bytes from the blob
    store, parsed back to its original JSON shape.

    Mutates ``delta_dict`` in place. Raises ``BlobNotFound`` if any
    referenced blob is missing — caller (``get_cached_delta``) translates
    that into a cache miss.

    Currently only ``analysis.details`` ever spills, but the function is
    written to extend cleanly when other fields start spilling.
    """
    analysis = delta_dict.get("analysis")
    if not isinstance(analysis, dict):
        return
    details = analysis.get("details")
    if isinstance(details, dict) and "__blob_ref__" in details:
        sha = details["__blob_ref__"]
        with blob_store.get(sha) as fp:
            blob_bytes = fp.read()
        analysis["details"] = json.loads(blob_bytes.decode("utf-8"))


def get_cached_delta(
    observable: "Observable",
    module,
    blob_store: BlobStore,
) -> Optional[ModuleExecutionDelta]:
    """Look up a cached ``ModuleExecutionDelta`` for ``(observable, module)``.

    Returns ``None`` on any of: module not opted in (``cache_ttl is None``),
    cache disabled globally, no row, expired row, legacy pre-Step-3.1 row
    (no ``details`` key in the analysis dict), missing blob, or any
    decode/decompress failure. Misses are logged with a structured
    ``reason`` so Splunk can break them down.

    All exceptions are caught — cache lookup is best-effort and must
    never propagate into the executor.
    """
    cache_key = generate_cache_key(observable, module)
    if cache_key is None:
        return None

    if not get_config().analysis_cache.enabled:
        return None

    module_name = getattr(getattr(module, "config", None), "name", "<unknown>")
    observable_type = getattr(observable, "type", "<unknown>")
    observable_value = getattr(observable, "value", "<unknown>")
    # Derive the root_uuid from the observable's tree manager. Defensive
    # getattr chain: the observable always has the tree manager injected in
    # the real executor path, but test stubs may not — and lookup is
    # best-effort, so a missing root must never raise here.
    _tree_manager = getattr(observable, "analysis_tree_manager", None)
    _root = getattr(_tree_manager, "root_analysis", None)
    root_uuid = getattr(_root, "uuid", "<unknown>")
    cache_key_prefix = cache_key[:12]
    lookup_start_ns = time.monotonic_ns()

    def _miss(reason: str) -> None:
        lookup_ms = (time.monotonic_ns() - lookup_start_ns) // 1_000_000
        logging.info(
            "analysis cache miss module_name=%s observable_type=%s "
            "observable_value=%s root_uuid=%s cache_key_prefix=%s "
            "reason=%s lookup_ms=%d",
            module_name, observable_type, observable_value, root_uuid,
            cache_key_prefix, reason, lookup_ms,
            extra={
                "module_name": module_name,
                "observable_type": observable_type,
                "observable_value": observable_value,
                "root_uuid": root_uuid,
                "cache_key_prefix": cache_key_prefix,
                "reason": reason,
                "lookup_ms": lookup_ms,
            },
        )

    try:
        row = get_db().execute(
            select(
                AnalysisResultCache.delta_zstd,
                AnalysisResultCache.has_blob_refs,
            )
            .where(
                AnalysisResultCache.cache_key == cache_key,
                AnalysisResultCache.expires_at > func.now(),
            )
        ).first()

        if row is None:
            _miss("not_found")
            return None

        delta_zstd, has_blob_refs = row
        try:
            delta_json = zstandard.ZstdDecompressor().decompress(delta_zstd)
            delta_dict = json.loads(delta_json.decode("utf-8"))
        except Exception:
            logging.warning(
                "failed to decode cached delta module_name=%s cache_key_prefix=%s",
                module_name, cache_key_prefix, exc_info=True,
                extra={
                    "module_name": module_name,
                    "cache_key_prefix": cache_key_prefix,
                },
            )
            _miss("decode_error")
            return None

        # Step 3.4 legacy-shape guard: pre-Step-3.1 rows wrote
        # `analysis` dicts without a `details` key. Treat as miss so the
        # executor falls through to a live run, which will overwrite the
        # row via ON DUPLICATE KEY UPDATE with a Step-3.1-shaped delta.
        analysis_in_dict = delta_dict.get("analysis")
        if isinstance(analysis_in_dict, dict) and "details" not in analysis_in_dict:
            _miss("legacy_no_details")
            return None

        if has_blob_refs:
            try:
                _inline_blob_refs(delta_dict, blob_store)
            except BlobNotFound as e:
                logging.warning(
                    "cached delta references missing blob module_name=%s "
                    "cache_key_prefix=%s sha256=%s",
                    module_name, cache_key_prefix, e, exc_info=False,
                    extra={
                        "module_name": module_name,
                        "cache_key_prefix": cache_key_prefix,
                        "sha256": str(e),
                    },
                )
                _miss("blob_missing")
                return None

        try:
            delta = ModuleExecutionDelta.from_dict(delta_dict)
        except Exception:
            logging.warning(
                "failed to deserialize cached delta module_name=%s cache_key_prefix=%s",
                module_name, cache_key_prefix, exc_info=True,
                extra={
                    "module_name": module_name,
                    "cache_key_prefix": cache_key_prefix,
                },
            )
            _miss("decode_error")
            return None

        # Step 3.4 cache-key recomputation: must match by construction;
        # mismatch indicates corruption (different module identity stored
        # against this key, or a key-generation regression). Log but
        # proceed — the row is presumed good enough for replay.
        recomputed = generate_cache_key(observable, module)
        if recomputed != cache_key:
            recomputed_prefix = (recomputed or "")[:12]
            logging.warning(
                "cache_key mismatch on lookup module_name=%s observable_type=%s "
                "stored_prefix=%s recomputed_prefix=%s",
                module_name, observable_type,
                cache_key_prefix, recomputed_prefix,
                extra={
                    "module_name": module_name,
                    "observable_type": observable_type,
                    "stored_prefix": cache_key_prefix,
                    "recomputed_prefix": recomputed_prefix,
                },
            )

        return delta

    except Exception:
        logging.warning(
            "cache lookup failed module_name=%s cache_key_prefix=%s",
            module_name, cache_key_prefix, exc_info=True,
            extra={
                "module_name": module_name,
                "cache_key_prefix": cache_key_prefix,
            },
        )
        _miss("decode_error")
        return None


def apply_delta(
    root: "RootAnalysis",
    target_observable: "Observable",
    delta: ModuleExecutionDelta,
) -> None:
    """Apply a cached ``ModuleExecutionDelta`` to a target tree.

    Idempotent additive replay (design doc §5). Re-installs the analysis
    object on the target observable, adds any child observables, copies
    over tags / detections / directives / relationships / excluded_analysis
    / limited_analysis, applies scalar transitions, and applies root-level
    additions. All primitives used are idempotent — calling ``apply_delta``
    twice on the same root produces the same state as calling it once.

    Does NOT process ``other_observable_diffs`` or ``analysis_children_diffs``
    — those only exist on wide-diff captures, which are uncacheable by
    contract (``AnalysisModuleConfig`` rejects ``wide_diff + cache_ttl``).
    """
    # Defense-in-depth: wide-diff deltas should never reach this path
    # (config validation blocks the combination), but enforce explicitly.
    assert not delta.wide_diff, "wide_diff deltas are not cacheable"

    if delta.has_file_observables:
        # Read-time refusal — guards against malformed rows from a prior
        # buggy build. Treat as a no-op rather than partially applying.
        logging.warning(
            "refusing to replay cached delta module_path=%s observable_uuid=%s "
            "refusal_reason=file_observables (Phase 4 territory)",
            delta.module_path, target_observable.uuid,
            extra={
                "module_path": delta.module_path,
                "observable_uuid": target_observable.uuid,
                "refusal_reason": "file_observables",
            },
        )
        return

    # 1. Rehydrate the Analysis object first so step 2's new observables
    # can be hung off it as children (matching the live run's structure).
    # _rehydrate_analysis returns the freshly rehydrated analysis, the
    # pre-existing one when the slot-collision skip fires, or None when
    # the delta carries no analysis dict.
    rehydrated_analysis = _rehydrate_analysis(target_observable, delta)

    # 2. Spawn new observables. Parent is the rehydrated/preserved
    # analysis when we have one (matches the live run's parent-child
    # link), else fall back to the root.
    parent_for_new = rehydrated_analysis if rehydrated_analysis is not None else root
    for spec in delta.new_observables:
        _apply_observable_spec(parent_for_new, spec)

    # 3. Apply mutations to the target observable.
    _apply_observable_diff(target_observable, delta.target_observable_diff, root)

    # 4. Apply root-level mutations.
    _apply_root_diff(root, delta.root_diff)


def _rehydrate_analysis(
    target_observable: "Observable",
    delta: ModuleExecutionDelta,
):
    """Install the cached analysis on the target observable if absent.

    Returns the analysis instance (newly rehydrated or pre-existing), or
    None if the delta carried no analysis dict. Honors the slot-collision
    skip: if the slot already has an Analysis at ``module_path``, leave
    it alone — the existing instance is good and the analysis_tree_manager
    would otherwise log a noisy "replacing analysis" error.
    """
    if delta.analysis is None:
        return None
    module_path = delta.analysis.get("module_path")
    if not module_path:
        return None

    existing = target_observable._analysis.get(module_path)
    if isinstance(existing, _Analysis):
        # Slot-collision skip: re-analysis path / retry — keep the existing
        # analysis, idempotent diffs above still apply.
        return existing

    try:
        _module_name, _class_name, _instance = SPLIT_MODULE_PATH(module_path)
        _module = importlib.import_module(_module_name)
        _class = getattr(_module, _class_name)
        analysis = _class()
    except Exception as e:
        logging.warning(
            "failed to instantiate analysis for cache replay module_path=%s error=%s "
            "— falling back to UnknownAnalysis",
            module_path, e,
            extra={"module_path": module_path},
        )
        analysis = UnknownAnalysis(module_path)

    analysis.observable = target_observable
    analysis.file_manager = target_observable.file_manager

    # Strip alert-specific fields from the dict before letting
    # AnalysisSerializer.deserialize apply it. ``external_details_path``
    # is the source alert's path; the persistence manager will re-derive
    # one when we mark details_modified. ``details`` is applied
    # separately because the serializer doesn't deserialize it (it's
    # normally loaded lazily from the path).
    stripped = dict(delta.analysis)
    stripped.pop("external_details_path", None)
    cached_details = stripped.pop("details", None)

    try:
        analysis.json = stripped
    except Exception:
        logging.warning(
            "failed to apply cached analysis dict module_path=%s observable_uuid=%s",
            module_path, target_observable.uuid, exc_info=True,
            extra={
                "module_path": module_path,
                "observable_uuid": target_observable.uuid,
            },
        )

    if isinstance(cached_details, dict):
        analysis.details = cached_details
    elif cached_details is not None:
        analysis.details = cached_details
    analysis.set_details_modified()

    target_observable.analysis_tree_manager.add_analysis(target_observable, analysis)
    return analysis


def _apply_observable_spec(parent_analysis, spec) -> None:
    """Add a cached ObservableSpec as a child of ``parent_analysis`` and
    copy over its initial mutable state. Idempotent — the analysis tree
    manager dedupes by (type, value, time) and the add_* primitives
    dedupe at the field level.
    """
    o_time = None
    if spec.time:
        try:
            o_time = parse_event_time(spec.time)
        except Exception:
            o_time = None

    new_obs = parent_analysis.add_observable_by_spec(
        spec.type, spec.value, o_time=o_time,
    )
    if new_obs is None:
        return
    for tag in spec.initial_tags:
        new_obs.add_tag(tag)
    for directive in spec.initial_directives:
        new_obs.add_directive(directive)
    for det_dict in spec.initial_detections:
        description = det_dict.get("description")
        if description:
            new_obs.add_detection_point(description, det_dict.get("details"))


def _apply_observable_diff(observable, diff, root) -> None:
    """Apply an ObservableDiff's additions and scalar transitions to a
    live observable. All primitives are idempotent; safe to re-apply.
    """
    for tag in diff.added_tags:
        observable.add_tag(tag)
    for det_dict in diff.added_detections:
        description = det_dict.get("description")
        if description:
            observable.add_detection_point(description, det_dict.get("details"))
    for directive in diff.added_directives:
        observable.add_directive(directive)
    for rel_dict in diff.added_relationships:
        target_uuid = rel_dict.get("target")
        r_type = rel_dict.get("type")
        if not target_uuid or not r_type:
            continue
        target_obs = root.get_observable(target_uuid)
        if target_obs is None:
            logging.debug(
                "skipping relationship %s -> %s on cache replay — target not in tree",
                r_type, target_uuid,
            )
            continue
        observable.add_relationship(r_type, target_obs)
    # excluded_analysis / limited_analysis are simple string lists with no
    # idempotent setter — dedupe manually.
    for name in diff.added_excluded_analysis:
        if name not in observable._excluded_analysis:
            observable._excluded_analysis.append(name)
    for name in diff.added_limited_analysis:
        if name not in observable._limited_analysis:
            observable._limited_analysis.append(name)

    # Scalar transitions: set to "after" value when present.
    if diff.grouping_target is not None:
        _, after_val = diff.grouping_target
        observable._grouping_target = bool(after_val)
    if diff.redirection is not None:
        _, after_val = diff.redirection
        # _redirection is a UUID string; assign directly. (The setter
        # requires an Observable instance — but the captured form is
        # already the UUID, so we skip the setter.)
        observable._redirection = after_val
    if diff.ignored is not None:
        _, after_val = diff.ignored
        observable._ignored = bool(after_val)


def _apply_root_diff(root, root_diff) -> None:
    """Apply RootDiff additions to the root analysis."""
    for tag in root_diff.added_tags:
        root.add_tag(tag)
    for det_dict in root_diff.added_detections:
        description = det_dict.get("description")
        if description:
            root.add_detection_point(description, det_dict.get("details"))
