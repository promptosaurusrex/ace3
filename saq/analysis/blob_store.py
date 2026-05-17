"""Content-addressed blob storage for the analysis result cache.

The BlobStore interface abstracts bulk-content storage from the cache layer so
the local filesystem backend (used today) and a future S3 backend share the
same code paths. See docs/design/analysis_diff_tracking.md §A7 for the full
design.

Two kinds of things live in the blob store:

1. Spilled ``analysis.details`` dicts for cached ModuleExecutionDeltas whose
   details would bloat the DB row.
2. File observable payloads (deferred to Phase 4; not written in Phase 2).

Reference counting is explicit via the ``blob_refs`` table — we never rely on
filesystem link counts, because the S3 backend won't have them.
"""

import hashlib
import importlib
import logging
import os
import shutil
import tempfile
from abc import ABC, abstractmethod
from contextlib import contextmanager
from datetime import timedelta
from typing import BinaryIO, Iterator, Optional, Type, Union

from pydantic import BaseModel
from sqlalchemy import delete
from sqlalchemy.dialects.mysql import insert as mysql_insert

from saq.configuration.config import get_config
from saq.configuration.schema import BlobStoreSpec
from saq.database.model import BlobRef
from saq.database.pool import get_db
from saq.environment import get_base_dir


# Reference kinds stored in the blob_refs table.
REFERRER_KIND_CACHE_ROW = 'cache_row'
REFERRER_KIND_ALERT = 'alert'
REFERRER_KIND_ANALYSIS_DETAILS = 'analysis_details'


class BlobNotFound(Exception):
    pass


class BlobStoreConfig(BaseModel):
    """Base Pydantic config for blob store backends.

    Backend implementations subclass this to declare their own config fields and
    return the subclass from BlobStore.get_config_class().
    """


def resolve_blob_store_dir(configured: Optional[str]) -> str:
    """Resolve a configured blob store root directory to an absolute path.

    Absolute paths are used as-is; relative paths resolve against SAQ_HOME; an unset
    value defaults to ``<data_dir>/blob_store``.
    """
    from saq.environment import get_data_dir
    if configured:
        return configured if os.path.isabs(configured) else os.path.join(get_base_dir(), configured)
    return os.path.join(get_data_dir(), 'blob_store')


class BlobStore(ABC):

    @classmethod
    def get_config_class(cls) -> Type[BlobStoreConfig]:
        """Return the Pydantic config class used to validate this backend's config.

        Mirrors AnalysisModule.get_config_class(). Backends with their own config
        fields override this to return their BlobStoreConfig subclass.
        """
        return BlobStoreConfig

    @abstractmethod
    def put(self, data: Union[bytes, BinaryIO]) -> str:
        """Store bytes, return hex sha256."""

    @abstractmethod
    def get(self, sha256: str):
        """Context manager yielding a read stream for the blob.

        Raises BlobNotFound if the blob is missing.
        """

    @abstractmethod
    def exists(self, sha256: str) -> bool:
        ...

    @abstractmethod
    def reference(self, sha256: str, referrer_kind: str, referrer_id: str) -> None:
        """Record that ``referrer`` depends on ``sha256``. Idempotent."""

    @abstractmethod
    def unreference(self, sha256: str, referrer_kind: str, referrer_id: str) -> None:
        """Drop the dependency. Safe to call when the ref doesn't exist."""

    @abstractmethod
    def gc(self, grace_period: timedelta) -> int:
        """Delete blobs with zero references older than ``grace_period``.

        Deferred to Phase 2b — not scheduled in Phase 2 because nothing spills
        to the blob store until cacheable modules opt in (Phase 3).
        """

    @abstractmethod
    def materialize(self, sha256: str, dest_path: str) -> None:
        """Make the blob available at a local filesystem path.

        Local backend hardlinks when same-FS, falls back to copy. The S3
        backend (future) downloads to the dest path.
        """


class LocalHardlinkBlobStoreConfig(BlobStoreConfig):
    """Config for the local filesystem blob store backend."""
    root_dir: Optional[str] = None


class LocalHardlinkBlobStore(BlobStore):
    """Local filesystem backend.

    Bytes are stored at ``{root_dir}/<abc>/<def...>`` using a 3-char shard to
    match ACE's existing ``storage_dir_from_uuid`` convention
    (saq/util/uuid.py). Hardlinks are used by ``materialize`` for zero-copy
    access when the destination is on the same filesystem.
    """

    SHARD_LEN = 3

    @classmethod
    def get_config_class(cls) -> Type[BlobStoreConfig]:
        return LocalHardlinkBlobStoreConfig

    def __init__(self, config: LocalHardlinkBlobStoreConfig):
        self.config = config
        self.root_dir = resolve_blob_store_dir(config.root_dir)

    def _path_for(self, sha256: str) -> str:
        if len(sha256) != 64:
            raise ValueError(f"expected 64-char sha256, got {len(sha256)} chars")
        return os.path.join(self.root_dir, sha256[:self.SHARD_LEN], sha256)

    def path_for(self, sha256: str) -> str:
        """Return the on-disk path where the blob is (or would be) stored."""
        return self._path_for(sha256)

    def put(self, data: Union[bytes, BinaryIO]) -> str:
        h = hashlib.sha256()
        if isinstance(data, (bytes, bytearray)):
            h.update(data)
            sha256 = h.hexdigest()
            target = self._path_for(sha256)
            if os.path.exists(target):
                return sha256
            os.makedirs(os.path.dirname(target), exist_ok=True)
            # Atomic write: tempfile in the shard dir, then rename.
            with tempfile.NamedTemporaryFile(
                dir=os.path.dirname(target), delete=False
            ) as tmp:
                tmp.write(data)
                tmp_path = tmp.name
            os.rename(tmp_path, target)
            return sha256

        # Stream: buffer to a tempfile while hashing, then rename into place.
        os.makedirs(self.root_dir, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            dir=self.root_dir, delete=False
        ) as tmp:
            tmp_path = tmp.name
            while True:
                chunk = data.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
                tmp.write(chunk)
        sha256 = h.hexdigest()
        target = self._path_for(sha256)
        if os.path.exists(target):
            os.unlink(tmp_path)
            return sha256
        os.makedirs(os.path.dirname(target), exist_ok=True)
        os.rename(tmp_path, target)
        return sha256

    @contextmanager
    def get(self, sha256: str) -> Iterator[BinaryIO]:
        path = self._path_for(sha256)
        if not os.path.exists(path):
            raise BlobNotFound(sha256)
        with open(path, 'rb') as f:
            yield f

    def exists(self, sha256: str) -> bool:
        return os.path.exists(self._path_for(sha256))

    def reference(self, sha256: str, referrer_kind: str, referrer_id: str) -> None:
        # INSERT IGNORE (via MySQL dialect prefix) makes this idempotent —
        # re-referencing the same (sha, kind, id) is a no-op rather than a
        # duplicate-key error.
        stmt = mysql_insert(BlobRef).values(
            sha256=sha256, referrer_kind=referrer_kind, referrer_id=referrer_id,
        ).prefix_with('IGNORE')
        get_db().execute(stmt)
        get_db().commit()

    def unreference(self, sha256: str, referrer_kind: str, referrer_id: str) -> None:
        get_db().execute(
            delete(BlobRef).where(
                BlobRef.sha256 == sha256,
                BlobRef.referrer_kind == referrer_kind,
                BlobRef.referrer_id == referrer_id,
            )
        )
        get_db().commit()

    def gc(self, grace_period: timedelta) -> int:
        # TODO (Phase 2b): walk blobs with zero refs older than grace_period
        # and unlink them. Deferred because Phase 2 is plumbing-only and no
        # blobs accumulate until cacheable modules opt in.
        logging.debug("LocalHardlinkBlobStore.gc is a no-op until Phase 2b")
        return 0

    def materialize(self, sha256: str, dest_path: str) -> None:
        src = self._path_for(sha256)
        if not os.path.exists(src):
            raise BlobNotFound(sha256)
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        try:
            os.link(src, dest_path)
        except OSError:
            # Cross-filesystem or hardlinks unsupported — fall back to copy.
            shutil.copyfile(src, dest_path)


_blob_store_singleton: Optional[BlobStore] = None


def _load_blob_store(spec: BlobStoreSpec) -> BlobStore:
    """Load a pluggable blob store backend from its config spec."""
    module = importlib.import_module(spec.python_module)
    cls = getattr(module, spec.python_class)
    config = cls.get_config_class().model_validate(spec.config)
    return cls(config)


def get_blob_store() -> BlobStore:
    """Return the process-wide blob store singleton.

    Lazy-initialized on first call. When ``analysis_cache.blob_store`` is set, the
    configured pluggable backend is loaded; otherwise the local hardlink store is
    used, rooted at ``analysis_cache.blob_store_dir`` (defaulting to
    ``<data_dir>/blob_store``).
    """
    global _blob_store_singleton
    if _blob_store_singleton is None:
        spec = get_config().analysis_cache.blob_store
        if spec is not None:
            _blob_store_singleton = _load_blob_store(spec)
        else:
            configured = get_config().analysis_cache.blob_store_dir
            _blob_store_singleton = LocalHardlinkBlobStore(
                LocalHardlinkBlobStoreConfig(root_dir=configured)
            )
    return _blob_store_singleton


def reset_blob_store_singleton() -> None:
    """Reset the singleton. Used in tests."""
    global _blob_store_singleton
    _blob_store_singleton = None
