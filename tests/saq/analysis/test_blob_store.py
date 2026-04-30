"""Unit tests for LocalHardlinkBlobStore (filesystem behavior only).

The reference/unreference DB methods are exercised in test_cache.py since
they require the blob_refs table.
"""
import hashlib
import io
import os

import pytest

from saq.analysis.blob_store import BlobNotFound, LocalHardlinkBlobStore


@pytest.fixture
def blob_store(tmp_path):
    return LocalHardlinkBlobStore(str(tmp_path / "blob_store"))


class TestPut:

    @pytest.mark.unit
    def test_put_bytes_returns_sha256(self, blob_store):
        data = b"hello world"
        sha = blob_store.put(data)
        assert sha == hashlib.sha256(data).hexdigest()

    @pytest.mark.unit
    def test_put_writes_to_sharded_path(self, blob_store):
        data = b"hello world"
        sha = blob_store.put(data)
        expected = os.path.join(blob_store.root_dir, sha[:3], sha)
        assert os.path.exists(expected)

    @pytest.mark.unit
    def test_put_is_idempotent(self, blob_store):
        data = b"hello world"
        sha1 = blob_store.put(data)
        sha2 = blob_store.put(data)
        assert sha1 == sha2

    @pytest.mark.unit
    def test_put_stream(self, blob_store):
        data = b"x" * (3 * 1024 * 1024)  # > 1 MB, exercises streaming loop
        sha = blob_store.put(io.BytesIO(data))
        assert sha == hashlib.sha256(data).hexdigest()
        assert blob_store.exists(sha)


class TestGetExists:

    @pytest.mark.unit
    def test_get_returns_stored_bytes(self, blob_store):
        data = b"payload"
        sha = blob_store.put(data)
        with blob_store.get(sha) as f:
            assert f.read() == data

    @pytest.mark.unit
    def test_get_missing_raises(self, blob_store):
        with pytest.raises(BlobNotFound):
            with blob_store.get("0" * 64):
                pass

    @pytest.mark.unit
    def test_exists(self, blob_store):
        sha = blob_store.put(b"x")
        assert blob_store.exists(sha)
        assert not blob_store.exists("0" * 64)


class TestMaterialize:

    @pytest.mark.unit
    def test_materialize_hardlinks(self, blob_store, tmp_path):
        data = b"payload"
        sha = blob_store.put(data)
        dest = tmp_path / "materialized" / "file.dat"
        blob_store.materialize(sha, str(dest))
        assert dest.exists()
        assert dest.read_bytes() == data
        # Hardlink check: same inode as the blob store entry
        blob_path = blob_store._path_for(sha)
        assert os.stat(blob_path).st_ino == os.stat(str(dest)).st_ino

    @pytest.mark.unit
    def test_materialize_missing_raises(self, blob_store, tmp_path):
        dest = tmp_path / "out"
        with pytest.raises(BlobNotFound):
            blob_store.materialize("0" * 64, str(dest))


class TestPathValidation:

    @pytest.mark.unit
    def test_path_for_rejects_wrong_length(self, blob_store):
        with pytest.raises(ValueError):
            blob_store._path_for("short")
