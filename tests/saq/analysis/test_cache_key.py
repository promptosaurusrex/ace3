"""Unit tests for saq.analysis.cache.generate_cache_key."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from saq.analysis.cache import generate_cache_key


def _make_observable(type_: str = "url", value: str = "https://example.com/", time=None):
    return SimpleNamespace(type=type_, value=value, time=time)


def _make_module(
    name: str = "test_module",
    version: int = 1,
    cache_ttl=timedelta(hours=1),
    extended_version=None,
):
    return SimpleNamespace(
        config=SimpleNamespace(name=name),
        version=version,
        cache_ttl=cache_ttl,
        extended_version=extended_version or {},
    )


class TestCacheKeyBasics:

    @pytest.mark.unit
    def test_returns_none_when_cache_ttl_is_none(self):
        key = generate_cache_key(_make_observable(), _make_module(cache_ttl=None))
        assert key is None

    @pytest.mark.unit
    def test_returns_sha256_hex_when_cache_ttl_set(self):
        key = generate_cache_key(_make_observable(), _make_module())
        assert isinstance(key, str)
        assert len(key) == 64
        int(key, 16)  # hex

    @pytest.mark.unit
    def test_deterministic(self):
        obs = _make_observable()
        mod = _make_module()
        assert generate_cache_key(obs, mod) == generate_cache_key(obs, mod)


class TestCacheKeySensitivity:

    @pytest.mark.unit
    def test_changes_with_observable_value(self):
        mod = _make_module()
        k1 = generate_cache_key(_make_observable(value="https://a.example/"), mod)
        k2 = generate_cache_key(_make_observable(value="https://b.example/"), mod)
        assert k1 != k2

    @pytest.mark.unit
    def test_changes_with_observable_type(self):
        mod = _make_module()
        k1 = generate_cache_key(_make_observable(type_="url"), mod)
        k2 = generate_cache_key(_make_observable(type_="fqdn"), mod)
        assert k1 != k2

    @pytest.mark.unit
    def test_ignores_observable_time(self):
        """observable.time is deliberately excluded from the key — cacheable
        results are time-independent, and including time would defeat dedup
        for time-bearing observable types (IPs). Two observables identical
        but for their time must produce the SAME key."""
        mod = _make_module()
        t1 = datetime(2026, 4, 17, 10, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 4, 17, 11, 0, tzinfo=timezone.utc)
        k1 = generate_cache_key(_make_observable(time=t1), mod)
        k2 = generate_cache_key(_make_observable(time=t2), mod)
        k_none = generate_cache_key(_make_observable(time=None), mod)
        assert k1 == k2 == k_none

    @pytest.mark.unit
    def test_changes_with_module_name(self):
        obs = _make_observable()
        k1 = generate_cache_key(obs, _make_module(name="module_a"))
        k2 = generate_cache_key(obs, _make_module(name="module_b"))
        assert k1 != k2

    @pytest.mark.unit
    def test_changes_with_module_version(self):
        obs = _make_observable()
        k1 = generate_cache_key(obs, _make_module(version=1))
        k2 = generate_cache_key(obs, _make_module(version=2))
        assert k1 != k2

    @pytest.mark.unit
    def test_changes_with_extended_version(self):
        obs = _make_observable()
        k1 = generate_cache_key(obs, _make_module(extended_version={"rules_sha": "aaa"}))
        k2 = generate_cache_key(obs, _make_module(extended_version={"rules_sha": "bbb"}))
        assert k1 != k2

    @pytest.mark.unit
    def test_extended_version_ordering_is_stable(self):
        """Keys within extended_version should be sorted so insertion order
        doesn't change the cache key."""
        obs = _make_observable()
        k1 = generate_cache_key(obs, _make_module(extended_version={"a": "1", "b": "2"}))
        k2 = generate_cache_key(obs, _make_module(extended_version={"b": "2", "a": "1"}))
        assert k1 == k2

    @pytest.mark.unit
    def test_empty_extended_version_equals_unset(self):
        obs = _make_observable()
        k1 = generate_cache_key(obs, _make_module(extended_version={}))
        k2 = generate_cache_key(obs, _make_module())
        assert k1 == k2
