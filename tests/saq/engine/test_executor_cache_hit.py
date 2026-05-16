"""Tests for the Phase 3 cache-hit short-circuit in
``AnalysisExecutor._execute_module_analysis``.

Mirrors the Phase 1 precedent: full ``_execute_module_analysis`` flow
testing requires mocking the entire engine context (configuration
manager, delayed analysis interface, tracking message manager, work
stacks) and is deliberately deferred. These tests focus on the helper
``_apply_cached_delta`` and the dataclass plumbing that supports it.
"""
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from saq.analysis.module_execution_delta import (
    ModuleExecutionDelta,
    ObservableDiff,
    ObservableSpec,
    RootDiff,
)
from saq.analysis.root import RootAnalysis
from saq.constants import F_FILE, F_FQDN, F_URL
from saq.engine.executor import AnalysisExecutionContext, AnalysisExecutor
from saq.modules.whois import WhoisAnalysis


def _make_executor() -> AnalysisExecutor:
    """Minimum-viable AnalysisExecutor for testing the cache-hit helper.

    The helper doesn't touch configuration / delayed-analysis /
    tracking-message state, so MagicMock placeholders are enough.
    """
    return AnalysisExecutor(
        configuration_manager=MagicMock(),
        delayed_analysis_interface=MagicMock(),
        tracking_message_manager=MagicMock(),
        single_threaded_mode=True,
    )


def _make_root(tmp_path):
    root = RootAnalysis(storage_dir=str(tmp_path))
    root.initialize_storage()
    return root


def _make_context(root) -> AnalysisExecutionContext:
    """Real AnalysisExecutionContext bound to ``root`` so counter bumps
    flow into the same dicts ``record_execution_statistics`` consumes."""
    return AnalysisExecutionContext(root)


def _make_module(name="whois_analyzer"):
    """Stub module — only the attributes _apply_cached_delta touches."""
    return SimpleNamespace(config=SimpleNamespace(name=name))


def _make_delta_for(observable, *, with_analysis=True):
    analysis = None
    if with_analysis:
        analysis = {
            "module_path": "saq.modules.whois:WhoisAnalysis",
            "details": {"registrar": "Test Registrar"},
            "completed": True,
            "delayed": False,
        }
    delta = ModuleExecutionDelta(
        module_path="saq.modules.whois:WhoisAnalysis",
        module_instance=None,
        module_version=1,
        observable_uuid=observable.uuid,
        observable_type=observable.type,
        observable_value=observable.value,
        created_at=datetime.now(timezone.utc).isoformat(),
        execution_time_ms=42,
        target_observable_diff=ObservableDiff(added_tags=["replayed"]),
        new_observables=[],
        root_diff=RootDiff(),
        analysis=analysis,
    )
    delta.cache_key = "deadbeef" * 8  # 64-char hex placeholder
    return delta


class TestApplyCachedDelta:

    @pytest.mark.unit
    def test_records_attribution_delta_with_from_cache_hit_flag(self, tmp_path):
        executor = _make_executor()
        root = _make_root(tmp_path)
        context = _make_context(root)
        obs = root.add_observable_by_spec(F_FQDN, "example.com")
        module = _make_module()
        delta = _make_delta_for(obs)

        executor._apply_cached_delta(context, root, obs, module, delta, lookup_ms=4)

        assert len(root.module_executions) == 1
        recorded = root.module_executions[0]
        assert recorded.from_cache_hit is True
        assert recorded.observable_uuid == obs.uuid
        # root_uuid is rewritten to the current alert being analyzed.
        assert recorded.root_uuid == root.uuid
        # Mutation fields preserved from original capture.
        assert recorded.target_observable_diff.added_tags == ["replayed"]
        # Attribution execution_time_ms reflects total hit cost
        # (lookup + replay), not replay alone.
        assert recorded.execution_time_ms >= 4

    @pytest.mark.unit
    def test_bumps_cache_hit_counters_on_context(self, tmp_path):
        """The plain ``analysis cache hit`` log line was replaced by
        per-(root, module) aggregation on the AnalysisExecutionContext.
        Each call to ``_apply_cached_delta`` must bump cache_hit_count
        and the lookup-latency accumulators for the module.
        """
        executor = _make_executor()
        root = _make_root(tmp_path)
        context = _make_context(root)
        obs = root.add_observable_by_spec(F_FQDN, "example.com")
        module = _make_module()
        delta = _make_delta_for(obs)

        executor._apply_cached_delta(context, root, obs, module, delta, lookup_ms=7)
        executor._apply_cached_delta(context, root, obs, module, delta, lookup_ms=3)

        name = module.config.name
        assert context.cache_hit_count[name] == 2
        assert context.cache_lookup_ms_sum[name] == 10
        assert context.cache_lookup_ms_max[name] == 7

    @pytest.mark.unit
    def test_attribution_delta_recorded_even_when_diff_is_empty(self, tmp_path):
        """Phase 1 filters empty deltas to avoid bloating root.json. Phase 3
        cache hits must always be recorded — cache consultation is itself
        information worth keeping (audit/debug).
        """
        executor = _make_executor()
        root = _make_root(tmp_path)
        context = _make_context(root)
        obs = root.add_observable_by_spec(F_FQDN, "example.com")
        module = _make_module()

        # Build a delta with no mutations and no analysis dict.
        empty_delta = ModuleExecutionDelta(
            module_path="saq.modules.x:X",
            module_instance=None,
            module_version=1,
            observable_uuid=obs.uuid,
            observable_type=obs.type,
            observable_value=obs.value,
            created_at=datetime.now(timezone.utc).isoformat(),
            execution_time_ms=0,
            target_observable_diff=ObservableDiff(),
            new_observables=[],
            root_diff=RootDiff(),
            analysis=None,
        )
        empty_delta.cache_key = "00" * 32

        executor._apply_cached_delta(context, root, obs, module, empty_delta, lookup_ms=2)

        # Even though the delta is empty, attribution is recorded.
        assert len(root.module_executions) == 1
        assert root.module_executions[0].from_cache_hit is True

    @pytest.mark.unit
    def test_apply_delta_actually_mutates_target_tree(self, tmp_path):
        """End-to-end: _apply_cached_delta calls apply_delta which
        mutates the observable, then records attribution. Verifies the
        helper isn't a no-op.
        """

        executor = _make_executor()
        root = _make_root(tmp_path)
        context = _make_context(root)
        obs = root.add_observable_by_spec(F_FQDN, "example.com")
        module = _make_module()
        delta = _make_delta_for(obs)

        executor._apply_cached_delta(context, root, obs, module, delta, lookup_ms=1)

        # Diff additions applied.
        assert "replayed" in obs.tags
        # Analysis rehydrated.
        rehydrated = obs.get_analysis(WhoisAnalysis)
        assert rehydrated is not None
        assert rehydrated.details == {"registrar": "Test Registrar"}


class TestModuleExecutionDeltaCacheHitMetadata:
    """The dataclass method that the executor helper uses to mint the
    attribution copy — exercised independently of the helper to make
    failure modes easier to localize.
    """

    @pytest.mark.unit
    def test_with_cache_hit_metadata_sets_flag(self):
        delta = ModuleExecutionDelta(
            module_path="m",
            module_instance=None,
            module_version=1,
            observable_uuid="u",
            observable_type="t",
            observable_value="v",
            created_at=datetime.now(timezone.utc).isoformat(),
            execution_time_ms=1234,
            root_uuid="source-alert-uuid",
            target_observable_diff=ObservableDiff(added_tags=["t1"]),
            new_observables=[],
            root_diff=RootDiff(),
        )
        executed_at = datetime(2026, 5, 7, 12, 0, 0, tzinfo=timezone.utc)
        copy = delta.with_cache_hit_metadata(
            executed_at=executed_at,
            execution_time_ms=5,
            root_uuid="current-alert-uuid",
        )
        # Original is untouched.
        assert delta.from_cache_hit is False
        assert delta.execution_time_ms == 1234
        assert delta.root_uuid == "source-alert-uuid"
        # Copy reflects the cache-hit replay.
        assert copy.from_cache_hit is True
        assert copy.execution_time_ms == 5
        assert copy.created_at == executed_at.isoformat()
        # root_uuid is rewritten to the current alert, not the source alert
        # the cached delta originated from.
        assert copy.root_uuid == "current-alert-uuid"
        # Mutations preserved.
        assert copy.target_observable_diff.added_tags == ["t1"]

    @pytest.mark.unit
    def test_from_cache_hit_round_trips_through_dict(self):
        delta = ModuleExecutionDelta(
            module_path="m",
            module_instance=None,
            module_version=1,
            observable_uuid="u",
            observable_type="t",
            observable_value="v",
            created_at=datetime.now(timezone.utc).isoformat(),
            execution_time_ms=1,
            target_observable_diff=ObservableDiff(),
            new_observables=[],
            root_diff=RootDiff(),
            from_cache_hit=True,
        )
        d = delta.to_dict()
        assert d["from_cache_hit"] is True
        rebuilt = ModuleExecutionDelta.from_dict(d)
        assert rebuilt.from_cache_hit is True

    @pytest.mark.unit
    def test_from_cache_hit_default_false_on_old_dicts(self):
        """Backward compat: pre-Step-3.7 dicts have no from_cache_hit
        key. from_dict must default to False.
        """
        d = {
            "module_path": "m",
            "module_version": 1,
            "observable_uuid": "u",
            "observable_type": "t",
            "observable_value": "v",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "execution_time_ms": 1,
        }
        rebuilt = ModuleExecutionDelta.from_dict(d)
        assert rebuilt.from_cache_hit is False

    @pytest.mark.unit
    def test_has_file_observables_property(self):

        delta = ModuleExecutionDelta(
            module_path="m",
            module_instance=None,
            module_version=1,
            observable_uuid="u",
            observable_type="t",
            observable_value="v",
            created_at=datetime.now(timezone.utc).isoformat(),
            execution_time_ms=1,
            target_observable_diff=ObservableDiff(),
            new_observables=[
                ObservableSpec(uuid="1", type=F_URL, value="https://x"),
            ],
            root_diff=RootDiff(),
        )
        assert delta.has_file_observables is False

        delta.new_observables.append(
            ObservableSpec(uuid="2", type=F_FILE, value="path")
        )
        assert delta.has_file_observables is True
