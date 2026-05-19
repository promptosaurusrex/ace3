"""Tests for ModuleExecutionDelta and related dataclasses."""

import pytest

from saq.analysis.module_execution_delta import (
    AnalysisChildrenDiff,
    ModuleExecutionDelta,
    ObservableDiff,
    ObservableSpec,
    RootDiff,
)


class TestObservableDiff:
    @pytest.mark.unit
    def test_empty_diff(self):
        diff = ObservableDiff()
        assert diff.is_empty
        assert not diff.has_removals

    @pytest.mark.unit
    def test_additions_only(self):
        diff = ObservableDiff(
            added_tags=["suspicious", "malware"],
            added_directives=["sandbox"],
        )
        assert not diff.is_empty
        assert not diff.has_removals

    @pytest.mark.unit
    def test_removals_detected(self):
        diff = ObservableDiff(removed_tags=["benign"])
        assert not diff.is_empty
        assert diff.has_removals

    @pytest.mark.unit
    def test_scalar_transition(self):
        diff = ObservableDiff(grouping_target=(False, True))
        assert not diff.is_empty
        assert not diff.has_removals

    @pytest.mark.unit
    def test_serialization_round_trip(self):
        diff = ObservableDiff(
            added_tags=["suspicious"],
            removed_tags=["benign"],
            added_detections=[{"description": "test", "details": None}],
            added_directives=["sandbox"],
            removed_directives=["crawl"],
            added_relationships=[{"type": "downloaded_from", "target": "uuid-1"}],
            added_excluded_analysis=["saq.modules.test:TestAnalysis"],
            added_limited_analysis=["saq.modules.other:OtherAnalysis"],
            grouping_target=(False, True),
            redirection=(None, "uuid-2"),
            ignored=(False, True),
        )
        d = diff.to_dict()
        restored = ObservableDiff.from_dict(d)

        assert restored.added_tags == ["suspicious"]
        assert restored.removed_tags == ["benign"]
        assert restored.added_detections == [{"description": "test", "details": None}]
        assert restored.added_directives == ["sandbox"]
        assert restored.removed_directives == ["crawl"]
        assert restored.added_relationships == [{"type": "downloaded_from", "target": "uuid-1"}]
        assert restored.added_excluded_analysis == ["saq.modules.test:TestAnalysis"]
        assert restored.added_limited_analysis == ["saq.modules.other:OtherAnalysis"]
        assert restored.grouping_target == (False, True)
        assert restored.redirection == (None, "uuid-2")
        assert restored.ignored == (False, True)

    @pytest.mark.unit
    def test_empty_serialization_is_compact(self):
        diff = ObservableDiff()
        assert diff.to_dict() == {}

    @pytest.mark.unit
    def test_from_dict_missing_fields_default_to_empty(self):
        diff = ObservableDiff.from_dict({})
        assert diff.is_empty


class TestObservableSpec:
    @pytest.mark.unit
    def test_minimal_spec(self):
        spec = ObservableSpec(uuid="u1", type="ipv4", value="1.2.3.4")
        d = spec.to_dict()
        assert d == {"uuid": "u1", "type": "ipv4", "value": "1.2.3.4"}

        restored = ObservableSpec.from_dict(d)
        assert restored.uuid == "u1"
        assert restored.type == "ipv4"
        assert restored.value == "1.2.3.4"
        assert restored.time is None
        assert restored.initial_tags == []

    @pytest.mark.unit
    def test_full_spec_round_trip(self):
        spec = ObservableSpec(
            uuid="u2",
            type="fqdn",
            value="evil.com",
            time="2026-04-10T12:00:00+00:00",
            initial_tags=["suspicious"],
            initial_directives=["sandbox"],
            initial_detections=[{"description": "match", "details": None}],
            initial_excluded_analysis=["MyAnalyzer", "OtherAnalyzer"],
            initial_limited_analysis=["LimitedAnalyzer"],
        )
        d = spec.to_dict()
        restored = ObservableSpec.from_dict(d)
        assert restored.uuid == spec.uuid
        assert restored.type == spec.type
        assert restored.value == spec.value
        assert restored.time == spec.time
        assert restored.initial_tags == spec.initial_tags
        assert restored.initial_directives == spec.initial_directives
        assert restored.initial_detections == spec.initial_detections
        assert restored.initial_excluded_analysis == spec.initial_excluded_analysis
        assert restored.initial_limited_analysis == spec.initial_limited_analysis

    @pytest.mark.unit
    def test_from_dict_backward_compat_missing_exclude_fields(self):
        """Cache rows written before initial_excluded_analysis existed must
        still load cleanly. Old shape → empty lists for the new fields."""
        old_shape = {
            "uuid": "u3",
            "type": "user",
            "value": "Usr123",
            "initial_tags": ["from-old-cache"],
        }
        restored = ObservableSpec.from_dict(old_shape)
        assert restored.initial_excluded_analysis == []
        assert restored.initial_limited_analysis == []


class TestRootDiff:
    @pytest.mark.unit
    def test_empty(self):
        diff = RootDiff()
        assert diff.is_empty
        assert diff.to_dict() == {}

    @pytest.mark.unit
    def test_round_trip(self):
        diff = RootDiff(
            added_tags=["alert"],
            removed_detections=[{"description": "old", "details": None}],
        )
        restored = RootDiff.from_dict(diff.to_dict())
        assert restored.added_tags == ["alert"]
        assert restored.removed_detections == [{"description": "old", "details": None}]


class TestModuleExecutionDelta:
    def _make_delta(self, **overrides):
        defaults = dict(
            module_path="saq.modules.test:TestAnalysis",
            module_instance=None,
            module_version=1,
            observable_uuid="obs-uuid-1",
            observable_type="ipv4",
            observable_value="10.0.0.1",
            created_at="2026-04-10T12:00:00+00:00",
            execution_time_ms=42,
        )
        defaults.update(overrides)
        return ModuleExecutionDelta(**defaults)

    @pytest.mark.unit
    def test_empty_delta(self):
        delta = self._make_delta()
        assert delta.is_empty
        assert not delta.has_removals

    @pytest.mark.unit
    def test_delta_with_analysis(self):
        delta = self._make_delta(
            analysis={"module_path": "saq.modules.test:TestAnalysis", "completed": True},
        )
        assert not delta.is_empty

    @pytest.mark.unit
    def test_delta_with_new_observables(self):
        spec = ObservableSpec(uuid="new-1", type="fqdn", value="evil.com")
        delta = self._make_delta(new_observables=[spec])
        assert not delta.is_empty

    @pytest.mark.unit
    def test_has_removals_from_target(self):
        diff = ObservableDiff(removed_tags=["old"])
        delta = self._make_delta(target_observable_diff=diff)
        assert delta.has_removals

    @pytest.mark.unit
    def test_has_removals_from_other_observable(self):
        other_diff = ObservableDiff(removed_directives=["crawl"])
        delta = self._make_delta(
            wide_diff=True,
            other_observable_diffs={"other-uuid": other_diff},
        )
        assert delta.has_removals

    @pytest.mark.unit
    def test_full_round_trip(self):
        target_diff = ObservableDiff(
            added_tags=["suspicious"],
            added_detections=[{"description": "found malware", "details": None}],
        )
        new_obs = ObservableSpec(
            uuid="new-1", type="fqdn", value="evil.com",
            initial_tags=["new"],
        )
        root_diff = RootDiff(added_tags=["alert_tag"])
        other_diff = ObservableDiff(added_directives=["sandbox"])

        delta = self._make_delta(
            module_instance="instance1",
            root_uuid="root-uuid-1",
            analysis={"module_path": "saq.modules.test:TestAnalysis", "completed": True},
            target_observable_diff=target_diff,
            new_observables=[new_obs],
            root_diff=root_diff,
            cache_key="abc123",
            wide_diff=True,
            other_observable_diffs={"other-uuid": other_diff},
        )

        d = delta.to_dict()
        restored = ModuleExecutionDelta.from_dict(d)

        assert restored.module_path == delta.module_path
        assert restored.module_instance == "instance1"
        assert restored.module_version == 1
        assert restored.observable_uuid == delta.observable_uuid
        assert restored.observable_type == delta.observable_type
        assert restored.observable_value == delta.observable_value
        assert restored.created_at == delta.created_at
        assert restored.execution_time_ms == 42
        assert restored.root_uuid == "root-uuid-1"
        assert restored.analysis == delta.analysis
        assert restored.target_observable_diff.added_tags == ["suspicious"]
        assert len(restored.new_observables) == 1
        assert restored.new_observables[0].value == "evil.com"
        assert restored.root_diff.added_tags == ["alert_tag"]
        assert restored.cache_key == "abc123"
        assert restored.wide_diff is True
        assert "other-uuid" in restored.other_observable_diffs
        assert restored.other_observable_diffs["other-uuid"].added_directives == ["sandbox"]

    @pytest.mark.unit
    def test_compact_serialization_omits_empty_fields(self):
        delta = self._make_delta()
        d = delta.to_dict()
        # Empty diffs and None fields should not appear
        assert "target_observable_diff" not in d
        assert "new_observables" not in d
        assert "root_diff" not in d
        assert "analysis" not in d
        assert "cache_key" not in d
        assert "wide_diff" not in d
        assert "other_observable_diffs" not in d
        assert "module_instance" not in d
        assert "analysis_children_diffs" not in d
        assert "root_uuid" not in d

    @pytest.mark.unit
    def test_has_removals_from_analysis_children(self):
        acd = AnalysisChildrenDiff(
            analysis_module_path="saq.modules.email.rfc822:EmailAnalysis",
            parent_observable_uuid="obs-parent",
            removed_child_uuids=["obs-removed"],
        )
        delta = self._make_delta(analysis_children_diffs=[acd])
        assert delta.has_removals

    @pytest.mark.unit
    def test_analysis_children_diff_round_trip(self):
        acd = AnalysisChildrenDiff(
            analysis_module_path="saq.modules.email.rfc822:EmailAnalysis",
            parent_observable_uuid="obs-parent",
            added_child_uuids=["obs-added-1"],
            removed_child_uuids=["obs-removed-1", "obs-removed-2"],
        )
        delta = self._make_delta(
            wide_diff=True,
            analysis_children_diffs=[acd],
        )
        d = delta.to_dict()
        assert "analysis_children_diffs" in d
        assert len(d["analysis_children_diffs"]) == 1

        restored = ModuleExecutionDelta.from_dict(d)
        assert len(restored.analysis_children_diffs) == 1
        r_acd = restored.analysis_children_diffs[0]
        assert r_acd.analysis_module_path == "saq.modules.email.rfc822:EmailAnalysis"
        assert r_acd.parent_observable_uuid == "obs-parent"
        assert r_acd.added_child_uuids == ["obs-added-1"]
        assert r_acd.removed_child_uuids == ["obs-removed-1", "obs-removed-2"]

    @pytest.mark.unit
    def test_delta_not_empty_with_analysis_children(self):
        acd = AnalysisChildrenDiff(
            analysis_module_path="saq.modules.test:Test",
            parent_observable_uuid="obs-1",
            removed_child_uuids=["obs-2"],
        )
        delta = self._make_delta(analysis_children_diffs=[acd])
        assert not delta.is_empty


class TestAnalysisChildrenDiff:
    @pytest.mark.unit
    def test_empty(self):
        acd = AnalysisChildrenDiff(
            analysis_module_path="saq.modules.test:Test",
            parent_observable_uuid="obs-1",
        )
        assert acd.is_empty

    @pytest.mark.unit
    def test_round_trip(self):
        acd = AnalysisChildrenDiff(
            analysis_module_path="saq.modules.email.rfc822:EmailAnalysis",
            parent_observable_uuid="parent-uuid",
            added_child_uuids=["child-1"],
            removed_child_uuids=["child-2", "child-3"],
        )
        d = acd.to_dict()
        restored = AnalysisChildrenDiff.from_dict(d)
        assert restored.analysis_module_path == acd.analysis_module_path
        assert restored.parent_observable_uuid == acd.parent_observable_uuid
        assert restored.added_child_uuids == ["child-1"]
        assert restored.removed_child_uuids == ["child-2", "child-3"]
        assert not restored.is_empty
