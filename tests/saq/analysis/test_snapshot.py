"""Tests for ModuleExecutionSnapshot capture and diff computation."""

from unittest.mock import MagicMock
import pytest

from saq.analysis.analysis import Analysis
from saq.analysis.root import RootAnalysis
from saq.analysis.snapshot import ModuleExecutionSnapshot, _ObservableState
from saq.constants import F_IPV4, F_FQDN, F_EMAIL_ADDRESS


def _make_root(tmp_path):
    root = RootAnalysis(storage_dir=str(tmp_path))
    root.initialize_storage()
    return root


def _make_mock_module(name="saq.modules.test:TestAnalysis", instance=None, version=1, wide_diff=False):
    module = MagicMock()
    module.config = MagicMock()
    module.config.name = name
    module.config.wide_diff = wide_diff
    module.instance = instance
    module.version = version
    # MODULE_PATH expects a specific interface — mock the generated_analysis_type
    module.generated_analysis_type = MagicMock()
    module.generated_analysis_type.__module__ = "saq.modules.test"
    module.generated_analysis_type.__qualname__ = "TestAnalysis"
    return module


class TestObservableStateCapture:
    @pytest.mark.unit
    def test_capture_empty_observable(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IPV4, "10.0.0.1")
        state = _ObservableState.capture(obs)

        assert state.uuid == obs.uuid
        assert state.tags == frozenset()
        assert state.detection_ids == frozenset()
        assert state.directives == frozenset()
        assert state.relationship_ids == frozenset()
        assert state.excluded_analysis == frozenset()
        assert state.limited_analysis == frozenset()
        assert state.grouping_target is False
        assert state.redirection is None
        assert state.ignored is False

    @pytest.mark.unit
    def test_capture_observable_with_state(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IPV4, "10.0.0.1")
        obs.add_tag("suspicious")
        obs.add_tag("malware")
        obs.add_directive("sandbox")
        obs.add_detection_point("test detection")

        state = _ObservableState.capture(obs)
        assert state.tags == frozenset(["suspicious", "malware"])
        assert state.directives == frozenset(["sandbox"])
        assert len(state.detection_ids) == 1


class TestNarrowSnapshot:
    @pytest.mark.unit
    def test_capture_and_diff_add_tag(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IPV4, "10.0.0.1")
        module = _make_mock_module()

        before = ModuleExecutionSnapshot.narrow(root, obs, module)

        # Simulate module adding a tag
        obs.add_tag("suspicious")

        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert delta.target_observable_diff.added_tags == ["suspicious"]
        assert not delta.target_observable_diff.removed_tags
        assert not delta.is_empty

    @pytest.mark.unit
    def test_diff_add_detection(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IPV4, "10.0.0.1")
        module = _make_mock_module()

        before = ModuleExecutionSnapshot.narrow(root, obs, module)

        obs.add_detection_point("found malware", details={"rule": "yara_match"})

        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert len(delta.target_observable_diff.added_detections) == 1
        assert delta.target_observable_diff.added_detections[0]["description"] == "found malware"

    @pytest.mark.unit
    def test_diff_add_directive(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IPV4, "10.0.0.1")
        module = _make_mock_module()

        before = ModuleExecutionSnapshot.narrow(root, obs, module)
        obs.add_directive("sandbox")
        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert delta.target_observable_diff.added_directives == ["sandbox"]

    @pytest.mark.unit
    def test_diff_add_observable(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IPV4, "10.0.0.1")
        module = _make_mock_module()

        before = ModuleExecutionSnapshot.narrow(root, obs, module)

        new_obs = root.add_observable_by_spec(F_FQDN, "evil.com")

        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert len(delta.new_observables) == 1
        assert delta.new_observables[0].type == F_FQDN
        assert delta.new_observables[0].value == "evil.com"
        assert delta.new_observables[0].uuid == new_obs.uuid

    @pytest.mark.unit
    def test_diff_add_observable_with_initial_state(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IPV4, "10.0.0.1")
        module = _make_mock_module()

        before = ModuleExecutionSnapshot.narrow(root, obs, module)

        new_obs = root.add_observable_by_spec(F_FQDN, "evil.com")
        new_obs.add_tag("new_tag")
        new_obs.add_directive("crawl")

        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert len(delta.new_observables) == 1
        assert "new_tag" in delta.new_observables[0].initial_tags
        assert "crawl" in delta.new_observables[0].initial_directives

    @pytest.mark.unit
    def test_diff_remove_tag(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IPV4, "10.0.0.1")
        obs.add_tag("benign")
        module = _make_mock_module()

        before = ModuleExecutionSnapshot.narrow(root, obs, module)
        obs.remove_tag("benign")
        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert delta.target_observable_diff.removed_tags == ["benign"]
        assert delta.has_removals

    @pytest.mark.unit
    def test_diff_no_changes(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IPV4, "10.0.0.1")
        module = _make_mock_module()

        before = ModuleExecutionSnapshot.narrow(root, obs, module)
        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert delta.is_empty
        assert not delta.has_removals

    @pytest.mark.unit
    def test_diff_root_tag(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IPV4, "10.0.0.1")
        module = _make_mock_module()

        before = ModuleExecutionSnapshot.narrow(root, obs, module)
        root.add_tag("alert_tag")
        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert delta.root_diff.added_tags == ["alert_tag"]

    @pytest.mark.unit
    def test_diff_scalar_transitions(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IPV4, "10.0.0.1")
        module = _make_mock_module()

        before = ModuleExecutionSnapshot.narrow(root, obs, module)
        obs._grouping_target = True
        obs._ignored = True
        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert delta.target_observable_diff.grouping_target == (False, True)
        assert delta.target_observable_diff.ignored == (False, True)

    @pytest.mark.unit
    def test_diff_excluded_and_limited_analysis(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IPV4, "10.0.0.1")
        module = _make_mock_module()

        before = ModuleExecutionSnapshot.narrow(root, obs, module)
        obs._excluded_analysis.append("saq.modules.test:TestAnalysis")
        obs._limited_analysis.append("saq.modules.other:OtherAnalysis")
        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert delta.target_observable_diff.added_excluded_analysis == ["saq.modules.test:TestAnalysis"]
        assert delta.target_observable_diff.added_limited_analysis == ["saq.modules.other:OtherAnalysis"]


class TestWideSnapshot:
    @pytest.mark.unit
    def test_wide_captures_other_observable_mutations(self, tmp_path):
        root = _make_root(tmp_path)
        target_obs = root.add_observable_by_spec(F_IPV4, "10.0.0.1")
        other_obs = root.add_observable_by_spec(F_FQDN, "example.com")
        module = _make_mock_module(wide_diff=True)

        before = ModuleExecutionSnapshot.wide(root, target_obs, module)

        # Simulate a wide-diff module mutating a different observable
        other_obs.add_tag("suspicious")
        other_obs.add_directive("sandbox")

        after = ModuleExecutionSnapshot.wide(root, target_obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, target_obs)

        assert delta.wide_diff is True
        assert other_obs.uuid in delta.other_observable_diffs
        other_diff = delta.other_observable_diffs[other_obs.uuid]
        assert "suspicious" in other_diff.added_tags
        assert "sandbox" in other_diff.added_directives

    @pytest.mark.unit
    def test_wide_does_not_include_empty_diffs(self, tmp_path):
        root = _make_root(tmp_path)
        target_obs = root.add_observable_by_spec(F_IPV4, "10.0.0.1")
        other_obs = root.add_observable_by_spec(F_FQDN, "example.com")
        module = _make_mock_module(wide_diff=True)

        before = ModuleExecutionSnapshot.wide(root, target_obs, module)
        # Only mutate the target, not the other
        target_obs.add_tag("tagged")
        after = ModuleExecutionSnapshot.wide(root, target_obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, target_obs)

        assert delta.target_observable_diff.added_tags == ["tagged"]
        # other_obs had no changes, so it should not appear
        assert other_obs.uuid not in delta.other_observable_diffs


class TestAnalysisChildrenTracking:
    @pytest.mark.unit
    def test_wide_captures_child_removal_from_analysis(self, tmp_path):
        """Simulate the ignore action: remove an observable from a parent analysis's _observables."""
        root = _make_root(tmp_path)
        # Create observables
        target_obs = root.add_observable_by_spec(F_IPV4, "10.0.0.1")
        child_obs = root.add_observable_by_spec(F_EMAIL_ADDRESS, "victim@example.com")

        # Create an Analysis on target_obs that has child_obs as a child
        analysis = Analysis()
        analysis._observables.append(child_obs)
        target_obs.add_analysis_to_tree(analysis, target_obs)

        module = _make_mock_module(wide_diff=True)
        before = ModuleExecutionSnapshot.wide(root, target_obs, module)

        # Simulate ignore action: remove child_obs from the analysis
        analysis._observables.remove(child_obs)

        after = ModuleExecutionSnapshot.wide(root, target_obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, target_obs)

        assert len(delta.analysis_children_diffs) == 1
        acd = delta.analysis_children_diffs[0]
        assert child_obs.uuid in acd.removed_child_uuids
        assert acd.parent_observable_uuid == target_obs.uuid
        assert delta.has_removals

    @pytest.mark.unit
    def test_wide_captures_child_addition_to_analysis(self, tmp_path):
        """Track when a module adds an observable as a child of an existing analysis."""
        root = _make_root(tmp_path)
        target_obs = root.add_observable_by_spec(F_IPV4, "10.0.0.1")
        new_child = root.add_observable_by_spec(F_FQDN, "example.com")

        analysis = Analysis()
        target_obs.add_analysis_to_tree(analysis, target_obs)

        module = _make_mock_module(wide_diff=True)
        before = ModuleExecutionSnapshot.wide(root, target_obs, module)

        # Add new_child to the analysis
        analysis._observables.append(new_child)

        after = ModuleExecutionSnapshot.wide(root, target_obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, target_obs)

        assert len(delta.analysis_children_diffs) == 1
        acd = delta.analysis_children_diffs[0]
        assert new_child.uuid in acd.added_child_uuids

    @pytest.mark.unit
    def test_no_analysis_children_diff_when_unchanged(self, tmp_path):
        root = _make_root(tmp_path)
        target_obs = root.add_observable_by_spec(F_IPV4, "10.0.0.1")
        child_obs = root.add_observable_by_spec(F_FQDN, "example.com")

        analysis = Analysis()
        analysis._observables.append(child_obs)
        target_obs.add_analysis_to_tree(analysis, target_obs)

        module = _make_mock_module(wide_diff=True)
        before = ModuleExecutionSnapshot.wide(root, target_obs, module)
        # No changes
        after = ModuleExecutionSnapshot.wide(root, target_obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, target_obs)

        assert len(delta.analysis_children_diffs) == 0

    @pytest.mark.unit
    def test_narrow_does_not_track_analysis_children(self, tmp_path):
        """Narrow snapshots don't capture analysis children — only wide does."""
        root = _make_root(tmp_path)
        target_obs = root.add_observable_by_spec(F_IPV4, "10.0.0.1")
        child_obs = root.add_observable_by_spec(F_FQDN, "example.com")

        analysis = Analysis()
        analysis._observables.append(child_obs)
        target_obs.add_analysis_to_tree(analysis, target_obs)

        module = _make_mock_module()
        before = ModuleExecutionSnapshot.narrow(root, target_obs, module)
        analysis._observables.remove(child_obs)
        after = ModuleExecutionSnapshot.narrow(root, target_obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, target_obs)

        # Narrow snapshots don't capture analysis children
        assert len(delta.analysis_children_diffs) == 0


class TestDeltaModuleMetadata:
    @pytest.mark.unit
    def test_module_identity_captured(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IPV4, "10.0.0.1")
        module = _make_mock_module(
            name="saq.modules.intel:ThreatIntel",
            instance="instance1",
            version=3,
        )

        before = ModuleExecutionSnapshot.narrow(root, obs, module)
        obs.add_tag("malicious")
        after = ModuleExecutionSnapshot.narrow(root, obs, module)
        delta = ModuleExecutionSnapshot.diff(before, after, module, obs)

        assert delta.module_instance == "instance1"
        assert delta.module_version == 3
        assert delta.observable_uuid == obs.uuid
        assert delta.observable_type == F_IPV4
        assert delta.observable_value == "10.0.0.1"
        assert delta.created_at is not None
