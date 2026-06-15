"""Unit tests for saq.analysis.cache.apply_delta (Phase 3 Step 3.5)."""
import logging
from datetime import datetime, timezone

import pytest

from saq.analysis.cache import apply_delta
from saq.analysis.module_execution_delta import (
    ModuleExecutionDelta,
    ObservableDiff,
    ObservableSpec,
    RootDiff,
)
from saq.analysis.root import RootAnalysis
from saq.constants import F_EMAIL_ADDRESS, F_FILE, F_FQDN, F_IPV4, F_URL, F_USER, R_IS_HASH_OF
from saq.modules.rdap import RdapAnalysis


def _make_root(tmp_path):
    root = RootAnalysis(storage_dir=str(tmp_path))
    root.initialize_storage()
    return root


def _empty_delta(target_observable, **overrides):
    """Build a minimum-shape delta for the target observable, with
    optional overrides for specific fields under test.
    """
    defaults = dict(
        module_path="saq.modules.test:DummyAnalysis",
        module_instance=None,
        module_version=1,
        observable_uuid=target_observable.uuid,
        observable_type=target_observable.type,
        observable_value=target_observable.value,
        created_at=datetime.now(timezone.utc).isoformat(),
        execution_time_ms=42,
        analysis=None,
        target_observable_diff=ObservableDiff(),
        new_observables=[],
        root_diff=RootDiff(),
    )
    defaults.update(overrides)
    return ModuleExecutionDelta(**defaults)


class TestApplyDeltaPrimitives:

    @pytest.mark.unit
    def test_added_tags_applied(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IPV4, "10.0.0.1")
        delta = _empty_delta(
            obs,
            target_observable_diff=ObservableDiff(added_tags=["suspicious", "malware"]),
        )
        apply_delta(root, obs, delta)
        assert "suspicious" in obs.tags
        assert "malware" in obs.tags

    @pytest.mark.unit
    def test_added_detections_applied(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IPV4, "10.0.0.1")
        delta = _empty_delta(
            obs,
            target_observable_diff=ObservableDiff(
                added_detections=[
                    {"description": "yara hit", "details": {"rule": "phish"}},
                ],
            ),
        )
        apply_delta(root, obs, delta)
        assert len(obs.detections) == 1
        assert obs.detections[0].description == "yara hit"
        assert obs.detections[0].details == {"rule": "phish"}

    @pytest.mark.unit
    def test_added_directives_applied(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IPV4, "10.0.0.1")
        delta = _empty_delta(
            obs,
            target_observable_diff=ObservableDiff(added_directives=["sandbox"]),
        )
        apply_delta(root, obs, delta)
        assert obs.has_directive("sandbox")

    @pytest.mark.unit
    def test_added_relationship_resolves_existing_target(self, tmp_path):
        root = _make_root(tmp_path)
        src = root.add_observable_by_spec(F_FQDN, "example.com")
        # Pre-existing target observable in the tree.
        target = root.add_observable_by_spec(F_IPV4, "1.2.3.4")
        delta = _empty_delta(
            src,
            target_observable_diff=ObservableDiff(
                added_relationships=[{"type": R_IS_HASH_OF, "target": target.uuid}],
            ),
        )
        apply_delta(root, src, delta)
        assert any(
            r.r_type == R_IS_HASH_OF and r.target.uuid == target.uuid
            for r in src.relationships
        )

    @pytest.mark.unit
    def test_relationship_with_missing_target_skipped(self, tmp_path, caplog):
        """Legacy uuid-only relationship dict (no target spec) whose uuid
        isn't in the tree: skipped with a WARNING, never raises."""
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_FQDN, "example.com")
        delta = _empty_delta(
            obs,
            target_observable_diff=ObservableDiff(
                added_relationships=[{"type": R_IS_HASH_OF, "target": "missing-uuid"}],
            ),
        )
        with caplog.at_level(logging.WARNING):
            apply_delta(root, obs, delta)
        assert not obs.relationships
        assert any("target unresolved" in rec.message for rec in caplog.records)

    @pytest.mark.unit
    def test_relationship_resolved_by_spec_on_fresh_root(self, tmp_path):
        """Cross-root replay: the cached target uuid means nothing on the
        new root, but the (type, value) spec resolves to the observable
        the same delta just created."""
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_FQDN, "example.com")
        delta = _empty_delta(
            obs,
            observable_uuid="source-obs-uuid",  # captured on a different alert
            new_observables=[
                ObservableSpec(uuid="source-child-uuid", type=F_IPV4, value="1.2.3.4"),
            ],
            target_observable_diff=ObservableDiff(
                added_relationships=[{
                    "type": R_IS_HASH_OF,
                    "target": "source-child-uuid",
                    "target_type": F_IPV4,
                    "target_value": "1.2.3.4",
                }],
            ),
        )
        apply_delta(root, obs, delta)

        assert len(obs.relationships) == 1
        resolved = obs.relationships[0].target
        assert resolved.type == F_IPV4
        assert resolved.value == "1.2.3.4"
        # The replayed child got a fresh uuid — spec resolution, not uuid.
        assert resolved.uuid != "source-child-uuid"

    @pytest.mark.unit
    def test_self_relationship_resolves_despite_time_mismatch(self, tmp_path):
        """A relationship whose target is the analyzed observable itself
        must resolve via the self-target shortcut. The current
        observable carries an event time the source didn't, so a
        (type, value, time) spec lookup would miss — the shortcut on
        delta.observable_uuid is what makes this work."""
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(
            F_FQDN, "example.com", o_time=datetime(2026, 6, 1, tzinfo=timezone.utc),
        )
        delta = _empty_delta(
            obs,
            observable_uuid="source-obs-uuid",
            target_observable_diff=ObservableDiff(
                added_relationships=[{
                    "type": R_IS_HASH_OF,
                    "target": "source-obs-uuid",
                    "target_type": F_FQDN,
                    "target_value": "example.com",
                }],
            ),
        )
        apply_delta(root, obs, delta)

        assert len(obs.relationships) == 1
        assert obs.relationships[0].target is obs

    @pytest.mark.unit
    def test_excluded_and_limited_dedupe(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IPV4, "10.0.0.1")
        delta = _empty_delta(
            obs,
            target_observable_diff=ObservableDiff(
                added_excluded_analysis=["mod.a:A"],
                added_limited_analysis=["mod.b:B"],
            ),
        )
        apply_delta(root, obs, delta)
        apply_delta(root, obs, delta)  # idempotent re-apply
        assert obs._excluded_analysis == ["mod.a:A"]
        assert obs._limited_analysis == ["mod.b:B"]

    @pytest.mark.unit
    def test_scalar_transitions_applied(self, tmp_path):
        root = _make_root(tmp_path)
        obs = root.add_observable_by_spec(F_IPV4, "10.0.0.1")
        delta = _empty_delta(
            obs,
            target_observable_diff=ObservableDiff(
                grouping_target=(False, True),
                ignored=(False, True),
            ),
        )
        apply_delta(root, obs, delta)
        assert obs.grouping_target is True
        assert obs._ignored is True


class TestApplyDeltaNewObservables:

    @pytest.mark.unit
    def test_new_observable_spawned_under_root(self, tmp_path):
        root = _make_root(tmp_path)
        target = root.add_observable_by_spec(F_FQDN, "example.com")
        spec = ObservableSpec(
            uuid="11111111-1111-1111-1111-111111111111",
            type=F_URL,
            value="https://example.com/path",
            initial_tags=["from_replay"],
            initial_directives=["sandbox"],
        )
        delta = _empty_delta(target, new_observables=[spec])
        apply_delta(root, target, delta)
        urls = [o for o in root.all_observables if o.type == F_URL]
        assert len(urls) == 1
        assert "from_replay" in urls[0].tags
        assert urls[0].has_directive("sandbox")

    @pytest.mark.unit
    def test_new_observable_carries_excluded_analysis_on_replay(self, tmp_path):
        """Some analysis modules add a child observable and
        immediately call .exclude_analysis(self) on it so the module won't
        recurse. On cache replay that exclusion must be re-applied —
        otherwise the cached module runs against its own children.
        """
        root = _make_root(tmp_path)
        target = root.add_observable_by_spec(F_EMAIL_ADDRESS, "user@company.com")
        spec = ObservableSpec(
            uuid="33333333-3333-3333-3333-333333333333",
            type=F_USER,
            value="Usr123",
            initial_excluded_analysis=["UserLookupAnalyzer"],
            initial_limited_analysis=["LimitedAnalyzer"],
        )
        delta = _empty_delta(target, new_observables=[spec])
        apply_delta(root, target, delta)

        users = [o for o in root.all_observables if o.type == F_USER]
        assert len(users) == 1
        assert "UserLookupAnalyzer" in users[0]._excluded_analysis
        assert "LimitedAnalyzer" in users[0]._limited_analysis

    @pytest.mark.unit
    def test_new_observable_dedup_on_replay(self, tmp_path):
        """Calling apply_delta twice on the same root must NOT spawn a
        second observable — analysis_tree_manager dedupes by
        (type, value, time) and the add_* primitives are idempotent.
        """
        root = _make_root(tmp_path)
        target = root.add_observable_by_spec(F_FQDN, "example.com")
        spec = ObservableSpec(
            uuid="22222222-2222-2222-2222-222222222222",
            type=F_URL,
            value="https://example.com/path",
            initial_tags=["replay"],
        )
        delta = _empty_delta(target, new_observables=[spec])

        apply_delta(root, target, delta)
        apply_delta(root, target, delta)

        urls = [o for o in root.all_observables if o.type == F_URL]
        assert len(urls) == 1
        assert urls[0].tags.count("replay") == 1


class TestApplyDeltaRehydration:

    @pytest.mark.unit
    def test_analysis_rehydrated_on_target(self, tmp_path):
        """A delta carrying ``analysis`` must rehydrate that analysis on
        the target observable's _analysis slot.
        """

        root = _make_root(tmp_path)
        target = root.add_observable_by_spec(F_FQDN, "example.com")
        analysis_dict = {
            "module_path": "saq.modules.rdap:RdapAnalysis",
            "details": {"registrar": "Test Registrar"},
            "summary": "whois ok",
            "completed": True,
            "delayed": False,
        }
        delta = _empty_delta(target, analysis=analysis_dict)
        apply_delta(root, target, delta)

        rehydrated = target.get_analysis(RdapAnalysis)
        assert rehydrated is not None
        assert isinstance(rehydrated, RdapAnalysis)
        assert rehydrated.details == {"registrar": "Test Registrar"}

    @pytest.mark.unit
    def test_external_details_path_stripped(self, tmp_path):
        """external_details_path on the cached dict points at the SOURCE
        alert's storage_dir. Replay must drop it so the persistence
        manager re-derives a fresh path under the TARGET alert.
        """

        root = _make_root(tmp_path)
        target = root.add_observable_by_spec(F_FQDN, "example.com")
        analysis_dict = {
            "module_path": "saq.modules.rdap:RdapAnalysis",
            "details": {"x": 1},
            "external_details_path": "/some/source/alert/path/whois_xxx.json",
            "completed": True,
            "delayed": False,
        }
        delta = _empty_delta(target, analysis=analysis_dict)
        apply_delta(root, target, delta)

        rehydrated = target.get_analysis(RdapAnalysis)
        assert rehydrated.external_details_path is None

    @pytest.mark.unit
    def test_slot_collision_skips_rehydration(self, tmp_path):
        """If the slot already has an Analysis instance (re-analysis or
        retry), the existing one must be preserved rather than replaced
        with a fresh rehydration. Idempotent diffs still apply.
        """

        root = _make_root(tmp_path)
        target = root.add_observable_by_spec(F_FQDN, "example.com")

        # Pre-install an existing analysis at the slot.
        existing = RdapAnalysis()
        existing.details = {"sentinel": "preexisting"}
        target.analysis_tree_manager.add_analysis(target, existing)

        analysis_dict = {
            "module_path": "saq.modules.rdap:RdapAnalysis",
            "details": {"sentinel": "from_cache"},
            "completed": True,
            "delayed": False,
        }
        delta = _empty_delta(
            target,
            analysis=analysis_dict,
            target_observable_diff=ObservableDiff(added_tags=["replay-tag"]),
        )
        apply_delta(root, target, delta)

        # Existing analysis preserved (sentinel unchanged).
        kept = target.get_analysis(RdapAnalysis)
        assert kept is existing
        assert kept.details == {"sentinel": "preexisting"}
        # Diffs still applied.
        assert "replay-tag" in target.tags

    @pytest.mark.unit
    def test_analysis_tags_rehydrated(self, tmp_path):
        """Tags captured off the Analysis object must be restored on the
        rehydrated analysis (they flow through the analysis.json setter →
        AnalysisSerializer.deserialize → BaseNode.set_json_data)."""

        root = _make_root(tmp_path)
        target = root.add_observable_by_spec(F_FQDN, "example.com")
        analysis_dict = {
            "module_path": "saq.modules.rdap:RdapAnalysis",
            "details": {"registrar": "Test Registrar"},
            "tags": ["registrar:test", "cached"],
            "completed": True,
            "delayed": False,
        }
        delta = _empty_delta(target, analysis=analysis_dict)
        apply_delta(root, target, delta)

        rehydrated = target.get_analysis(RdapAnalysis)
        assert rehydrated.tags == ["registrar:test", "cached"]

    @pytest.mark.unit
    def test_slot_collision_leaves_existing_analysis_tags_alone(self, tmp_path):

        root = _make_root(tmp_path)
        target = root.add_observable_by_spec(F_FQDN, "example.com")
        existing = RdapAnalysis()
        existing.add_tag("preexisting")
        target.analysis_tree_manager.add_analysis(target, existing)

        analysis_dict = {
            "module_path": "saq.modules.rdap:RdapAnalysis",
            "details": {},
            "tags": ["from-cache"],
            "completed": True,
            "delayed": False,
        }
        delta = _empty_delta(target, analysis=analysis_dict)
        apply_delta(root, target, delta)

        kept = target.get_analysis(RdapAnalysis)
        assert kept is existing
        assert kept.tags == ["preexisting"]

    @pytest.mark.unit
    def test_idempotent_double_apply(self, tmp_path):
        """Calling apply_delta twice must produce the same tree state as
        one call — no double tags, no slot replacement, no duplicate
        observables.
        """

        root = _make_root(tmp_path)
        target = root.add_observable_by_spec(F_FQDN, "example.com")
        analysis_dict = {
            "module_path": "saq.modules.rdap:RdapAnalysis",
            "details": {"x": 1},
            "completed": True,
            "delayed": False,
        }
        delta = _empty_delta(
            target,
            analysis=analysis_dict,
            target_observable_diff=ObservableDiff(added_tags=["once"]),
        )

        apply_delta(root, target, delta)
        apply_delta(root, target, delta)

        assert target.tags.count("once") == 1
        assert isinstance(target.get_analysis(RdapAnalysis), RdapAnalysis)


class TestApplyDeltaContractEnforcement:

    @pytest.mark.unit
    def test_wide_diff_raises(self, tmp_path):
        """Wide-diff deltas must never reach the replay path
        (config validation refuses cache_ttl + wide_diff). Defense-in-depth
        assertion enforces this even if the config check is bypassed.
        """
        root = _make_root(tmp_path)
        target = root.add_observable_by_spec(F_FQDN, "example.com")
        delta = _empty_delta(target, wide_diff=True)
        with pytest.raises(AssertionError, match="wide_diff"):
            apply_delta(root, target, delta)

    @pytest.mark.unit
    def test_file_observables_refused_at_replay(self, tmp_path, caplog):
        """Read-time defense-in-depth — even if a malformed row from a
        prior buggy build slips past the write guard, replay must refuse
        rather than partially apply.
        """
        root = _make_root(tmp_path)
        target = root.add_observable_by_spec(F_FQDN, "example.com")
        delta = _empty_delta(
            target,
            new_observables=[
                ObservableSpec(
                    uuid="33333333-3333-3333-3333-333333333333",
                    type=F_FILE,
                    value="some/file.txt",
                ),
            ],
            target_observable_diff=ObservableDiff(added_tags=["should-not-apply"]),
        )
        with caplog.at_level(logging.WARNING):
            apply_delta(root, target, delta)
        # Nothing should have been applied — caller is told via log.
        assert "should-not-apply" not in target.tags
        warns = [r for r in caplog.records if "refusal_reason=file_observables" in r.getMessage()]
        assert warns
        assert warns[0].refusal_reason == "file_observables"


class TestApplyDeltaRootLevel:

    @pytest.mark.unit
    def test_root_diff_added_tags(self, tmp_path):
        root = _make_root(tmp_path)
        target = root.add_observable_by_spec(F_FQDN, "example.com")
        delta = _empty_delta(
            target,
            root_diff=RootDiff(added_tags=["root-tag"]),
        )
        apply_delta(root, target, delta)
        assert "root-tag" in root.tags

    @pytest.mark.unit
    def test_root_diff_added_detections(self, tmp_path):
        root = _make_root(tmp_path)
        target = root.add_observable_by_spec(F_FQDN, "example.com")
        delta = _empty_delta(
            target,
            root_diff=RootDiff(
                added_detections=[{"description": "root det", "details": None}],
            ),
        )
        apply_delta(root, target, delta)
        assert len(root.detections) == 1
        assert root.detections[0].description == "root det"
