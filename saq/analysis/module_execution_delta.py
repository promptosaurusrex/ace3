"""Data structures for recording per-module analysis deltas.

A ModuleExecutionDelta captures exactly what a single analysis module execution
changed on the analysis tree: tags added/removed, observables created, detection
points added, etc. Recorded at the executor boundary (snapshot before → snapshot
after → diff) and stored in RootAnalysis._module_executions for attribution and
eventual caching.
"""

from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Optional

from saq.constants import F_FILE


@dataclass
class ObservableDiff:
    """Changes to a single observable's mutable fields during one module execution."""

    # Set-valued fields: additions and removals
    added_tags: list[str] = field(default_factory=list)
    removed_tags: list[str] = field(default_factory=list)

    added_detections: list[dict] = field(default_factory=list)
    removed_detections: list[dict] = field(default_factory=list)

    added_directives: list[str] = field(default_factory=list)
    removed_directives: list[str] = field(default_factory=list)

    added_relationships: list[dict] = field(default_factory=list)
    removed_relationships: list[dict] = field(default_factory=list)

    added_excluded_analysis: list[str] = field(default_factory=list)
    removed_excluded_analysis: list[str] = field(default_factory=list)

    added_limited_analysis: list[str] = field(default_factory=list)
    removed_limited_analysis: list[str] = field(default_factory=list)

    # Scalar transitions: (before, after) or None if unchanged
    grouping_target: Optional[tuple] = None  # (bool, bool)
    redirection: Optional[tuple] = None  # (str|None, str|None)
    ignored: Optional[tuple] = None  # (bool, bool)

    @property
    def has_removals(self) -> bool:
        return bool(
            self.removed_tags
            or self.removed_detections
            or self.removed_directives
            or self.removed_relationships
            or self.removed_excluded_analysis
            or self.removed_limited_analysis
        )

    @property
    def is_empty(self) -> bool:
        return (
            not self.added_tags
            and not self.removed_tags
            and not self.added_detections
            and not self.removed_detections
            and not self.added_directives
            and not self.removed_directives
            and not self.added_relationships
            and not self.removed_relationships
            and not self.added_excluded_analysis
            and not self.removed_excluded_analysis
            and not self.added_limited_analysis
            and not self.removed_limited_analysis
            and self.grouping_target is None
            and self.redirection is None
            and self.ignored is None
        )

    def to_dict(self) -> dict:
        result = {}
        # Only include non-empty fields to keep serialization compact
        if self.added_tags:
            result["added_tags"] = self.added_tags
        if self.removed_tags:
            result["removed_tags"] = self.removed_tags
        if self.added_detections:
            result["added_detections"] = self.added_detections
        if self.removed_detections:
            result["removed_detections"] = self.removed_detections
        if self.added_directives:
            result["added_directives"] = self.added_directives
        if self.removed_directives:
            result["removed_directives"] = self.removed_directives
        if self.added_relationships:
            result["added_relationships"] = self.added_relationships
        if self.removed_relationships:
            result["removed_relationships"] = self.removed_relationships
        if self.added_excluded_analysis:
            result["added_excluded_analysis"] = self.added_excluded_analysis
        if self.removed_excluded_analysis:
            result["removed_excluded_analysis"] = self.removed_excluded_analysis
        if self.added_limited_analysis:
            result["added_limited_analysis"] = self.added_limited_analysis
        if self.removed_limited_analysis:
            result["removed_limited_analysis"] = self.removed_limited_analysis
        if self.grouping_target is not None:
            result["grouping_target"] = list(self.grouping_target)
        if self.redirection is not None:
            result["redirection"] = list(self.redirection)
        if self.ignored is not None:
            result["ignored"] = list(self.ignored)
        return result

    @classmethod
    def from_dict(cls, data: dict) -> "ObservableDiff":
        diff = cls()
        diff.added_tags = data.get("added_tags", [])
        diff.removed_tags = data.get("removed_tags", [])
        diff.added_detections = data.get("added_detections", [])
        diff.removed_detections = data.get("removed_detections", [])
        diff.added_directives = data.get("added_directives", [])
        diff.removed_directives = data.get("removed_directives", [])
        diff.added_relationships = data.get("added_relationships", [])
        diff.removed_relationships = data.get("removed_relationships", [])
        diff.added_excluded_analysis = data.get("added_excluded_analysis", [])
        diff.removed_excluded_analysis = data.get("removed_excluded_analysis", [])
        diff.added_limited_analysis = data.get("added_limited_analysis", [])
        diff.removed_limited_analysis = data.get("removed_limited_analysis", [])
        if "grouping_target" in data:
            diff.grouping_target = tuple(data["grouping_target"])
        if "redirection" in data:
            diff.redirection = tuple(data["redirection"])
        if "ignored" in data:
            diff.ignored = tuple(data["ignored"])
        return diff


@dataclass
class ObservableSpec:
    """Enough information to re-add an observable to a root on cache replay."""

    uuid: str
    type: str
    value: str
    time: Optional[str] = None  # ISO format string for serialization
    initial_tags: list[str] = field(default_factory=list)
    initial_directives: list[str] = field(default_factory=list)
    initial_detections: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        result = {
            "uuid": self.uuid,
            "type": self.type,
            "value": self.value,
        }
        if self.time is not None:
            result["time"] = self.time
        if self.initial_tags:
            result["initial_tags"] = self.initial_tags
        if self.initial_directives:
            result["initial_directives"] = self.initial_directives
        if self.initial_detections:
            result["initial_detections"] = self.initial_detections
        return result

    @classmethod
    def from_dict(cls, data: dict) -> "ObservableSpec":
        return cls(
            uuid=data["uuid"],
            type=data["type"],
            value=data["value"],
            time=data.get("time"),
            initial_tags=data.get("initial_tags", []),
            initial_directives=data.get("initial_directives", []),
            initial_detections=data.get("initial_detections", []),
        )


@dataclass
class RootDiff:
    """Changes to root-level tags and detections during one module execution."""

    added_tags: list[str] = field(default_factory=list)
    removed_tags: list[str] = field(default_factory=list)
    added_detections: list[dict] = field(default_factory=list)
    removed_detections: list[dict] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return (
            not self.added_tags
            and not self.removed_tags
            and not self.added_detections
            and not self.removed_detections
        )

    def to_dict(self) -> dict:
        result = {}
        if self.added_tags:
            result["added_tags"] = self.added_tags
        if self.removed_tags:
            result["removed_tags"] = self.removed_tags
        if self.added_detections:
            result["added_detections"] = self.added_detections
        if self.removed_detections:
            result["removed_detections"] = self.removed_detections
        return result

    @classmethod
    def from_dict(cls, data: dict) -> "RootDiff":
        return cls(
            added_tags=data.get("added_tags", []),
            removed_tags=data.get("removed_tags", []),
            added_detections=data.get("added_detections", []),
            removed_detections=data.get("removed_detections", []),
        )


@dataclass
class AnalysisChildrenDiff:
    """Changes to an Analysis object's child observable membership.

    Captures when observables are added to or removed from an Analysis's
    _observables list (e.g., ObservableModifier's ignore action removes
    an observable from its parent analysis).
    """

    # The module_path of the Analysis object whose children changed
    analysis_module_path: str

    # The UUID of the observable that owns this Analysis
    parent_observable_uuid: str

    # Observable UUIDs added/removed from this Analysis's _observables
    added_child_uuids: list[str] = field(default_factory=list)
    removed_child_uuids: list[str] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not self.added_child_uuids and not self.removed_child_uuids

    def to_dict(self) -> dict:
        result = {
            "analysis_module_path": self.analysis_module_path,
            "parent_observable_uuid": self.parent_observable_uuid,
        }
        if self.added_child_uuids:
            result["added_child_uuids"] = self.added_child_uuids
        if self.removed_child_uuids:
            result["removed_child_uuids"] = self.removed_child_uuids
        return result

    @classmethod
    def from_dict(cls, data: dict) -> "AnalysisChildrenDiff":
        return cls(
            analysis_module_path=data["analysis_module_path"],
            parent_observable_uuid=data["parent_observable_uuid"],
            added_child_uuids=data.get("added_child_uuids", []),
            removed_child_uuids=data.get("removed_child_uuids", []),
        )


@dataclass
class ModuleExecutionDelta:
    """Complete record of what one analysis module execution changed.

    Recorded by the executor after each successful module.analyze() call.
    Stored in RootAnalysis._module_executions and serialized into root.json.
    """

    # Module identity
    module_path: str
    module_instance: Optional[str]
    module_version: int

    # Observable identity (the observable being analyzed)
    observable_uuid: str
    observable_type: str
    observable_value: str

    # Timing
    created_at: str  # ISO format
    execution_time_ms: int = 0

    # The analysis object produced by this module (serialized), or None
    analysis: Optional[dict] = None

    # What changed
    target_observable_diff: ObservableDiff = field(default_factory=ObservableDiff)
    new_observables: list[ObservableSpec] = field(default_factory=list)
    root_diff: RootDiff = field(default_factory=RootDiff)

    # Cache support (Phase 2+)
    cache_key: Optional[str] = None

    # Whether this was a wide-diff capture (all observables, not just target)
    wide_diff: bool = False

    # For wide-diff: diffs on observables other than the target
    # Maps observable_uuid -> ObservableDiff
    other_observable_diffs: dict[str, ObservableDiff] = field(default_factory=dict)

    # For wide-diff: changes to Analysis objects' child observable membership
    analysis_children_diffs: list[AnalysisChildrenDiff] = field(default_factory=list)

    # Phase 3: True when this delta was synthesized by a cache replay rather
    # than a live module run. Lets audit consumers (root.json readers, GUI)
    # distinguish replay attribution from live attribution.
    from_cache_hit: bool = False

    @property
    def has_removals(self) -> bool:
        if self.target_observable_diff.has_removals:
            return True
        for diff in self.other_observable_diffs.values():
            if diff.has_removals:
                return True
        for acd in self.analysis_children_diffs:
            if acd.removed_child_uuids:
                return True
        return False

    @property
    def is_empty(self) -> bool:
        return (
            self.target_observable_diff.is_empty
            and not self.new_observables
            and self.root_diff.is_empty
            and self.analysis is None
            and not self.other_observable_diffs
            and not self.analysis_children_diffs
        )

    @property
    def has_file_observables(self) -> bool:
        """True if this delta would spawn file observables on replay.

        Phase 3 cache replay does not yet materialize file bytes (Phase 4
        territory). Used as a write-time refusal and a read-time
        defense-in-depth check.
        """
        return any(spec.type == F_FILE for spec in self.new_observables)

    def with_cache_hit_metadata(
        self, executed_at: datetime, execution_time_ms: int,
    ) -> "ModuleExecutionDelta":
        """Return a copy of this delta marked as a cache replay.

        Preserves all mutation fields (so root.json shows the same
        attribution as the original live run) but updates the timestamps
        and sets ``from_cache_hit=True``. Used by the executor's cache-hit
        branch to record replay attribution distinct from live runs.
        """
        return replace(
            self,
            created_at=executed_at.isoformat(),
            execution_time_ms=execution_time_ms,
            from_cache_hit=True,
        )

    def to_dict(self) -> dict:
        result = {
            "module_path": self.module_path,
            "module_version": self.module_version,
            "observable_uuid": self.observable_uuid,
            "observable_type": self.observable_type,
            "observable_value": self.observable_value,
            "created_at": self.created_at,
            "execution_time_ms": self.execution_time_ms,
        }
        if self.module_instance is not None:
            result["module_instance"] = self.module_instance
        if self.analysis is not None:
            result["analysis"] = self.analysis
        if not self.target_observable_diff.is_empty:
            result["target_observable_diff"] = self.target_observable_diff.to_dict()
        if self.new_observables:
            result["new_observables"] = [o.to_dict() for o in self.new_observables]
        if not self.root_diff.is_empty:
            result["root_diff"] = self.root_diff.to_dict()
        if self.cache_key is not None:
            result["cache_key"] = self.cache_key
        if self.wide_diff:
            result["wide_diff"] = True
        if self.other_observable_diffs:
            result["other_observable_diffs"] = {
                uuid: diff.to_dict()
                for uuid, diff in self.other_observable_diffs.items()
                if not diff.is_empty
            }
        if self.analysis_children_diffs:
            result["analysis_children_diffs"] = [
                acd.to_dict() for acd in self.analysis_children_diffs
                if not acd.is_empty
            ]
        if self.from_cache_hit:
            result["from_cache_hit"] = True
        return result

    @classmethod
    def from_dict(cls, data: dict) -> "ModuleExecutionDelta":
        target_diff = ObservableDiff.from_dict(data["target_observable_diff"]) if "target_observable_diff" in data else ObservableDiff()
        new_obs = [ObservableSpec.from_dict(o) for o in data.get("new_observables", [])]
        root_diff = RootDiff.from_dict(data["root_diff"]) if "root_diff" in data else RootDiff()
        other_diffs = {
            uuid: ObservableDiff.from_dict(d)
            for uuid, d in data.get("other_observable_diffs", {}).items()
        }
        analysis_children = [
            AnalysisChildrenDiff.from_dict(acd)
            for acd in data.get("analysis_children_diffs", [])
        ]

        return cls(
            module_path=data["module_path"],
            module_instance=data.get("module_instance"),
            module_version=data["module_version"],
            observable_uuid=data["observable_uuid"],
            observable_type=data["observable_type"],
            observable_value=data["observable_value"],
            created_at=data["created_at"],
            execution_time_ms=data.get("execution_time_ms", 0),
            analysis=data.get("analysis"),
            target_observable_diff=target_diff,
            new_observables=new_obs,
            root_diff=root_diff,
            cache_key=data.get("cache_key"),
            wide_diff=data.get("wide_diff", False),
            other_observable_diffs=other_diffs,
            analysis_children_diffs=analysis_children,
            from_cache_hit=data.get("from_cache_hit", False),
        )
