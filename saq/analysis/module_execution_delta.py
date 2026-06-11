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
    initial_excluded_analysis: list[str] = field(default_factory=list)
    initial_limited_analysis: list[str] = field(default_factory=list)

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
        if self.initial_excluded_analysis:
            result["initial_excluded_analysis"] = self.initial_excluded_analysis
        if self.initial_limited_analysis:
            result["initial_limited_analysis"] = self.initial_limited_analysis
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
            initial_excluded_analysis=data.get("initial_excluded_analysis", []),
            initial_limited_analysis=data.get("initial_limited_analysis", []),
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

    # Root analysis this delta was recorded against. Denormalized (like the
    # observable_* fields) so a delta is self-describing in logs and in the
    # cache row — and so a cached delta carries the provenance of the alert
    # that first produced it. On a cache-hit replay, with_cache_hit_metadata()
    # rewrites this to the *current* root being analyzed.
    root_uuid: str = ""

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

    # Phase 3: when from_cache_hit is True, the ISO timestamp of the *original*
    # live capture (i.e. when the cached delta was first written to the cache).
    # ``created_at`` gets rewritten to the replay time by with_cache_hit_metadata,
    # so without this field the original timestamp would be lost. Surfaced in
    # the alert GUI tooltip so analysts can tell at a glance how stale a
    # cached result is. None on live-run attribution deltas.
    cached_at: Optional[str] = None

    @property
    def has_removals(self) -> bool:
        if self.target_observable_diff.has_removals:
            return True
        # Root-level removals count too: cache replay only applies root
        # additions (_apply_root_diff), so a delta that removed a root tag
        # or detection cannot be faithfully replayed.
        if self.root_diff.removed_tags or self.root_diff.removed_detections:
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

    def out_of_scope_relationship_targets(self) -> list[dict]:
        """Relationships added by this delta whose target lies outside the
        delta's own scope.

        The cacheability contract requires a module's relationships to
        stay within its own output: the analyzed observable itself, or an
        observable this same delta created. A relationship to any *other*
        tree node depends on surrounding tree context, which a cached
        replay onto a different root cannot guarantee to reproduce —
        ``put_cached_delta`` refuses such deltas. Returns the offending
        relationship dicts (empty list = in scope / no relationships).
        """
        allowed = {self.observable_uuid} | {spec.uuid for spec in self.new_observables}
        return [
            rel for rel in self.target_observable_diff.added_relationships
            if rel.get("target") not in allowed
        ]

    def with_cache_hit_metadata(
        self, executed_at: datetime, execution_time_ms: int,
        root_uuid: str, observable_uuid: str,
    ) -> "ModuleExecutionDelta":
        """Return a copy of this delta marked as a cache replay.

        Preserves all mutation fields (so root.json shows the same
        attribution as the original live run) but rewrites both
        ``root_uuid`` and ``observable_uuid`` to the *current* alert /
        observable being analyzed. The cached delta carries the source
        alert's identifiers — both UUIDs are per-alert-instance, so
        leaving them in place would (a) misattribute the replay to the
        wrong alert in root.json audits, and (b) break the
        (module_path, observable_uuid) lookup used by the alert GUI to
        render the "cached" badge against the current observable.

        ``observable_type`` and ``observable_value`` are *not* rewritten
        — by construction the cache key matches on those, so they're
        identical between source and current observable.
        """
        return replace(
            self,
            created_at=executed_at.isoformat(),
            cached_at=self.created_at,
            execution_time_ms=execution_time_ms,
            root_uuid=root_uuid,
            observable_uuid=observable_uuid,
            from_cache_hit=True,
        )

    def without_analysis_details(self) -> "ModuleExecutionDelta":
        """Return a copy of this delta whose analysis dict omits ``details``.

        Used when recording a delta into ``root._module_executions``: the
        analysis tree already persists each analysis's ``details`` once, so
        keeping a second copy inside the attribution log would double the
        details bytes in root.json (measured at 14-39% of data.json on
        real alerts). The cache-write path keeps using the original delta,
        which retains ``details`` for replay.

        Returns ``self`` when there is nothing to strip. Never mutates the
        original — the copy is shallow except for the analysis dict itself.
        """
        if self.analysis is None or "details" not in self.analysis:
            return self
        return replace(
            self,
            analysis={k: v for k, v in self.analysis.items() if k != "details"},
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
        if self.root_uuid:
            result["root_uuid"] = self.root_uuid
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
        if self.cached_at is not None:
            result["cached_at"] = self.cached_at
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
            root_uuid=data.get("root_uuid", ""),
            analysis=data.get("analysis"),
            target_observable_diff=target_diff,
            new_observables=new_obs,
            root_diff=root_diff,
            cache_key=data.get("cache_key"),
            wide_diff=data.get("wide_diff", False),
            other_observable_diffs=other_diffs,
            analysis_children_diffs=analysis_children,
            from_cache_hit=data.get("from_cache_hit", False),
            cached_at=data.get("cached_at"),
        )


def _dedupe(items: list, key=None) -> list:
    """Order-preserving dedupe; ``key`` extracts the identity when items
    aren't hashable (detection/relationship dicts)."""
    seen = set()
    result = []
    for item in items:
        k = key(item) if key else item
        if k not in seen:
            seen.add(k)
            result.append(item)
    return result


def _detection_dict_identity(det: dict) -> tuple:
    # Mirrors snapshot._detection_identity, but over the serialized form.
    return (det.get("description"), str(det.get("details")))


def _relationship_dict_identity(rel: dict) -> tuple:
    return (rel.get("type"), rel.get("target"))


def _merge_scalar(diffs: list[ObservableDiff], field_name: str) -> Optional[tuple]:
    """Compose (before, after) transitions across cycles: earliest
    'before', latest 'after'."""
    transitions = [
        getattr(d, field_name) for d in diffs
        if getattr(d, field_name) is not None
    ]
    if not transitions:
        return None
    return (transitions[0][0], transitions[-1][1])


def _merge_observable_diffs(diffs: list[ObservableDiff]) -> ObservableDiff:
    def added_and_removed(added_field: str, removed_field: str, key=None):
        return (
            _dedupe([x for d in diffs for x in getattr(d, added_field)], key=key),
            _dedupe([x for d in diffs for x in getattr(d, removed_field)], key=key),
        )

    added_tags, removed_tags = added_and_removed("added_tags", "removed_tags")
    added_detections, removed_detections = added_and_removed(
        "added_detections", "removed_detections", key=_detection_dict_identity)
    added_directives, removed_directives = added_and_removed(
        "added_directives", "removed_directives")
    added_relationships, removed_relationships = added_and_removed(
        "added_relationships", "removed_relationships", key=_relationship_dict_identity)
    added_excluded, removed_excluded = added_and_removed(
        "added_excluded_analysis", "removed_excluded_analysis")
    added_limited, removed_limited = added_and_removed(
        "added_limited_analysis", "removed_limited_analysis")

    return ObservableDiff(
        added_tags=added_tags,
        removed_tags=removed_tags,
        added_detections=added_detections,
        removed_detections=removed_detections,
        added_directives=added_directives,
        removed_directives=removed_directives,
        added_relationships=added_relationships,
        removed_relationships=removed_relationships,
        added_excluded_analysis=added_excluded,
        removed_excluded_analysis=removed_excluded,
        added_limited_analysis=added_limited,
        removed_limited_analysis=removed_limited,
        grouping_target=_merge_scalar(diffs, "grouping_target"),
        redirection=_merge_scalar(diffs, "redirection"),
        ignored=_merge_scalar(diffs, "ignored"),
    )


def merge_module_execution_deltas(
    priors: list[ModuleExecutionDelta],
    final: ModuleExecutionDelta,
) -> ModuleExecutionDelta:
    """Merge prior delayed-cycle deltas into the final cycle's delta.

    A delayed-analysis module records one delta per ``analyze()`` cycle.
    Mid-delay deltas are refused at cache-write time, so the cached
    (final) delta must absorb the earlier cycles' tree mutations — tags,
    new observables, detections added *before* the module delayed would
    otherwise be missing from the replay.

    Returns a NEW delta; inputs are not mutated. Keeps the final delta's
    identity fields and analysis dict (the analysis object accumulates
    across cycles in memory and round-trips through root.json, so the
    final whole-capture is complete). Removals are merged too so
    ``has_removals`` on the result reflects every cycle — a cycle-1
    removal correctly refuses the whole cache write.

    Only narrow-diff deltas are mergeable; wide-diff modules are
    uncacheable by config so this should never see one.
    """
    if not priors:
        return final

    ordered = list(priors) + [final]
    for d in ordered:
        if d.wide_diff or d.other_observable_diffs or d.analysis_children_diffs:
            raise ValueError(
                "cannot merge wide-diff deltas (module_path=%s)" % d.module_path
            )

    new_observables = _dedupe(
        [spec for d in ordered for spec in d.new_observables],
        # First occurrence wins, preserving the uuid the earliest cycle's
        # relationships reference (the same-delta scope check relies on it).
        key=lambda spec: (spec.type, spec.value, spec.time),
    )

    return replace(
        final,
        target_observable_diff=_merge_observable_diffs(
            [d.target_observable_diff for d in ordered]
        ),
        new_observables=new_observables,
        root_diff=RootDiff(
            added_tags=_dedupe([t for d in ordered for t in d.root_diff.added_tags]),
            removed_tags=_dedupe([t for d in ordered for t in d.root_diff.removed_tags]),
            added_detections=_dedupe(
                [x for d in ordered for x in d.root_diff.added_detections],
                key=_detection_dict_identity,
            ),
            removed_detections=_dedupe(
                [x for d in ordered for x in d.root_diff.removed_detections],
                key=_detection_dict_identity,
            ),
        ),
        execution_time_ms=sum(d.execution_time_ms for d in ordered),
    )
