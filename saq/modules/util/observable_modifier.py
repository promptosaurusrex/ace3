import logging
import os
import re
from dataclasses import dataclass, field
from typing import Generator, Optional, Type, override

from saq.analysis.observable import Observable
from saq.analysis.root import RootAnalysis
import yaml
from pydantic import Field

from saq.analysis.analysis import Analysis
from saq.constants import DIRECTIVE_EXCLUDE_ALL, DIRECTIVE_YARA_META_PREFIX, F_SIGNATURE_ID, AnalysisExecutionResult
from saq.environment import get_base_dir
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.observables.type_hierarchy import get_type_hierarchy


class ObservableModifierConfig(AnalysisModuleConfig):
    priority: int = Field(default=1, description="Priority for the observable modifier module (lower = runs earlier).")
    rules_config_path: str = Field(
        default="etc/observable_modifier_rules.yaml",
        description="Path to YAML rules config file, relative to SAQ_HOME",
    )


class ObservableModifierAnalysis(Analysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            "matched_rules": [],
        }

    @override
    @property
    def display_name(self) -> str:
        return "Observable Modifier Analysis"

    def generate_summary(self):
        matched = self.details.get("matched_rules", [])
        if not matched:
            return None
        names = [r["name"] for r in matched]
        return f"Applied {len(matched)} rule(s): {', '.join(names)}"


def get_nested_value(data: dict, dot_path: str):
    """Traverse nested dicts using dot notation."""
    keys = dot_path.split(".")
    current = data
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
        else:
            return None
    return current


@dataclass
class TreeCondition:
    analysis_type: str
    scope: str = "ancestors"  # "ancestors", "descendants", "global", "self", "parent", or "siblings"
    details_match: dict[str, re.Pattern] = field(default_factory=dict)
    observable_match: dict[str, re.Pattern] = field(default_factory=dict)
    negate: bool = False
    # if set, require exactly this many matching analyses. None means "at least one"
    # (the historical default). Used to scope rules to top-level contexts — e.g.
    # match_count: 1 on an ancestors scope identifies an observable whose chain
    # contains exactly one instance of the analysis type.
    match_count: Optional[int] = None

    def evaluate(self, observable: Observable, root: RootAnalysis) -> bool:
        result = self._evaluate_inner(observable, root)
        return not result if self.negate else result

    def _evaluate_inner(self, observable: Observable, root: RootAnalysis) -> bool:
        if self.scope == "ancestors":
            analyses = _get_ancestor_analyses(observable)
        elif self.scope == "descendants":
            analyses = _get_descendant_analyses(observable)
        elif self.scope == "parent":
            analyses = observable.parents
        elif self.scope == "siblings":
            analyses = _get_sibling_analyses(observable)
        elif self.scope == "self":
            analyses = observable.all_analysis
        else:  # global
            analyses = (a for a in root.all_analysis if a)

        matches = 0
        for analysis in analyses:
            if self.analysis_type and analysis.module_path != self.analysis_type:
                continue
            if self.details_match:
                analysis.load_details()
                if not self._check_details(analysis.details):
                    continue
            if self.observable_match:
                if not self._check_observable(analysis.observable):
                    continue
            matches += 1
            if self.match_count is None:
                return True
        if self.match_count is None:
            return False
        return matches == self.match_count

    def _check_observable(self, obs) -> bool:
        if obs is None:
            return False
        for attr, pattern in self.observable_match.items():
            value = getattr(obs, attr, None)
            if value is None:
                return False
            if not pattern.search(str(value)):
                return False
        return True

    def _check_details(self, details: dict) -> bool:
        if not details:
            return False
        for dot_path, pattern in self.details_match.items():
            value = get_nested_value(details, dot_path)
            if value is None:
                return False
            if not pattern.search(str(value)):
                return False
        return True


def _get_ancestor_analyses(observable: Observable) -> Generator[Analysis, None, None]:
    """Yield all Analysis objects that are ancestors of this observable."""
    visited = set()
    stack = list(observable.parents)
    while stack:
        analysis = stack.pop()
        if id(analysis) in visited:
            continue
        visited.add(id(analysis))
        yield analysis
        if analysis.observable:
            stack.extend(analysis.observable.parents)


def _get_sibling_analyses(observable: Observable) -> Generator[Analysis, None, None]:
    """Yield all analyses on the observable(s) that directly produced this observable.

    For each direct parent analysis P, yield every analysis on P.observable —
    that is, P itself plus its peers (other analyses on the same observable).
    Useful for matching a peer analysis without walking the whole ancestor
    chain — e.g., a URL extracted by URLExtractionAnalysis on a file should
    consult the FileTypeAnalysis on that same file to learn its mime type.
    """
    visited_obs = set()
    visited_analyses = set()
    for parent_analysis in observable.parents:
        parent_obs = parent_analysis.observable
        if parent_obs is None or id(parent_obs) in visited_obs:
            continue
        visited_obs.add(id(parent_obs))
        for a in parent_obs.all_analysis:
            if a is None or id(a) in visited_analyses:
                continue
            visited_analyses.add(id(a))
            yield a


def _get_descendant_analyses(observable: Observable) -> Generator[Analysis, None, None]:
    """Yield all Analysis objects that are descendants of this observable.

    A descendant analysis runs on an observable that was (transitively) produced
    by an analysis on this observable. Analyses directly on this observable
    (scope: "self") are NOT included — use scope "self" for those.
    """
    visited = set()
    stack = []
    for self_analysis in observable.all_analysis:
        for child in self_analysis.observables:
            stack.extend(child.all_analysis)
    while stack:
        analysis = stack.pop()
        if id(analysis) in visited:
            continue
        visited.add(id(analysis))
        yield analysis
        for child in analysis.observables:
            stack.extend(child.all_analysis)


@dataclass
class RuleConditions:
    alert_tags: list[str] = field(default_factory=list)
    alert_type: Optional[str] = None
    queue: Optional[str] = None
    observable_types: list[str] = field(default_factory=list)
    value_pattern: Optional[re.Pattern] = None
    file_name_pattern: Optional[re.Pattern] = None
    has_tags: list[str] = field(default_factory=list)
    has_directives: list[str] = field(default_factory=list)
    has_yara_meta_tags: list[str] = field(default_factory=list)
    display_type_pattern: Optional[re.Pattern] = None
    display_value_pattern: Optional[re.Pattern] = None
    tree_conditions: list[TreeCondition] = field(default_factory=list)

    def evaluate_early(self, observable: Observable, root: RootAnalysis) -> bool:
        """Check only immutable conditions known at analysis start.
        Returns False if the rule cannot match, True if it might."""
        if self.observable_types:
            hierarchy = get_type_hierarchy()
            if not any(hierarchy.is_subtype(observable.type, t) for t in self.observable_types):
                return False
        if self.alert_type is not None:
            if root.alert_type != self.alert_type:
                return False
        if self.queue is not None:
            if root.queue != self.queue:
                return False
        if self.value_pattern is not None:
            if not self.value_pattern.search(str(observable.value)):
                return False
        if self.file_name_pattern is not None:
            file_name = getattr(observable, "file_name", None)
            if file_name is None or not self.file_name_pattern.search(file_name):
                return False
        if self.display_type_pattern is not None:
            if not self.display_type_pattern.search(str(observable.display_type)):
                return False
        if self.display_value_pattern is not None:
            if not self.display_value_pattern.search(str(observable.display_value)):
                return False
        return True

    def evaluate(self, observable: Observable, root: RootAnalysis) -> bool:
        # Cheapest checks first for short-circuit efficiency

        # Observable type check (subtype-aware: a rule targeting "email_address"
        # also matches subtypes like "email_from", "email_return_path", etc.)
        if self.observable_types:
            hierarchy = get_type_hierarchy()
            if not any(hierarchy.is_subtype(observable.type, t) for t in self.observable_types):
                return False

        # Alert-level checks
        if self.alert_tags:
            for tag in self.alert_tags:
                if not root.has_tag(tag):
                    return False

        if self.alert_type is not None:
            if root.alert_type != self.alert_type:
                return False

        if self.queue is not None:
            if root.queue != self.queue:
                return False

        # Observable-level checks
        if self.has_tags:
            for tag in self.has_tags:
                if not observable.has_tag(tag):
                    return False

        if self.has_directives:
            for directive in self.has_directives:
                if not observable.has_directive(directive):
                    return False

        if self.has_yara_meta_tags:
            for tag in self.has_yara_meta_tags:
                if not observable.has_directive(f"{DIRECTIVE_YARA_META_PREFIX}{tag}"):
                    return False

        # Value pattern (regex)
        if self.value_pattern is not None:
            if not self.value_pattern.search(str(observable.value)):
                return False

        # File name pattern (regex, only applies to FileObservable)
        if self.file_name_pattern is not None:
            file_name = getattr(observable, "file_name", None)
            if file_name is None or not self.file_name_pattern.search(file_name):
                return False

        # Display type pattern (regex)
        if self.display_type_pattern is not None:
            if not self.display_type_pattern.search(str(observable.display_type)):
                return False

        # Display value pattern (regex)
        if self.display_value_pattern is not None:
            if not self.display_value_pattern.search(str(observable.display_value)):
                return False

        # Tree conditions (most expensive — disk I/O)
        for tc in self.tree_conditions:
            if not tc.evaluate(observable, root):
                return False

        return True


@dataclass
class RuleActions:
    add_directives: list[str] = field(default_factory=list)
    add_tags: list[str] = field(default_factory=list)
    add_detection_points: list[str] = field(default_factory=list)
    exclude_analysis: list[str] = field(default_factory=list)
    limit_analysis: list[str] = field(default_factory=list)
    reset_analysis: list[str] = field(default_factory=list)
    set_display_type: Optional[str] = None
    set_display_value: Optional[str] = None
    ignore: bool = False

    def apply(self, observable: Observable) -> dict:
        applied = {}
        # Clear any "no_analysis" sentinels FIRST so that the subsequent
        # add_directives below can trigger a re-dispatch (via
        # EVENT_DIRECTIVE_ADDED) and have the targeted modules actually run
        # instead of being skipped by accepts() seeing the False marker.
        if self.reset_analysis:
            reset_done = []
            for module_path in self.reset_analysis:
                current = observable._analysis.get(module_path)
                if current is False:
                    del observable._analysis[module_path]
                    reset_done.append(module_path)
            if reset_done:
                applied["reset_analysis"] = reset_done

        if self.add_directives:
            for d in self.add_directives:
                observable.add_directive(d)
            applied["add_directives"] = self.add_directives

        if self.add_tags:
            for t in self.add_tags:
                observable.add_tag(t)
            applied["add_tags"] = self.add_tags

        if self.add_detection_points:
            for desc in self.add_detection_points:
                observable.add_detection_point(desc)
            applied["add_detection_points"] = self.add_detection_points

        if self.exclude_analysis:
            for module_name in self.exclude_analysis:
                observable._excluded_analysis.append(module_name)
            applied["exclude_analysis"] = self.exclude_analysis

        if self.limit_analysis:
            for module_name in self.limit_analysis:
                observable._limited_analysis.append(module_name)
            applied["limit_analysis"] = self.limit_analysis

        if self.set_display_type is not None:
            observable.display_type = self.set_display_type
            applied["set_display_type"] = self.set_display_type

        if self.set_display_value is not None:
            observable.display_value = self.set_display_value
            applied["set_display_value"] = self.set_display_value

        if self.ignore:
            applied["ignore"] = True

        return applied


@dataclass
class Rule:
    name: str
    uuid: str
    description: str
    enabled: bool
    conditions: RuleConditions
    actions: RuleActions
    phase: str = "post"  # "pre" or "post"


class ObservableModifierAnalyzer(AnalysisModule):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._initialized = False
        self._rules: list[Rule] = []

    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return ObservableModifierConfig

    @property
    def generated_analysis_type(self):
        return ObservableModifierAnalysis

    def _load_config(self):
        """Load rules from YAML config file."""
        self._rules = []

        yaml_path = os.path.join(
            get_base_dir(),
            self.config.rules_config_path,
        )

        try:
            with open(yaml_path, "r") as f:
                data = yaml.safe_load(f) or {}
        except Exception as e:
            logging.warning(f"failed to load observable modifier rules YAML {yaml_path}: {e}")
            return

        for rule_data in data.get("rules", []) or []:
            try:
                rule = self._parse_rule(rule_data)
                if rule:
                    self._rules.append(rule)
            except Exception as e:
                logging.warning(f"failed to parse observable modifier rule: {e}")

        logging.debug(f"loaded {len(self._rules)} observable modifier rules from {yaml_path}")

    def _parse_rule(self, rule_data: dict) -> Optional[Rule]:
        name = rule_data.get("name", "unnamed")
        rule_uuid = rule_data.get("uuid")
        if not rule_uuid:
            logging.error(
                f"observable modifier rule '{name}' is missing required 'uuid' field -- "
                f"refusing to load this rule"
            )
            return None
        description = rule_data.get("description", "")
        enabled = rule_data.get("enabled", True)
        phase = rule_data.get("phase", "post")
        if phase not in ("pre", "post"):
            logging.warning(f"invalid phase '{phase}' in rule '{name}', defaulting to 'post'")
            phase = "post"

        conditions_data = rule_data.get("conditions", {}) or {}
        actions_data = rule_data.get("actions", {}) or {}

        # Parse conditions
        value_pattern = None
        raw_pattern = conditions_data.get("value_pattern")
        if raw_pattern:
            try:
                value_pattern = re.compile(raw_pattern)
            except re.error as e:
                logging.warning(f"invalid value_pattern regex '{raw_pattern}' in rule '{name}': {e}")
                return None

        file_name_pattern = None
        raw_fn_pattern = conditions_data.get("file_name_pattern")
        if raw_fn_pattern:
            try:
                file_name_pattern = re.compile(raw_fn_pattern)
            except re.error as e:
                logging.warning(f"invalid file_name_pattern regex '{raw_fn_pattern}' in rule '{name}': {e}")
                return None

        display_type_pattern = None
        raw_dt_pattern = conditions_data.get("display_type_pattern")
        if raw_dt_pattern:
            try:
                display_type_pattern = re.compile(raw_dt_pattern)
            except re.error as e:
                logging.warning(f"invalid display_type_pattern regex '{raw_dt_pattern}' in rule '{name}': {e}")
                return None

        display_value_pattern = None
        raw_dv_pattern = conditions_data.get("display_value_pattern")
        if raw_dv_pattern:
            try:
                display_value_pattern = re.compile(raw_dv_pattern)
            except re.error as e:
                logging.warning(f"invalid display_value_pattern regex '{raw_dv_pattern}' in rule '{name}': {e}")
                return None

        tree_conditions = []
        for tc_data in conditions_data.get("tree_conditions", []) or []:
            tc = self._parse_tree_condition(tc_data, name)
            if tc is None:
                return None
            tree_conditions.append(tc)

        conditions = RuleConditions(
            alert_tags=conditions_data.get("alert_tags", []) or [],
            alert_type=conditions_data.get("alert_type"),
            queue=conditions_data.get("queue"),
            observable_types=conditions_data.get("observable_types", []) or [],
            value_pattern=value_pattern,
            file_name_pattern=file_name_pattern,
            display_type_pattern=display_type_pattern,
            display_value_pattern=display_value_pattern,
            has_tags=conditions_data.get("has_tags", []) or [],
            has_directives=conditions_data.get("has_directives", []) or [],
            has_yara_meta_tags=conditions_data.get("has_yara_meta_tags", []) or [],
            tree_conditions=tree_conditions,
        )

        actions = RuleActions(
            add_directives=actions_data.get("add_directives", []) or [],
            add_tags=actions_data.get("add_tags", []) or [],
            add_detection_points=actions_data.get("add_detection_points", []) or [],
            exclude_analysis=actions_data.get("exclude_analysis", []) or [],
            limit_analysis=actions_data.get("limit_analysis", []) or [],
            reset_analysis=actions_data.get("reset_analysis", []) or [],
            set_display_type=actions_data.get("set_display_type"),
            set_display_value=actions_data.get("set_display_value"),
            ignore=bool(actions_data.get("ignore", False)),
        )

        return Rule(
            name=name,
            uuid=rule_uuid,
            description=description,
            enabled=enabled,
            conditions=conditions,
            actions=actions,
            phase=phase,
        )

    def _parse_tree_condition(self, tc_data: dict, rule_name: str) -> Optional[TreeCondition]:
        analysis_type = tc_data.get("analysis_type", "")
        scope = tc_data.get("scope", "ancestors")
        if scope not in ("ancestors", "descendants", "global", "self", "parent", "siblings"):
            logging.warning(f"invalid scope '{scope}' in tree_condition for rule '{rule_name}', defaulting to 'ancestors'")
            scope = "ancestors"
        details_match_raw = tc_data.get("details_match", {}) or {}

        compiled_details_match = {}
        for dot_path, pattern_str in details_match_raw.items():
            try:
                compiled_details_match[dot_path] = re.compile(str(pattern_str))
            except re.error as e:
                logging.warning(
                    f"invalid details_match regex '{pattern_str}' for path '{dot_path}' in rule '{rule_name}': {e}"
                )
                return None

        observable_match_raw = tc_data.get("observable_match", {}) or {}
        compiled_observable_match = {}
        for attr, pattern_str in observable_match_raw.items():
            try:
                compiled_observable_match[attr] = re.compile(str(pattern_str))
            except re.error as e:
                logging.warning(
                    f"invalid observable_match regex '{pattern_str}' for attr '{attr}' in rule '{rule_name}': {e}"
                )
                return None

        negate = bool(tc_data.get("negate", False))

        match_count = tc_data.get("match_count")
        if match_count is not None:
            try:
                match_count = int(match_count)
            except (TypeError, ValueError):
                logging.warning(
                    f"invalid match_count '{match_count}' in tree_condition for rule '{rule_name}': must be int"
                )
                return None
            if match_count < 0:
                logging.warning(
                    f"invalid match_count {match_count} in tree_condition for rule '{rule_name}': must be >= 0"
                )
                return None

        return TreeCondition(
            analysis_type=analysis_type,
            scope=scope,
            details_match=compiled_details_match,
            observable_match=compiled_observable_match,
            negate=negate,
            match_count=match_count,
        )

    def _ensure_initialized(self):
        if not self._initialized:
            yaml_path = os.path.join(
                get_base_dir(),
                self.config.rules_config_path,
            )
            self.watch_file(yaml_path, self._load_config)
            self._initialized = True

    def _any_rule_could_match(self, observable: Observable, root: RootAnalysis) -> bool:
        """Check if any enabled rule's immutable conditions could match."""
        return any(
            rule.enabled and rule.conditions.evaluate_early(observable, root)
            for rule in self._rules
        )

    def execute_analysis(self, observable: Observable) -> AnalysisExecutionResult:
        self._ensure_initialized()

        # Check immutable conditions early. If no rule can possibly match,
        # skip waiting for the full analysis tree.
        root = self.get_root()
        if not self._any_rule_could_match(observable, root):
            return AnalysisExecutionResult.COMPLETED

        matched_rules = []

        for rule in self._rules:
            if not rule.enabled:
                continue
            if rule.phase != "pre":
                continue

            if rule.conditions.evaluate(observable, root):
                applied = rule.actions.apply(observable)
                matched_rules.append({
                    "name": rule.name,
                    "uuid": rule.uuid,
                    "actions_applied": applied,
                })
                logging.info(f"observable modifier pre-phase rule '{rule.name}' matched {observable}")

                if applied.get("ignore"):
                    # In the pre phase, also install DIRECTIVE_EXCLUDE_ALL so the
                    # engine skips all remaining analysis on this observable
                    # instead of analyzing it and discarding the work at the end.
                    # add_directive is idempotent and fires EVENT_DIRECTIVE_ADDED,
                    # which re-queues the observable so _process_observable_exclusions
                    # picks up the directive. Not done in the post phase: by then the
                    # observable is already analyzed and the directive would only
                    # cause needless re-queue churn.
                    observable.add_directive(DIRECTIVE_EXCLUDE_ALL)
                    self._apply_ignore(rule, observable, root)

        if matched_rules:
            # Persist pre-phase matches in the analysis itself rather than
            # in-memory module state, so the post-phase pass survives a
            # worker hand-off (root saved to disk and resumed by a different
            # worker process whose module instance has no in-memory carryover).
            #
            # completed=False is critical: Analysis objects are born completed,
            # and AnalysisModule.accepts() refuses to re-run a module whose
            # analysis is already completed. Leaving it True here would block
            # execute_final_analysis from ever running for this observable, so
            # no post-phase rule would be evaluated.
            self._persist_matches(observable, matched_rules, emitted_uuids=set(), completed=False)

        # Return INCOMPLETE so execute_final_analysis runs later
        # for post-phase rules.
        return AnalysisExecutionResult.INCOMPLETE

    def execute_final_analysis(self, observable: Observable) -> AnalysisExecutionResult:
        self._ensure_initialized()

        root = self.get_root()

        # Fast path: re-check immutable conditions since the engine always
        # calls execute_final_analysis regardless of execute_analysis result.
        if not self._any_rule_could_match(observable, root):
            return AnalysisExecutionResult.COMPLETED

        # Recover any pre-phase matches from the analysis that pre-phase
        # persisted to the observable. This survives a worker hand-off that
        # in-memory state on the analyzer instance would not.
        existing = observable.get_and_load_analysis(ObservableModifierAnalysis)
        if existing:
            matched_rules = list(existing.details.get("matched_rules", []))
            emitted_uuids: set[str] = {
                m["uuid"] for m in matched_rules if m.get("uuid")
            }
        else:
            matched_rules = []
            emitted_uuids = set()

        ignore_rules = []

        for rule in self._rules:
            if not rule.enabled:
                continue
            if rule.phase != "post":
                continue

            if rule.conditions.evaluate(observable, root):
                applied = rule.actions.apply(observable)
                matched_rules.append({
                    "name": rule.name,
                    "uuid": rule.uuid,
                    "actions_applied": applied,
                })
                logging.info(f"observable modifier rule '{rule.name}' matched {observable}")

                if applied.get("ignore"):
                    ignore_rules.append(rule)

        # Handle ignore action: surgically remove observable from matching parent analyses
        for rule in ignore_rules:
            self._apply_ignore(rule, observable, root)

        if matched_rules:
            # completed=True: the post phase is the module's final pass for
            # this observable, so the analysis is genuinely done.
            self._persist_matches(observable, matched_rules, emitted_uuids, completed=True)

        return AnalysisExecutionResult.COMPLETED

    def continue_analysis(self, observable: Observable, analysis: Analysis) -> AnalysisExecutionResult:
        logging.warning("observable modifier continue_analysis called, but this module never calls delay_analysis()")
        return AnalysisExecutionResult.INCOMPLETE

    def _apply_ignore(self, rule: "Rule", observable: Observable, root: RootAnalysis) -> None:
        """Apply a matched rule's ``ignore`` action: surgically remove the
        observable from matching parent analyses and/or mark it ignored.

        Callable from both phases. Idempotent: the pre phase's execute_analysis
        is re-invoked as the tree grows, so the parent-removal tolerates an
        already-removed observable and ``observable.ignored = True`` is a plain
        (idempotent) assignment.
        """
        parent_scoped_conditions = [tc for tc in rule.conditions.tree_conditions if tc.scope == "parent"]
        if parent_scoped_conditions:
            # Find all non-root analyses that have this observable as a child.
            # We check _observables directly to avoid RootAnalysis.has_observable()
            # which searches the global registry rather than its own children.
            all_parent_analyses = [
                a for a in root.all_analysis
                if observable in a._observables
            ]
            for tc in parent_scoped_conditions:
                for parent_analysis in list(all_parent_analyses):
                    if tc.analysis_type and parent_analysis.module_path == tc.analysis_type:
                        if observable in parent_analysis._observables:
                            parent_analysis._observables.remove(observable)
                        all_parent_analyses.remove(parent_analysis)
                        logging.info(
                            f"observable modifier rule '{rule.name}' removed "
                            f"{observable} from {parent_analysis}"
                        )
            # If no non-root parents remain, mark as globally ignored for DB indexing
            if not all_parent_analyses:
                observable.ignored = True
                logging.info(f"observable {observable} has no remaining parents, marking as ignored")
        else:
            # No parent-scoped tree conditions -- global ignore
            observable.ignored = True
            logging.info(f"observable modifier rule '{rule.name}' globally ignored {observable}")

    def _persist_matches(
        self,
        observable: Observable,
        matched_rules: list[dict],
        emitted_uuids: set[str],
        completed: bool,
    ) -> None:
        """Write matched_rules into the observable's ObservableModifierAnalysis
        and emit a signature_id observable for each not-yet-emitted rule uuid.

        Idempotent: create_analysis returns an existing analysis if one was
        already created (e.g. by pre-phase), and add_observable_by_spec dedups
        signature_id observables by (type, value).

        ``emitted_uuids`` is the set of rule uuids that have already been
        emitted as signature_id observables; it is mutated in place to include
        any newly emitted uuids.

        ``completed`` sets the analysis's completed flag. Pre-phase passes
        False so AnalysisModule.accepts() still lets execute_final_analysis run
        the post-phase rules; post-phase passes True.
        """
        analysis = self.create_analysis(observable)
        analysis.completed = completed
        analysis.details["matched_rules"] = matched_rules
        analysis.summary = analysis.generate_summary()

        for match in matched_rules:
            rule_uuid = match.get("uuid")
            if rule_uuid and rule_uuid not in emitted_uuids:
                analysis.add_observable_by_spec(F_SIGNATURE_ID, rule_uuid)
                emitted_uuids.add(rule_uuid)
