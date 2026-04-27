from collections import deque
from dataclasses import dataclass, field
from typing import Optional, Union

from saq.analysis.analysis import Analysis
from saq.analysis.detection_point import DetectionPoint
from saq.analysis.observable import Observable
from saq.analysis.root import RootAnalysis


@dataclass
class ChainStep:
    observable: Observable
    extracted_by: Optional[Analysis]


@dataclass
class DetectionChain:
    detection: DetectionPoint
    owner: Union[Observable, Analysis]
    steps: list[ChainStep] = field(default_factory=list)


def _walk_to_root(observable: Observable) -> list[ChainStep]:
    # BFS in the parent DAG to find the shortest extraction lineage from `observable`
    # back to a true root observable (one with no non-root, non-self-loop parents).
    #
    # Why BFS: an observable can have many legitimate parent analyses (e.g. an FQDN
    # parsed out of dozens of redirected URLs). Picking parents[0] is non-deterministic
    # across loads, and walking arbitrary parents can take a long detour. BFS naturally
    # picks the shortest extraction lineage and we sort siblings for reproducibility.
    #
    # Why skip self-loops: some analyses (notably PhishkitAnalysis) include their own
    # input observable in their output set, so observable.parents lists an analysis
    # whose .observable is the same observable. Walking through it terminates the chain
    # immediately on a phantom one-step root.
    visited: set[str] = {observable.uuid}
    queue: deque[tuple[Observable, list[ChainStep]]] = deque([(observable, [])])

    while queue:
        current, path = queue.popleft()
        candidate_parents = [
            p for p in current.parents
            if not isinstance(p, RootAnalysis)
            and p.observable is not None
            and p.observable.uuid != current.uuid
        ]
        if not candidate_parents:
            return list(reversed(path + [ChainStep(observable=current, extracted_by=None)]))

        candidate_parents.sort(key=lambda a: (a.observable.uuid, a.module_path or ''))
        for parent_analysis in candidate_parents:
            parent_obs_uuid = parent_analysis.observable.uuid
            if parent_obs_uuid in visited:
                continue
            visited.add(parent_obs_uuid)
            queue.append((
                parent_analysis.observable,
                path + [ChainStep(observable=current, extracted_by=parent_analysis)],
            ))

    return [ChainStep(observable=observable, extracted_by=None)]


def build_detection_chains(root_analysis: RootAnalysis) -> list[DetectionChain]:
    chains: list[DetectionChain] = []

    for node in list(root_analysis.all_analysis) + list(root_analysis.all_observables):
        for detection in node.detections:
            if isinstance(node, RootAnalysis):
                continue
            if isinstance(node, Observable):
                carrier = node
            else:
                carrier = node.observable
                if carrier is None:
                    continue

            steps = _walk_to_root(carrier)
            chains.append(DetectionChain(detection=detection, owner=node, steps=steps))

    return chains


def module_display_name(analysis: Analysis) -> str:
    module_path = analysis.module_path or ''
    parts = module_path.split(':')
    if len(parts) >= 2 and parts[1]:
        return parts[1]
    if parts[0]:
        return parts[0]
    return type(analysis).__name__


@dataclass
class MergedTreeNode:
    observable: Observable
    extracted_by: Optional[Analysis]
    detections: list[DetectionPoint] = field(default_factory=list)
    children: dict[str, "MergedTreeNode"] = field(default_factory=dict)


def build_merged_detection_tree(chains: list[DetectionChain]) -> list[MergedTreeNode]:
    roots: dict[str, MergedTreeNode] = {}

    for chain in chains:
        if not chain.steps:
            continue
        container = roots
        node: Optional[MergedTreeNode] = None
        for step in chain.steps:
            uuid = step.observable.uuid
            if uuid not in container:
                container[uuid] = MergedTreeNode(
                    observable=step.observable,
                    extracted_by=step.extracted_by,
                )
            node = container[uuid]
            container = node.children

        if node is not None:
            if chain.detection not in node.detections:
                node.detections.append(chain.detection)

    return list(roots.values())


def observable_display_value(observable: Observable, max_len: int = 60) -> str:
    from saq.constants import F_FILE
    if observable.type == F_FILE:
        name = getattr(observable, 'file_name', None) or str(observable.value)
        if len(name) > max_len:
            return name[:max_len] + '...'
        return name
    value = str(observable.value)
    if len(value) > max_len:
        return value[:max_len] + '...'
    return value
