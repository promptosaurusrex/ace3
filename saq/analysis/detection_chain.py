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
    steps_reversed: list[ChainStep] = []
    current: Optional[Observable] = observable
    visited: set[str] = set()

    while current is not None and current.uuid not in visited:
        visited.add(current.uuid)
        # RootAnalysis reports itself as a parent of every descendant observable (its
        # has_observable() walks the whole tree), so prefer a non-root parent when one exists.
        non_root_parents = [p for p in current.parents if not isinstance(p, RootAnalysis)]
        if not non_root_parents:
            steps_reversed.append(ChainStep(observable=current, extracted_by=None))
            break

        parent_analysis = non_root_parents[0]
        if parent_analysis.observable is None:
            steps_reversed.append(ChainStep(observable=current, extracted_by=None))
            break

        steps_reversed.append(ChainStep(observable=current, extracted_by=parent_analysis))
        current = parent_analysis.observable

    return list(reversed(steps_reversed))


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
