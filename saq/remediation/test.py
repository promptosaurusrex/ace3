from saq.remediation.remediator import Remediator
from saq.remediation.target import ObservableRemediationInterface, register_observable_remediation_interface, RemediationTarget
from saq.observables.base import Observable
from saq.constants import F_TEST

from saq.remediation.types import RemediationWorkItem, RemediatorResult, RemediatorStatus

class TestObservableRemediationInterface(ObservableRemediationInterface):
    __test__ = False # tell pytest this is not a test class

    def get_remediation_targets(self, observable: Observable) -> list[RemediationTarget]:
        return [RemediationTarget("test", observable.type, observable.value)]

register_observable_remediation_interface(F_TEST, TestObservableRemediationInterface())

class TestRemediator(Remediator):
    """Simple test Remediator that returns a RemediatorResult with a value equal to the target value."""

    __test__ = False # tell pytest this is not a test class

    def execute(self, target: RemediationWorkItem) -> RemediatorResult:
        try:
            status = RemediatorStatus(target.key)
        except ValueError:
            return RemediatorResult(
                status=RemediatorStatus.ERROR,
                message=f"unexpected target key value (should be a RemediatorStatus value): {target.key}",
            )

        return RemediatorResult(
            status=status,
            message="test remediation system",
            restore_key=None
        )

    def remove(self, target: RemediationWorkItem) -> RemediatorResult:
        return self.execute(target)

    def restore(self, target: RemediationWorkItem) -> RemediatorResult:
        return self.execute(target)