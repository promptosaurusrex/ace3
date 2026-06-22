from saq.remediation.remediator import Remediator
from saq.remediation.types import RemediationWorkItem, RemediatorResult, RemediatorStatus

class TestRemediator(Remediator):
    __test__ = False # tell pytest this is not a test class

    def remove(self, target: RemediationWorkItem) -> RemediatorResult:
        return RemediatorResult(status=RemediatorStatus.SUCCESS, message="TestRemediator.remove", restore_key="restore_key")

    def restore(self, target: RemediationWorkItem) -> RemediatorResult:
        return RemediatorResult(status=RemediatorStatus.SUCCESS, message="TestRemediator.restore")

