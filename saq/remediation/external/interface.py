from typing import Protocol

from saq.remediation.external.types import CheckWorkItem


class CheckListener(Protocol):
    """Receives check work items from the collector — exactly one listener per
    registered probe name. Mirrors :class:`FileCollectionListener`."""

    def handle_external_check_request(self, work_item: CheckWorkItem):
        ...
