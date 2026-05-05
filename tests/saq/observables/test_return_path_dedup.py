"""Verifies that introducing F_EMAIL_RETURN_PATH as a distinct observable type
prevents the long-standing collision between Mail From and Mail Return Path
observables when both headers carry the same address."""

import pytest

from saq.analysis import RootAnalysis
from saq.constants import F_EMAIL_ADDRESS, F_EMAIL_RETURN_PATH


@pytest.mark.unit
def test_from_and_return_path_with_same_value_are_distinct_observables():
    root = RootAnalysis()

    mail_from = root.add_observable_by_spec(F_EMAIL_ADDRESS, "alice@example.com")
    mail_from.display_type = "Mail From"

    return_path = root.add_observable_by_spec(F_EMAIL_RETURN_PATH, "alice@example.com")
    return_path.display_type = "Mail Return Path"

    assert mail_from is not None
    assert return_path is not None
    assert mail_from is not return_path
    assert mail_from.uuid != return_path.uuid
    assert mail_from.value == return_path.value
    assert mail_from.display_type == "Mail From (email_address)"
    assert return_path.display_type == "Mail Return Path (email_return_path)"
