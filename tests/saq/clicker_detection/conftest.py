import pytest

from saq.clicker_detection.timeline import REGISTERED_CLICKER_PROVIDERS


@pytest.fixture(autouse=True)
def _restore_clicker_providers():
    # snapshot/restore the global provider registry so a test that registers a
    # provider can't leak it into later tests
    saved = list(REGISTERED_CLICKER_PROVIDERS)
    yield
    REGISTERED_CLICKER_PROVIDERS[:] = saved
