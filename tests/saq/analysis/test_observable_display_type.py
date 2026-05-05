"""Tests for Observable.display_type fallback to the configured default."""

import pytest

from saq.analysis import RootAnalysis
from saq.constants import F_EMAIL_ADDRESS, F_EMAIL_RETURN_PATH
from saq.observables.type_hierarchy import get_type_hierarchy


@pytest.fixture
def isolated_default_display_types():
    """Snapshot and restore the registry's default_display_type map for the test."""
    h = get_type_hierarchy()
    snapshot = dict(h._default_display_types)
    yield h
    h._default_display_types = snapshot


@pytest.mark.unit
def test_display_type_falls_back_to_configured_default(isolated_default_display_types):
    h = isolated_default_display_types
    h._default_display_types[F_EMAIL_RETURN_PATH] = "Mail Return Path"

    root = RootAnalysis()
    obs = root.add_observable_by_spec(F_EMAIL_RETURN_PATH, "alice@example.com")

    # No explicit setter — should use the configured default.
    assert obs._display_type is None
    assert obs.display_type == "Mail Return Path (email_return_path)"


@pytest.mark.unit
def test_explicit_display_type_wins_over_configured_default(isolated_default_display_types):
    h = isolated_default_display_types
    h._default_display_types[F_EMAIL_RETURN_PATH] = "Mail Return Path"

    root = RootAnalysis()
    obs = root.add_observable_by_spec(F_EMAIL_RETURN_PATH, "alice@example.com")
    obs.display_type = "Some Other Label"

    assert obs.display_type == "Some Other Label (email_return_path)"


@pytest.mark.unit
def test_display_type_returns_bare_type_when_nothing_configured(isolated_default_display_types):
    isolated_default_display_types._default_display_types.pop(F_EMAIL_ADDRESS, None)

    root = RootAnalysis()
    obs = root.add_observable_by_spec(F_EMAIL_ADDRESS, "alice@example.com")

    assert obs._display_type is None
    assert obs.display_type == F_EMAIL_ADDRESS
