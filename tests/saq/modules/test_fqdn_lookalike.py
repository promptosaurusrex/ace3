"""Unit tests for ``saq.modules.fqdn_lookalike``.

Author: jpetrucci
"""

import pytest

from saq.configuration.config import get_analysis_module_config
from saq.constants import (
    ANALYSIS_MODULE_FQDN_LOOKALIKE_ANALYZER,
    F_FQDN,
    AnalysisExecutionResult,
)
from saq.modules.fqdn_lookalike import (
    FQDNLookalikeAnalysis,
    FQDNLookalikeAnalyzer,
    TAG_LOOKALIKE,
    _levenshtein,
    _registrable,
)
from tests.saq.helpers import create_root_analysis
from tests.saq.test_util import create_test_context


def _build_analyzer(root):
    """Build an analyzer wired to a context whose root is the given RootAnalysis."""
    return FQDNLookalikeAnalyzer(
        context=create_test_context(root=root),
        config=get_analysis_module_config(ANALYSIS_MODULE_FQDN_LOOKALIKE_ANALYZER),
    )


def _run(analyzer, observable):
    return analyzer.execute_analysis(observable)


# ---------------------------------------------------------------------------
# pure helpers
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_levenshtein_basic():
    assert _levenshtein("paypal", "paypal") == 0
    assert _levenshtein("paypal", "paypa1") == 1
    assert _levenshtein("google", "googel") == 2
    assert _levenshtein("", "abc") == 3
    assert _levenshtein("abc", "") == 3


@pytest.mark.unit
def test_registrable_extracts_domain_and_label():
    assert _registrable("login.paypal.com") == ("paypal.com", "paypal")
    assert _registrable("PAYPAL.COM.") == ("paypal.com", "paypal")


@pytest.mark.unit
def test_registrable_returns_none_for_garbage():
    assert _registrable("") is None
    assert _registrable("not_a_domain") is None  # no public suffix
    assert _registrable(None) is None  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# FQDNLookalikeAnalysis
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_analysis_initial_state():
    analysis = FQDNLookalikeAnalysis()
    assert analysis.matches == []
    assert analysis.generate_summary() is None


@pytest.mark.unit
def test_analysis_summary_after_match():
    analysis = FQDNLookalikeAnalysis()
    analysis.add_match("paypa1.com", "paypal.com", "paypa1.com", 1)
    summary = analysis.generate_summary()
    assert summary is not None
    assert "paypa1.com" in summary
    assert "distance 1" in summary


# ---------------------------------------------------------------------------
# FQDNLookalikeAnalyzer
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_no_other_fqdns_no_analysis():
    root = create_root_analysis()
    root.initialize_storage()
    obs = root.add_observable_by_spec(F_FQDN, "paypal.com")

    analyzer = _build_analyzer(root)
    assert _run(analyzer, obs) == AnalysisExecutionResult.COMPLETED
    assert obs.get_analysis(FQDNLookalikeAnalysis) is None
    assert not obs.has_tag(TAG_LOOKALIKE)


@pytest.mark.unit
def test_identical_registrable_does_not_match():
    """mail.example.com and www.example.com share a registrable — not a lookalike."""
    root = create_root_analysis()
    root.initialize_storage()
    a = root.add_observable_by_spec(F_FQDN, "mail.example.com")
    root.add_observable_by_spec(F_FQDN, "www.example.com")

    analyzer = _build_analyzer(root)
    assert _run(analyzer, a) == AnalysisExecutionResult.COMPLETED
    assert a.get_analysis(FQDNLookalikeAnalysis) is None
    assert not a.has_tag(TAG_LOOKALIKE)


@pytest.mark.unit
def test_lookalike_pair_tags_and_records_match():
    root = create_root_analysis()
    root.initialize_storage()
    a = root.add_observable_by_spec(F_FQDN, "paypal.com")
    root.add_observable_by_spec(F_FQDN, "paypa1.com")

    analyzer = _build_analyzer(root)
    assert _run(analyzer, a) == AnalysisExecutionResult.COMPLETED

    analysis = a.get_analysis(FQDNLookalikeAnalysis)
    assert analysis is not None
    assert a.has_tag(TAG_LOOKALIKE)
    assert len(analysis.matches) == 1
    match = analysis.matches[0]
    assert match["other"] == "paypa1.com"
    assert match["registrable_self"] == "paypal.com"
    assert match["registrable_other"] == "paypa1.com"
    assert match["distance"] == 1


@pytest.mark.unit
def test_short_label_pair_does_not_match():
    """`a.io` vs `b.io`: distance is 1 but the labels are too short to be meaningful."""
    root = create_root_analysis()
    root.initialize_storage()
    a = root.add_observable_by_spec(F_FQDN, "a.io")
    root.add_observable_by_spec(F_FQDN, "b.io")

    analyzer = _build_analyzer(root)
    assert _run(analyzer, a) == AnalysisExecutionResult.COMPLETED
    assert a.get_analysis(FQDNLookalikeAnalysis) is None
    assert not a.has_tag(TAG_LOOKALIKE)


@pytest.mark.unit
def test_distant_pair_does_not_match():
    """Two completely different domains shouldn't trip the rule."""
    root = create_root_analysis()
    root.initialize_storage()
    a = root.add_observable_by_spec(F_FQDN, "paypal.com")
    root.add_observable_by_spec(F_FQDN, "google.com")

    analyzer = _build_analyzer(root)
    assert _run(analyzer, a) == AnalysisExecutionResult.COMPLETED
    assert a.get_analysis(FQDNLookalikeAnalysis) is None
    assert not a.has_tag(TAG_LOOKALIKE)


@pytest.mark.unit
def test_multiple_lookalikes_are_all_recorded():
    root = create_root_analysis()
    root.initialize_storage()
    a = root.add_observable_by_spec(F_FQDN, "paypal.com")
    root.add_observable_by_spec(F_FQDN, "paypa1.com")  # distance 1
    root.add_observable_by_spec(F_FQDN, "paypall.com")  # distance 1
    root.add_observable_by_spec(F_FQDN, "google.com")  # far

    analyzer = _build_analyzer(root)
    assert _run(analyzer, a) == AnalysisExecutionResult.COMPLETED

    analysis = a.get_analysis(FQDNLookalikeAnalysis)
    assert analysis is not None
    others = sorted(m["other"] for m in analysis.matches)
    assert others == ["paypa1.com", "paypall.com"]
