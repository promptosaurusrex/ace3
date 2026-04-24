import pytest

from saq.analysis.analysis import Analysis
from saq.analysis.detection_chain import (
    build_detection_chains,
    build_merged_detection_tree,
    module_display_name,
    observable_display_value,
)
from saq.analysis.root import RootAnalysis
from saq.constants import F_FILE, F_TEST, F_URL


class EmailAnalysis(Analysis):
    pass


class NestedEmailAnalysis(Analysis):
    pass


class PhishkitAnalysis(Analysis):
    pass


class QRCodeAnalysis(Analysis):
    pass


class _FakeObservable:
    """Minimal stand-in for display-formatting tests that don't need tree membership."""
    def __init__(self, type_, value):
        self.type = type_
        self.value = value


@pytest.mark.unit
def test_no_detections_returns_empty():
    root = RootAnalysis()
    root.add_observable_by_spec(F_TEST, "harmless")
    assert build_detection_chains(root) == []


@pytest.mark.unit
def test_detection_on_root_observable_produces_single_step_chain():
    root = RootAnalysis()
    obs = root.add_observable_by_spec(F_TEST, "toplevel")
    obs.add_detection_point("root-level detection")

    chains = build_detection_chains(root)
    assert len(chains) == 1
    chain = chains[0]
    assert chain.detection.description == "root-level detection"
    assert chain.owner is obs
    assert len(chain.steps) == 1
    assert chain.steps[0].observable is obs
    assert chain.steps[0].extracted_by is None


@pytest.mark.unit
def test_detection_on_nested_observable_walks_up_to_root():
    root = RootAnalysis()
    top = root.add_observable_by_spec(F_TEST, "top")
    email_analysis = EmailAnalysis()
    top.add_analysis(email_analysis)
    nested = email_analysis.add_observable_by_spec(F_TEST, "nested")
    nested.add_detection_point("nested email detection")

    chains = build_detection_chains(root)
    assert len(chains) == 1
    chain = chains[0]
    assert chain.detection.description == "nested email detection"
    assert len(chain.steps) == 2
    assert chain.steps[0].observable is top
    assert chain.steps[0].extracted_by is None
    assert chain.steps[1].observable is nested
    assert chain.steps[1].extracted_by is email_analysis


@pytest.mark.unit
def test_deep_chain_records_every_extracting_analysis():
    root = RootAnalysis()
    top = root.add_observable_by_spec(F_TEST, "original_email")

    email_a = EmailAnalysis()
    top.add_analysis(email_a)
    nested = email_a.add_observable_by_spec(F_TEST, "nested_email")

    email_b = NestedEmailAnalysis()
    nested.add_analysis(email_b)
    html = email_b.add_observable_by_spec(F_TEST, "html_body")

    phishkit = PhishkitAnalysis()
    html.add_analysis(phishkit)
    screenshot = phishkit.add_observable_by_spec(F_TEST, "screenshot")

    qrcode = QRCodeAnalysis()
    screenshot.add_analysis(qrcode)
    url_obs = qrcode.add_observable_by_spec(F_URL, "https://mikaija.ru/@bv.com")
    url_obs.add_detection_point("QR code URL targeting BV employee")

    chains = build_detection_chains(root)
    assert len(chains) == 1
    chain = chains[0]
    steps = chain.steps
    assert [s.observable.value for s in steps] == [
        "original_email",
        "nested_email",
        "html_body",
        "screenshot",
        "https://mikaija.ru/@bv.com",
    ]
    extractors = [s.extracted_by for s in steps]
    assert extractors[0] is None
    assert extractors[1] is email_a
    assert isinstance(extractors[2], NestedEmailAnalysis)
    assert extractors[3] is phishkit
    assert extractors[4] is qrcode


@pytest.mark.unit
def test_detection_on_analysis_uses_parent_observable_as_carrier():
    root = RootAnalysis()
    top = root.add_observable_by_spec(F_TEST, "top")
    analysis = EmailAnalysis()
    top.add_analysis(analysis)
    analysis.add_detection_point("detection on analysis")

    chains = build_detection_chains(root)
    assert len(chains) == 1
    chain = chains[0]
    assert chain.owner is analysis
    assert chain.steps[-1].observable is top


@pytest.mark.unit
def test_detection_on_root_analysis_itself_is_skipped():
    root = RootAnalysis()
    root.add_observable_by_spec(F_TEST, "dummy")
    root.add_detection_point("this should not chain")
    assert build_detection_chains(root) == []


@pytest.mark.unit
def test_merged_tree_shares_common_prefix():
    root = RootAnalysis()
    top = root.add_observable_by_spec(F_TEST, "top")
    email_a = EmailAnalysis()
    top.add_analysis(email_a)
    nested = email_a.add_observable_by_spec(F_TEST, "nested")
    nested.add_detection_point("nested detection")

    email_b = NestedEmailAnalysis()
    nested.add_analysis(email_b)
    html = email_b.add_observable_by_spec(F_TEST, "html")
    html.add_detection_point("html detection")

    chains = build_detection_chains(root)
    assert len(chains) == 2

    merged = build_merged_detection_tree(chains)
    assert len(merged) == 1
    root_node = merged[0]
    assert root_node.observable is top
    assert root_node.extracted_by is None
    assert not root_node.detections

    assert len(root_node.children) == 1
    nested_node = list(root_node.children.values())[0]
    assert nested_node.observable is nested
    assert nested_node.extracted_by is email_a
    assert any(d.description == "nested detection" for d in nested_node.detections)

    assert len(nested_node.children) == 1
    html_node = list(nested_node.children.values())[0]
    assert html_node.observable is html
    assert html_node.extracted_by is email_b
    assert any(d.description == "html detection" for d in html_node.detections)


@pytest.mark.unit
def test_module_display_name_uses_class_portion():
    analysis = EmailAnalysis()
    assert module_display_name(analysis) == "EmailAnalysis"


@pytest.mark.unit
def test_observable_display_value_uses_file_name_for_file_observables():
    class _FakeFileObservable(_FakeObservable):
        def __init__(self, value, file_name):
            super().__init__(F_FILE, value)
            self.file_name = file_name

    file_obs = _FakeFileObservable("a" * 64, "invoice.eml")
    assert observable_display_value(file_obs) == "invoice.eml"


@pytest.mark.unit
def test_observable_display_value_falls_back_to_hash_when_no_file_name():
    file_obs = _FakeObservable(F_FILE, "a" * 64)
    # no file_name attribute → fall back to value and truncate
    assert observable_display_value(file_obs, max_len=10) == "a" * 10 + "…"




@pytest.mark.unit
def test_observable_display_value_passes_short_values_through():
    url_obs = _FakeObservable(F_URL, "https://example.com/short")
    assert observable_display_value(url_obs) == "https://example.com/short"


@pytest.mark.unit
def test_observable_display_value_truncates_long_non_file_values():
    long_url = "https://example.com/" + "x" * 100
    url_obs = _FakeObservable(F_URL, long_url)
    displayed = observable_display_value(url_obs, max_len=60)
    assert displayed.endswith("…")
    assert len(displayed) == 61
