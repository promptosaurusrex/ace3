"""Unit tests for ``saq.modules.nrd``."""

import sqlite3
from pathlib import Path

import pytest

from saq.configuration.config import get_analysis_module_config
from saq.constants import ANALYSIS_MODULE_NRD_ANALYZER, F_FQDN, F_URL, AnalysisExecutionResult
from saq.modules.nrd import NRDAnalysis, NRDAnalyzer, TAG_NRD
from saq.nrd import util as nrd_util
from saq.nrd.util import _reset_connection_for_tests
from tests.saq.helpers import create_root_analysis


def _build_test_db(path: Path, domains: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    conn = sqlite3.connect(str(path))
    try:
        conn.executescript(
            """
            CREATE TABLE nrd (domain TEXT PRIMARY KEY) WITHOUT ROWID;
            CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
            """
        )
        with conn:
            conn.executemany(
                "INSERT OR IGNORE INTO nrd (domain) VALUES (?)",
                [(d,) for d in domains],
            )
    finally:
        conn.close()


@pytest.fixture
def nrd_db(tmp_path, monkeypatch):
    """Provide an isolated tmp NRD database. Returns a callable to (re)build it."""
    db_path = tmp_path / "nrd_index.db"
    monkeypatch.setattr(nrd_util, "get_database_path", lambda: db_path)
    _reset_connection_for_tests()

    def builder(domains: list[str]) -> Path:
        _build_test_db(db_path, domains)
        _reset_connection_for_tests()
        return db_path

    yield builder

    _reset_connection_for_tests()


# ---------------------------------------------------------------------------
# NRDAnalysis
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_nrd_analysis_initial_state():
    analysis = NRDAnalysis()
    assert analysis.is_nrd is False
    assert analysis.matched_at is None
    assert analysis.generate_summary() is None


@pytest.mark.unit
def test_nrd_analysis_setters():
    analysis = NRDAnalysis()
    analysis.is_nrd = True
    analysis.matched_at = "2026-04-29T12:00:00+00:00"
    assert analysis.is_nrd is True
    assert analysis.matched_at == "2026-04-29T12:00:00+00:00"
    assert "Newly Registered Domain" in analysis.generate_summary()


# ---------------------------------------------------------------------------
# NRDAnalyzer
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_analyzer_tags_match(nrd_db, test_context):
    nrd_db(["phish-test.example"])

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "phish-test.example")

    analyzer = NRDAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_NRD_ANALYZER),
    )
    analyzer.root = root

    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_analysis(NRDAnalysis)
    assert analysis is not None
    assert analysis.is_nrd is True
    assert analysis.matched_at is not None
    assert observable.has_tag(TAG_NRD)


@pytest.mark.unit
def test_analyzer_no_match_produces_no_analysis(nrd_db, test_context):
    nrd_db(["other-domain.example"])

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "not-in-nrd-list.example")

    analyzer = NRDAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_NRD_ANALYZER),
    )
    analyzer.root = root

    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_analysis(NRDAnalysis)
    assert analysis is None
    assert not observable.has_tag(TAG_NRD)


@pytest.mark.unit
def test_analyzer_handles_missing_database(tmp_path, monkeypatch, test_context):
    # Point at a nonexistent DB.
    monkeypatch.setattr(nrd_util, "get_database_path", lambda: tmp_path / "no-such-db.db")
    _reset_connection_for_tests()

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "anything.example")

    analyzer = NRDAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_NRD_ANALYZER),
    )
    analyzer.root = root

    try:
        result = analyzer.execute_analysis(observable)
    finally:
        _reset_connection_for_tests()

    assert result == AnalysisExecutionResult.COMPLETED
    assert observable.get_analysis(NRDAnalysis) is None


@pytest.mark.unit
def test_analyzer_tags_url_observable_on_match(nrd_db, test_context):
    """In email mode where parse_url isn't enabled, the analyzer must run on URL observables."""
    nrd_db(["phish-test.com"])

    root = create_root_analysis()
    root.initialize_storage()
    # URL has a subdomain to exercise both URL host extraction and the parent walk.
    observable = root.add_observable_by_spec(F_URL, "https://login.phish-test.com/start?q=1")

    analyzer = NRDAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_NRD_ANALYZER),
    )
    analyzer.root = root

    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_analysis(NRDAnalysis)
    assert analysis is not None
    assert analysis.is_nrd is True
    assert observable.has_tag(TAG_NRD)


@pytest.mark.unit
def test_analyzer_url_observable_no_match(nrd_db, test_context):
    nrd_db(["other-domain.example"])

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_URL, "https://safe-host.example/foo")

    analyzer = NRDAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_NRD_ANALYZER),
    )
    analyzer.root = root

    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED
    assert observable.get_analysis(NRDAnalysis) is None
    assert not observable.has_tag(TAG_NRD)


@pytest.mark.unit
def test_analyzer_idn_input_matches_punycode_row(nrd_db, test_context):
    """IDN input should match the punycode-form row stored in the database."""
    nrd_db(["xn--caf-dma.example"])

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "café.example")

    analyzer = NRDAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_NRD_ANALYZER),
    )
    analyzer.root = root

    assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_analysis(NRDAnalysis)
    assert analysis is not None
    assert analysis.is_nrd is True
