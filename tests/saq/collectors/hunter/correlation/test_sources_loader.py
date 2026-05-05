import logging

import pytest

from saq.collectors.hunter.correlation.registry import (
    QuerySource,
    clear_query_sources,
    get_query_source,
    get_registered_sources,
)
from saq.collectors.hunter.correlation.sources import (
    load_query_sources_from_config,
    reset_query_sources_loaded_flag,
)
from saq.configuration import get_config
from saq.configuration.schema import CorrelationConfig, HunterConfig, QuerySourceConfig


# concrete QuerySource subclasses used as load targets in these tests.
# they live at module scope so importlib.import_module + getattr can find them.

class _RecordingSource(QuerySource):
    default_time_field = "_time"
    default_time_format = "iso8601"

    def __init__(self, label="default"):
        self.label = label
        self.calls = []

    def execute_query(self, query, start_time, end_time, timeout):
        self.calls.append((query, start_time, end_time, timeout))
        return []


class _BoomSource(QuerySource):
    default_time_field = "_time"
    default_time_format = "iso8601"

    def __init__(self):
        raise RuntimeError("constructor boom")

    def execute_query(self, query, start_time, end_time, timeout):
        return []


@pytest.fixture
def _clean_registry():
    clear_query_sources()
    reset_query_sources_loaded_flag()
    yield
    clear_query_sources()
    reset_query_sources_loaded_flag()


def _set_query_sources(monkeypatch, sources: list[QuerySourceConfig]):
    monkeypatch.setattr(
        get_config(),
        "hunter",
        HunterConfig(correlation=CorrelationConfig(query_sources=sources)),
    )


@pytest.mark.unit
class TestLoadQuerySourcesFromConfig:

    def test_registers_configured_source(self, _clean_registry, monkeypatch):
        _set_query_sources(
            monkeypatch,
            [
                QuerySourceConfig(
                    name="rec",
                    python_module="tests.saq.collectors.hunter.correlation.test_sources_loader",
                    python_class="_RecordingSource",
                    kwargs={"label": "primary"},
                ),
            ],
        )

        load_query_sources_from_config()

        source = get_query_source("rec")
        assert isinstance(source, _RecordingSource)
        assert source.label == "primary"

    def test_loaded_flag_prevents_double_registration(self, _clean_registry, monkeypatch):
        _set_query_sources(
            monkeypatch,
            [
                QuerySourceConfig(
                    name="rec",
                    python_module="tests.saq.collectors.hunter.correlation.test_sources_loader",
                    python_class="_RecordingSource",
                ),
            ],
        )

        load_query_sources_from_config()
        first = get_query_source("rec")
        load_query_sources_from_config()
        second = get_query_source("rec")

        # second call short-circuits via the _loaded flag, so the registry is untouched
        assert first is second

    def test_force_reloads(self, _clean_registry, monkeypatch):
        _set_query_sources(
            monkeypatch,
            [
                QuerySourceConfig(
                    name="rec",
                    python_module="tests.saq.collectors.hunter.correlation.test_sources_loader",
                    python_class="_RecordingSource",
                ),
            ],
        )

        load_query_sources_from_config()
        first = get_query_source("rec")
        load_query_sources_from_config(force=True)
        second = get_query_source("rec")

        assert first is not second

    def test_failing_source_does_not_abort_others(self, _clean_registry, monkeypatch, caplog):
        _set_query_sources(
            monkeypatch,
            [
                QuerySourceConfig(
                    name="boom",
                    python_module="tests.saq.collectors.hunter.correlation.test_sources_loader",
                    python_class="_BoomSource",
                ),
                QuerySourceConfig(
                    name="rec",
                    python_module="tests.saq.collectors.hunter.correlation.test_sources_loader",
                    python_class="_RecordingSource",
                ),
            ],
        )

        with caplog.at_level(logging.ERROR):
            load_query_sources_from_config()

        assert isinstance(get_query_source("rec"), _RecordingSource)
        assert "failed to load query source boom" in caplog.text
        with pytest.raises(ValueError):
            get_query_source("boom")

    def test_no_op_when_hunter_config_absent(self, _clean_registry, monkeypatch):
        monkeypatch.setattr(get_config(), "hunter", None)

        load_query_sources_from_config()

        assert get_registered_sources() == {}
