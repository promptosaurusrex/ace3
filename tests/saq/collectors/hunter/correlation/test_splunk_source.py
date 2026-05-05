import datetime
from unittest.mock import MagicMock, patch

import pytest

from saq.collectors.hunter.correlation.registry import clear_query_sources
from saq.collectors.hunter.correlation.sources.splunk import SplunkQuerySource


@pytest.fixture(autouse=True)
def _clean_registry():
    clear_query_sources()
    yield
    clear_query_sources()


@pytest.mark.unit
class TestSplunkQuerySource:

    def test_execute_query_calls_splunk_client_with_config_name(self):
        mock_client = MagicMock()
        mock_client.query.return_value = []
        with patch(
            "saq.splunk.SplunkClient",
            return_value=mock_client,
        ) as mock_factory:
            source = SplunkQuerySource("my_config")
            source.execute_query(
                "search index=main",
                datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
                datetime.datetime(2024, 1, 2, tzinfo=datetime.timezone.utc),
                datetime.timedelta(minutes=30),
            )
            mock_factory.assert_called_once_with("my_config")

    def test_execute_query_passes_correct_params(self):
        mock_client = MagicMock()
        mock_client.query.return_value = []
        start = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
        end = datetime.datetime(2024, 1, 2, tzinfo=datetime.timezone.utc)
        timeout = datetime.timedelta(minutes=15)
        with patch(
            "saq.splunk.SplunkClient",
            return_value=mock_client,
        ):
            source = SplunkQuerySource()
            source.execute_query("search index=main", start, end, timeout)
            mock_client.query.assert_called_once_with(
                query="search index=main",
                start=start,
                end=end,
                timeout=timeout,
            )

    def test_execute_query_returns_results(self):
        mock_client = MagicMock()
        expected = [{"host": "web1"}, {"host": "web2"}]
        mock_client.query.return_value = expected
        with patch(
            "saq.splunk.SplunkClient",
            return_value=mock_client,
        ):
            source = SplunkQuerySource()
            results = source.execute_query(
                "search index=main",
                datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
                datetime.datetime(2024, 1, 2, tzinfo=datetime.timezone.utc),
                datetime.timedelta(minutes=5),
            )
            assert results == expected

    def test_execute_query_returns_empty_list(self):
        mock_client = MagicMock()
        mock_client.query.return_value = []
        with patch(
            "saq.splunk.SplunkClient",
            return_value=mock_client,
        ):
            source = SplunkQuerySource()
            results = source.execute_query(
                "search index=main",
                datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
                datetime.datetime(2024, 1, 2, tzinfo=datetime.timezone.utc),
                datetime.timedelta(minutes=5),
            )
            assert results == []

    def test_default_config_name(self):
        mock_client = MagicMock()
        mock_client.query.return_value = []
        with patch(
            "saq.splunk.SplunkClient",
            return_value=mock_client,
        ) as mock_factory:
            source = SplunkQuerySource()
            source.execute_query(
                "search index=main",
                datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
                datetime.datetime(2024, 1, 2, tzinfo=datetime.timezone.utc),
                datetime.timedelta(minutes=5),
            )
            mock_factory.assert_called_once_with("default")


@pytest.mark.unit
class TestSplunkSourceMetadata:

    def test_default_time_field_and_format(self):
        # the splunk source declares the conventional defaults so hunts can omit
        # relative_time_field / relative_time_format on splunk-anchored time_ranges
        assert SplunkQuerySource.default_time_field == "_time"
        assert SplunkQuerySource.default_time_format == "iso8601"
