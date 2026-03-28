from datetime import timedelta

import pytest

from saq.collectors.hunter.correlation.timespec import parse_timespec


@pytest.mark.unit
class TestParseTimespec:

    @pytest.mark.parametrize("value,expected", [
        ("30s", timedelta(seconds=30)),
        ("5m", timedelta(minutes=5)),
        ("2h", timedelta(hours=2)),
        ("1d", timedelta(days=1)),
        ("1w", timedelta(weeks=1)),
        ("1y", timedelta(days=365)),
        ("0s", timedelta(seconds=0)),
    ])
    def test_single_unit(self, value, expected):
        assert parse_timespec(value) == expected

    @pytest.mark.parametrize("value,expected", [
        ("8h30m30s", timedelta(hours=8, minutes=30, seconds=30)),
        ("8h 30m 30s", timedelta(hours=8, minutes=30, seconds=30)),
        ("1d12h", timedelta(days=1, hours=12)),
        ("1y2w3d", timedelta(days=365 + 14 + 3)),
        ("1d 0h 0m 0s", timedelta(days=1)),
    ])
    def test_combined_units(self, value, expected):
        assert parse_timespec(value) == expected

    def test_whitespace_variants(self):
        result = parse_timespec("  1h  30m  ")
        assert result == timedelta(hours=1, minutes=30)

    def test_invalid_raises_value_error(self):
        with pytest.raises(ValueError):
            parse_timespec("invalid")

    def test_empty_string_raises_value_error(self):
        with pytest.raises(ValueError):
            parse_timespec("")

    def test_case_insensitive(self):
        assert parse_timespec("1H30M") == timedelta(hours=1, minutes=30)
