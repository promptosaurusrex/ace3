from datetime import timedelta, timezone

import argparse
import pytest

from hunt_compiler.validate import (
    _parse_duration,
    _parse_time_range_override,
    _read_hunt_durations,
    _synthesize_start_time,
)


class TestParseDuration:
    @pytest.mark.parametrize("text,expected", [
        ("30", timedelta(seconds=30)),
        ("01:30", timedelta(minutes=1, seconds=30)),
        ("00:10:00", timedelta(minutes=10)),
        ("02:00:00", timedelta(hours=2)),
        ("01:00:00:00", timedelta(days=1)),
    ])
    def test_valid(self, text, expected):
        assert _parse_duration(text) == expected

    @pytest.mark.parametrize("text", ["", "abc", "1h", "1:2:3:4:5", "00:bad:00"])
    def test_invalid(self, text):
        with pytest.raises(ValueError):
            _parse_duration(text)


class TestParseTimeRangeOverride:
    def test_basic(self):
        assert _parse_time_range_override("TIMESPEC=00:10:00") == ("TIMESPEC", "00:10:00")

    def test_strips_whitespace(self):
        assert _parse_time_range_override("  TIMESPEC = 00:10:00 ") == ("TIMESPEC", "00:10:00")

    @pytest.mark.parametrize("bad", [
        "TIMESPEC",
        "=00:10:00",
        "TIMESPEC=",
        "TIMESPEC=not-a-duration",
    ])
    def test_invalid_raises_argparse_error(self, bad):
        with pytest.raises(argparse.ArgumentTypeError):
            _parse_time_range_override(bad)


class TestReadHuntDurations:
    def test_reads_time_ranges_dict(self, tmp_path):
        hunt = tmp_path / "h.yaml"
        hunt.write_text(
            "rule:\n"
            "  time_ranges:\n"
            "    TIMESPEC: '00:10:00'\n"
            "    TIMESPEC2: '00:30:00'\n"
        )
        assert _read_hunt_durations(str(hunt)) == {
            "TIMESPEC": "00:10:00",
            "TIMESPEC2": "00:30:00",
        }

    def test_reads_time_ranges_with_duration_before(self, tmp_path):
        hunt = tmp_path / "h.yaml"
        hunt.write_text(
            "rule:\n"
            "  time_ranges:\n"
            "    TIMESPEC:\n"
            "      duration_before: '00:15:00'\n"
        )
        assert _read_hunt_durations(str(hunt)) == {"TIMESPEC": "00:15:00"}

    def test_legacy_time_range_maps_to_TIMESPEC(self, tmp_path):
        hunt = tmp_path / "h.yaml"
        hunt.write_text(
            "rule:\n"
            "  time_range: '00:05:00'\n"
        )
        assert _read_hunt_durations(str(hunt)) == {"TIMESPEC": "00:05:00"}

    def test_time_ranges_takes_precedence_over_legacy(self, tmp_path):
        hunt = tmp_path / "h.yaml"
        hunt.write_text(
            "rule:\n"
            "  time_range: '00:05:00'\n"
            "  time_ranges:\n"
            "    TIMESPEC: '00:10:00'\n"
        )
        # time_ranges TIMESPEC wins; legacy time_range is not used to overwrite it
        assert _read_hunt_durations(str(hunt)) == {"TIMESPEC": "00:10:00"}

    def test_missing_rule_returns_empty(self, tmp_path):
        hunt = tmp_path / "h.yaml"
        hunt.write_text("commands: []\n")
        assert _read_hunt_durations(str(hunt)) == {}


class TestSynthesizeStartTime:
    def test_uses_widest_yaml_duration(self, tmp_path):
        hunt = tmp_path / "h.yaml"
        hunt.write_text(
            "rule:\n"
            "  time_ranges:\n"
            "    TIMESPEC: '00:10:00'\n"
            "    TIMESPEC2: '00:30:00'\n"
        )
        result = _synthesize_start_time(str(hunt), "01/01/2024:01:00:00", {}, timezone.utc)
        # widest is 30m, so start = end - 30m = 00:30:00
        assert result == "01/01/2024:00:30:00"

    def test_override_widens_window(self, tmp_path):
        hunt = tmp_path / "h.yaml"
        hunt.write_text(
            "rule:\n"
            "  time_ranges:\n"
            "    TIMESPEC: '00:10:00'\n"
            "    TIMESPEC2: '00:30:00'\n"
        )
        # override TIMESPEC2 to 2h — that becomes the widest
        result = _synthesize_start_time(
            str(hunt), "01/01/2024:01:00:00", {"TIMESPEC2": "02:00:00"}, timezone.utc,
        )
        assert result == "12/31/2023:23:00:00"

    def test_override_only_no_yaml_durations(self, tmp_path):
        hunt = tmp_path / "h.yaml"
        # no time_range / time_ranges in YAML
        hunt.write_text("rule:\n  name: empty\n")
        result = _synthesize_start_time(
            str(hunt), "01/01/2024:01:00:00", {"TIMESPEC": "00:15:00"}, timezone.utc,
        )
        assert result == "01/01/2024:00:45:00"

    def test_no_durations_anywhere_raises(self, tmp_path):
        hunt = tmp_path / "h.yaml"
        hunt.write_text("rule:\n  name: empty\n")
        with pytest.raises(ValueError, match="cannot synthesize"):
            _synthesize_start_time(str(hunt), "01/01/2024:01:00:00", {}, timezone.utc)
