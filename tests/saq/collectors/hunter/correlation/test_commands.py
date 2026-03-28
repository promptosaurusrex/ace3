import json
import sys
from unittest.mock import patch

import pytest

from saq.collectors.hunter.correlation.commands import execute_command
from saq.collectors.hunter.correlation.registry import (
    QuerySource,
    clear_query_sources,
    register_query_source,
)
from saq.collectors.hunter.correlation.schema import CommandConfig, PredefinedCommandConfig
from saq.util import local_time

PYTHON = sys.executable


class MockQuerySource(QuerySource):
    def __init__(self, results=None):
        self.results = results or []
        self.calls = []

    def execute_query(self, query, start_time, end_time, timeout):
        self.calls.append({"query": query, "start_time": start_time, "end_time": end_time})
        return self.results


@pytest.fixture(autouse=True)
def _clean_registry():
    clear_query_sources()
    yield
    clear_query_sources()


@pytest.mark.unit
class TestExecuteCommand:

    def test_query_command(self, tmpdir):
        source = MockQuerySource(results=[{"host": "web1"}, {"host": "web2"}])
        register_query_source("test_source", source)

        cmd = CommandConfig(
            type="query",
            source="test_source",
            query="search index=main",
            time_range=None,
        )

        with patch("saq.collectors.hunter.correlation.commands.get_cached_result", return_value=None), \
             patch("saq.collectors.hunter.correlation.commands.set_cached_result"):
            result = execute_command(
                cmd, {}, [], "event", [], local_time(), str(tmpdir),
            )

        lines = result.strip().split("\n")
        assert len(lines) == 2
        assert json.loads(lines[0]) == {"host": "web1"}

    def test_executable_command(self, tmpdir):
        cmd = CommandConfig(
            type="executable",
            path=PYTHON,
            args=["-c", "print('hello world')"],
        )
        result = execute_command(cmd, {}, [], "event", [], local_time(), str(tmpdir))
        assert result.strip() == "hello world"

    def test_executable_with_jinja_args(self, tmpdir):
        cmd = CommandConfig(
            type="executable",
            path=PYTHON,
            args=["-c", "import sys; print(sys.argv[1], sys.argv[2])", "{{ user }}", "{{ host }}"],
        )
        result = execute_command(
            cmd, {"user": "admin", "host": "web1"}, [], "event", [], local_time(), str(tmpdir),
        )
        assert result.strip() == "admin web1"

    def test_executable_with_stdin_event(self, tmpdir):
        cmd = CommandConfig(
            type="executable",
            path=PYTHON,
            args=["-c", "import sys; print(sys.stdin.read(), end='')"],
            stdin=True,
        )
        event = {"user": "admin"}
        result = execute_command(cmd, event, [event], "event", [], local_time(), str(tmpdir))
        assert json.loads(result) == {"user": "admin"}

    def test_defined_command(self, tmpdir):
        predef = PredefinedCommandConfig(
            name="lookup",
            type="executable",
            path=PYTHON,
            args=["-c", "print('default')"],
        )

        cmd = CommandConfig(
            type="defined",
            name="lookup",
            arguments={"args": ["-c", "import sys; print(sys.argv[1])", "{{ user }}"]},
        )
        result = execute_command(
            cmd, {"user": "admin"}, [], "event", [predef], local_time(), str(tmpdir),
        )
        assert result.strip() == "admin"

    def test_defined_command_not_found(self, tmpdir):
        cmd = CommandConfig(type="defined", name="nonexistent")
        with pytest.raises(ValueError, match="not found"):
            execute_command(cmd, {}, [], "event", [], local_time(), str(tmpdir))

    def test_stream_query_memoization(self, tmpdir):
        source = MockQuerySource(results=[{"host": "web1"}])
        register_query_source("test_source", source)

        cmd = CommandConfig(type="query", source="test_source", query="search index=main")
        cache = {}

        with patch("saq.collectors.hunter.correlation.commands.get_cached_result", return_value=None), \
             patch("saq.collectors.hunter.correlation.commands.set_cached_result"):
            result1 = execute_command(cmd, {}, [], "stream", [], local_time(), str(tmpdir), cache)
            result2 = execute_command(cmd, {}, [], "stream", [], local_time(), str(tmpdir), cache)

        assert result1 == result2
        assert len(source.calls) == 1  # only called once

    def test_executable_timeout(self, tmpdir):
        cmd = CommandConfig(
            type="executable",
            path=PYTHON,
            args=["-c", "import time; time.sleep(60)"],
            timeout="1s",
        )
        with pytest.raises(RuntimeError, match="timed out"):
            execute_command(cmd, {}, [], "event", [], local_time(), str(tmpdir))
