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
            args=["-c", "import sys; print(sys.argv[1], sys.argv[2])", "{{ _event.user }}", "{{ _event.host }}"],
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
            arguments={"args": ["-c", "import sys; print(sys.argv[1])", "{{ _event.user }}"]},
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

    def test_executable_with_env(self, tmpdir):
        cmd = CommandConfig(
            type="executable",
            path=PYTHON,
            args=["-c", "import os; print(os.environ['MY_VAR'])"],
            env={"MY_VAR": "hello"},
        )
        result = execute_command(cmd, {}, [], "event", [], local_time(), str(tmpdir))
        assert result.strip() == "hello"

    def test_executable_with_jinja_env(self, tmpdir):
        cmd = CommandConfig(
            type="executable",
            path=PYTHON,
            args=["-c", "import os; print(os.environ['USER_NAME'])"],
            env={"USER_NAME": "{{ _event.user }}"},
        )
        result = execute_command(
            cmd, {"user": "admin"}, [], "event", [], local_time(), str(tmpdir),
        )
        assert result.strip() == "admin"

    def test_executable_with_env_inherits_os_env(self, tmpdir):
        cmd = CommandConfig(
            type="executable",
            path=PYTHON,
            args=["-c", "import os; print(os.environ.get('PATH', 'missing'))"],
            env={"MY_VAR": "test"},
        )
        result = execute_command(cmd, {}, [], "event", [], local_time(), str(tmpdir))
        assert result.strip() != "missing"

    def test_executable_without_env_inherits_os_env(self, tmpdir):
        cmd = CommandConfig(
            type="executable",
            path=PYTHON,
            args=["-c", "import os; print(os.environ.get('PATH', 'missing'))"],
        )
        result = execute_command(cmd, {}, [], "event", [], local_time(), str(tmpdir))
        assert result.strip() != "missing"

    def test_executable_timeout(self, tmpdir):
        cmd = CommandConfig(
            type="executable",
            path=PYTHON,
            args=["-c", "import time; time.sleep(60)"],
            timeout="1s",
        )
        with pytest.raises(RuntimeError, match="timed out"):
            execute_command(cmd, {}, [], "event", [], local_time(), str(tmpdir))

    def test_executable_cache_hit(self, tmpdir):
        cmd = CommandConfig(
            type="executable",
            path=PYTHON,
            args=["-c", "print('hello')"],
            cache="1h",
        )
        with patch("saq.collectors.hunter.correlation.commands.get_cached_result", return_value="cached value") as mock_get:
            result = execute_command(cmd, {}, [], "event", [], local_time(), str(tmpdir))

        assert result == "cached value"
        mock_get.assert_called_once_with({"type": "executable", "path": PYTHON, "args": ["-c", "print('hello')"], "env": None})

    def test_executable_cache_miss_stores_result(self, tmpdir):
        cmd = CommandConfig(
            type="executable",
            path=PYTHON,
            args=["-c", "print('hello')"],
            cache="1h",
        )
        with patch("saq.collectors.hunter.correlation.commands.get_cached_result", return_value=None), \
             patch("saq.collectors.hunter.correlation.commands.set_cached_result") as mock_set:
            result = execute_command(cmd, {}, [], "event", [], local_time(), str(tmpdir))

        assert result.strip() == "hello"
        mock_set.assert_called_once_with(
            {"type": "executable", "path": PYTHON, "args": ["-c", "print('hello')"], "env": None},
            result,
            3600,
        )

    def test_executable_no_cache_skips_cache(self, tmpdir):
        cmd = CommandConfig(
            type="executable",
            path=PYTHON,
            args=["-c", "print('hello')"],
        )
        with patch("saq.collectors.hunter.correlation.commands.get_cached_result") as mock_get, \
             patch("saq.collectors.hunter.correlation.commands.set_cached_result") as mock_set:
            result = execute_command(cmd, {}, [], "event", [], local_time(), str(tmpdir))

        assert result.strip() == "hello"
        mock_get.assert_not_called()
        mock_set.assert_not_called()

    def test_executable_cache_key_includes_rendered_args(self, tmpdir):
        cmd = CommandConfig(
            type="executable",
            path=PYTHON,
            args=["-c", "print('hello')", "{{ _event.user }}"],
            cache="1h",
        )
        with patch("saq.collectors.hunter.correlation.commands.get_cached_result", return_value=None) as mock_get, \
             patch("saq.collectors.hunter.correlation.commands.set_cached_result"):
            execute_command(cmd, {"user": "admin"}, [], "event", [], local_time(), str(tmpdir))

        mock_get.assert_called_once_with({"type": "executable", "path": PYTHON, "args": ["-c", "print('hello')", "admin"], "env": None})

    def test_executable_cache_key_includes_rendered_env(self, tmpdir):
        cmd = CommandConfig(
            type="executable",
            path=PYTHON,
            args=["-c", "import os; print(os.environ['MY_VAR'])"],
            env={"MY_VAR": "{{ _event.val }}"},
            cache="1h",
        )
        with patch("saq.collectors.hunter.correlation.commands.get_cached_result", return_value=None) as mock_get, \
             patch("saq.collectors.hunter.correlation.commands.set_cached_result"):
            execute_command(cmd, {"val": "test123"}, [], "event", [], local_time(), str(tmpdir))

        mock_get.assert_called_once_with({
            "type": "executable",
            "path": PYTHON,
            "args": ["-c", "import os; print(os.environ['MY_VAR'])"],
            "env": {"MY_VAR": "test123"},
        })
