import json
import os
import shutil
import subprocess
from subprocess import TimeoutExpired
from unittest.mock import MagicMock, patch

import pytest
import yaml


FULL_PROXY_FALLBACK = {
    "error_patterns": [
        "ERR_TUNNEL_CONNECTION_FAILED",
        "ERR_PROXY_CONNECTION_FAILED",
        "ERR_PROXY_AUTH_FAILED",
        "ERR_PROXY_CERTIFICATE_INVALID",
    ],
    "proxy_status_codes": [400, 403, 407, 500, 502, 504, 522],
    "retry_on_timeout": True,
}

FULL_CONFIG = {"proxy_fallback": FULL_PROXY_FALLBACK}


# ---------------------------------------------------------------------------
# _matched_proxy_error_patterns
# ---------------------------------------------------------------------------


class TestMatchedProxyErrorPatterns:

    @pytest.mark.unit
    @pytest.mark.parametrize("pattern", [
        "ERR_TUNNEL_CONNECTION_FAILED",
        "ERR_PROXY_CONNECTION_FAILED",
        "ERR_PROXY_AUTH_FAILED",
        "ERR_PROXY_CERTIFICATE_INVALID",
    ])
    def test_matched_each_pattern(self, pattern):
        from phishkit import _matched_proxy_error_patterns
        patterns = FULL_PROXY_FALLBACK["error_patterns"]

        assert _matched_proxy_error_patterns(f"some output {pattern} here", "", patterns) == [pattern]

    @pytest.mark.unit
    def test_no_match_returns_empty(self):
        from phishkit import _matched_proxy_error_patterns
        patterns = FULL_PROXY_FALLBACK["error_patterns"]

        assert _matched_proxy_error_patterns("all good", "no errors", patterns) == []

    @pytest.mark.unit
    def test_none_inputs(self):
        from phishkit import _matched_proxy_error_patterns
        patterns = FULL_PROXY_FALLBACK["error_patterns"]

        assert _matched_proxy_error_patterns(None, None, patterns) == []

    @pytest.mark.unit
    def test_match_in_stderr_only(self):
        from phishkit import _matched_proxy_error_patterns
        patterns = FULL_PROXY_FALLBACK["error_patterns"]

        assert _matched_proxy_error_patterns(
            "", "ERR_TUNNEL_CONNECTION_FAILED", patterns,
        ) == ["ERR_TUNNEL_CONNECTION_FAILED"]

    @pytest.mark.unit
    def test_custom_patterns(self):
        from phishkit import _matched_proxy_error_patterns

        assert _matched_proxy_error_patterns(
            "CUSTOM_ERR occurred", "", ["CUSTOM_ERR"]
        ) == ["CUSTOM_ERR"]
        assert _matched_proxy_error_patterns(
            "CUSTOM_ERR occurred", "", ["OTHER_ERR"]
        ) == []

    @pytest.mark.unit
    def test_multiple_matches_returns_all(self):
        from phishkit import _matched_proxy_error_patterns
        patterns = ["ERR_A", "ERR_B", "ERR_C"]

        assert _matched_proxy_error_patterns(
            "ERR_A in stdout", "ERR_C in stderr", patterns,
        ) == ["ERR_A", "ERR_C"]


# ---------------------------------------------------------------------------
# _matched_proxy_status_code
# ---------------------------------------------------------------------------

class TestMatchedProxyStatusCode:

    @pytest.mark.unit
    def test_matching_status_code(self, tmpdir):
        from phishkit import _matched_proxy_status_code

        output_dir = str(tmpdir)
        requests_data = [
            {"type": "request", "url": "https://example.com", "requestId": "1"},
            {"type": "response", "url": "https://example.com", "requestId": "1", "status_code": 502},
        ]
        with open(os.path.join(output_dir, "requests.json"), "w") as f:
            json.dump(requests_data, f)

        assert _matched_proxy_status_code(output_dir, [502, 504]) == 502

    @pytest.mark.unit
    def test_non_matching_status_code(self, tmpdir):
        from phishkit import _matched_proxy_status_code

        output_dir = str(tmpdir)
        requests_data = [
            {"type": "request", "url": "https://example.com", "requestId": "1"},
            {"type": "response", "url": "https://example.com", "requestId": "1", "status_code": 200},
        ]
        with open(os.path.join(output_dir, "requests.json"), "w") as f:
            json.dump(requests_data, f)

        assert _matched_proxy_status_code(output_dir, [502, 504]) is None

    @pytest.mark.unit
    def test_missing_requests_json(self, tmpdir):
        from phishkit import _matched_proxy_status_code

        assert _matched_proxy_status_code(str(tmpdir), [502]) is None

    @pytest.mark.unit
    def test_empty_requests_json(self, tmpdir):
        from phishkit import _matched_proxy_status_code

        output_dir = str(tmpdir)
        with open(os.path.join(output_dir, "requests.json"), "w") as f:
            json.dump([], f)

        assert _matched_proxy_status_code(output_dir, [502]) is None

    @pytest.mark.unit
    def test_empty_status_codes_list(self, tmpdir):
        from phishkit import _matched_proxy_status_code

        assert _matched_proxy_status_code(str(tmpdir), []) is None

    @pytest.mark.unit
    def test_only_checks_first_response(self, tmpdir):
        from phishkit import _matched_proxy_status_code

        output_dir = str(tmpdir)
        requests_data = [
            {"type": "request", "url": "https://example.com", "requestId": "1"},
            {"type": "response", "url": "https://example.com", "requestId": "1", "status_code": 200},
            {"type": "response", "url": "https://cdn.example.com/bad", "requestId": "2", "status_code": 502},
        ]
        with open(os.path.join(output_dir, "requests.json"), "w") as f:
            json.dump(requests_data, f)

        assert _matched_proxy_status_code(output_dir, [502]) is None


# ---------------------------------------------------------------------------
# _sanitize_proxy_for_display
# ---------------------------------------------------------------------------

class TestSanitizeProxyForDisplay:

    @pytest.mark.unit
    def test_none_returns_none(self):
        from phishkit import _sanitize_proxy_for_display

        assert _sanitize_proxy_for_display(None) is None

    @pytest.mark.unit
    def test_empty_returns_none(self):
        from phishkit import _sanitize_proxy_for_display

        assert _sanitize_proxy_for_display("") is None

    @pytest.mark.unit
    def test_no_credentials_passthrough(self):
        from phishkit import _sanitize_proxy_for_display

        assert _sanitize_proxy_for_display("socks5://gate.example:1080") == "socks5://gate.example:1080"
        assert _sanitize_proxy_for_display("proxy.example:8080") == "proxy.example:8080"

    @pytest.mark.unit
    def test_strips_credentials_with_scheme(self):
        from phishkit import _sanitize_proxy_for_display

        assert _sanitize_proxy_for_display(
            "socks5://user:p@ss@gate.example:1080"
        ) == "socks5://gate.example:1080"

    @pytest.mark.unit
    def test_strips_credentials_without_scheme(self):
        from phishkit import _sanitize_proxy_for_display

        assert _sanitize_proxy_for_display("user:pass@gate.example:1080") == "gate.example:1080"


# ---------------------------------------------------------------------------
# _sync_config
# ---------------------------------------------------------------------------

class TestSyncConfig:

    @pytest.mark.unit
    def test_sync_config_valid_file(self, tmpdir, monkeypatch):
        import phishkit as phishkit_mod

        source = str(tmpdir.join("source_config.yaml"))
        with open(source, "w") as f:
            f.write("test: true\n")

        dest_dir = str(tmpdir.join("shared"))
        dest_path = os.path.join(dest_dir, "phishkit_config.yaml")
        monkeypatch.setattr(phishkit_mod, "SHARED_CONFIG", dest_path)

        result = phishkit_mod._sync_config(source)
        assert result == dest_path
        assert os.path.isfile(dest_path)

    @pytest.mark.unit
    def test_sync_config_none_path(self):
        from phishkit import _sync_config

        assert _sync_config(None) is None

    @pytest.mark.unit
    def test_sync_config_nonexistent_path(self):
        from phishkit import _sync_config

        assert _sync_config("/nonexistent/config.yaml") is None

    @pytest.mark.unit
    def test_sync_config_copy_failure(self, tmpdir, monkeypatch):
        import phishkit as phishkit_mod

        source = str(tmpdir.join("source.yaml"))
        with open(source, "w") as f:
            f.write("test: true\n")

        dest_path = str(tmpdir.join("shared", "config.yaml"))
        monkeypatch.setattr(phishkit_mod, "SHARED_CONFIG", dest_path)
        monkeypatch.setattr(shutil, "copy2", MagicMock(side_effect=PermissionError("denied")))

        result = phishkit_mod._sync_config(source)
        assert result is None


# ---------------------------------------------------------------------------
# _run_scanner
# ---------------------------------------------------------------------------

class TestRunScanner:

    def _make_mock_process(self, stdout="", stderr="", returncode=0):
        proc = MagicMock()
        proc.communicate.return_value = (stdout, stderr)
        proc.returncode = returncode
        proc.kill = MagicMock()
        proc.wait = MagicMock()
        return proc

    def _write_config(self, tmpdir, config_data=None):
        """Write a YAML config file and return its absolute path.

        Passing an absolute path as config_path causes os.path.join("/opt/ace", abs)
        to return the absolute path unchanged, so the real file is read.
        """
        if config_data is None:
            config_data = FULL_CONFIG
        config_file = tmpdir.join("phishkit_config.yaml")
        config_file.write(yaml.dump(config_data))
        return str(config_file)

    @pytest.mark.unit
    @patch("phishkit._force_stop_container")
    @patch("phishkit._sync_config", return_value=None)
    def test_run_scanner_successful(self, mock_sync, mock_force_stop, tmpdir):
        from phishkit import _run_scanner

        config_path = self._write_config(tmpdir)
        output_dir = str(tmpdir.join("output"))
        os.makedirs(output_dir)

        proc = self._make_mock_process(stdout="scan complete", stderr="", returncode=0)
        with patch("phishkit.Popen", return_value=proc):
            stdout, stderr, rc = _run_scanner(
                target_args=["https://example.com"],
                output_dir=output_dir,
                job_id="test-job",
                timeout=30,
                proxy=None,
                proxy_fallback_to_direct=False,
                config_path=config_path,
            )

        assert stdout == "scan complete"
        assert rc == 0
        assert os.path.isfile(os.path.join(output_dir, "std.out"))
        assert os.path.isfile(os.path.join(output_dir, "std.err"))
        assert os.path.isfile(os.path.join(output_dir, "exit.code"))

        with open(os.path.join(output_dir, "exit.code")) as f:
            assert f.read() == "0"

        # no proxy configured — proxy.json records final_route=none
        with open(os.path.join(output_dir, "proxy.json")) as f:
            proxy_status = json.load(f)
        assert proxy_status["configured"] is False
        assert proxy_status["fallback_triggered"] is False
        assert proxy_status["fallback_reason"] is None
        assert proxy_status["final_route"] == "none"
        assert proxy_status["host"] is None

        # finally-block cleanup always attempts to stop the container, even on success
        mock_force_stop.assert_called_with("phishkit-scan-test-job")

    @pytest.mark.unit
    @patch("phishkit._force_stop_container")
    @patch("phishkit._sync_config", return_value=None)
    def test_run_scanner_timeout_no_proxy_raises(self, mock_sync, mock_force_stop, tmpdir):
        """Timeout without proxy kills the container then raises TimeoutExpired."""
        from phishkit import _run_scanner

        config_path = self._write_config(tmpdir)
        output_dir = str(tmpdir.join("output"))
        os.makedirs(output_dir)

        proc = MagicMock()
        # first communicate call raises; second (post-kill) returns output
        proc.communicate.side_effect = [
            TimeoutExpired(cmd="docker", timeout=10),
            ("", ""),
        ]
        proc.kill = MagicMock()
        proc.wait = MagicMock()

        with patch("phishkit.Popen", return_value=proc):
            with pytest.raises(TimeoutExpired):
                _run_scanner(
                    target_args=["https://example.com"],
                    output_dir=output_dir,
                    job_id="test-job",
                    timeout=10,
                    proxy=None,
                    proxy_fallback_to_direct=False,
                    config_path=config_path,
                )
        # the fix: container must be docker-killed on timeout
        mock_force_stop.assert_any_call("phishkit-scan-test-job")

    @pytest.mark.unit
    @patch("phishkit._force_stop_container")
    @patch("phishkit._sync_config", return_value=None)
    def test_run_scanner_timeout_with_proxy_retries(self, mock_sync, mock_force_stop, tmpdir):
        """Timeout with proxy + fallback enabled retries without proxy."""
        from phishkit import _run_scanner

        config_path = self._write_config(tmpdir)
        output_dir = str(tmpdir.join("output"))
        os.makedirs(output_dir)

        direct_proc = self._make_mock_process(stdout="scan complete", stderr="", returncode=0)

        call_count = 0

        def popen_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                proc = MagicMock()
                proc.communicate.side_effect = [
                    TimeoutExpired(cmd="docker", timeout=10),
                    ("", ""),
                ]
                proc.kill = MagicMock()
                proc.wait = MagicMock()
                return proc
            return direct_proc

        with patch("phishkit.Popen", side_effect=popen_side_effect):
            stdout, stderr, rc = _run_scanner(
                target_args=["https://example.com"],
                output_dir=output_dir,
                job_id="test-job",
                timeout=10,
                proxy="http://proxy:8080",
                proxy_fallback_to_direct=True,
                config_path=config_path,
            )

        assert call_count == 2
        assert "PROXY ATTEMPT (timed out, retried direct)" in stdout
        assert "DIRECT ATTEMPT" in stdout
        assert rc == 0

        with open(os.path.join(output_dir, "proxy.json")) as f:
            proxy_status = json.load(f)
        assert proxy_status["configured"] is True
        assert proxy_status["host"] == "http://proxy:8080"
        assert proxy_status["fallback_enabled"] is True
        assert proxy_status["fallback_triggered"] is True
        assert proxy_status["fallback_reason"] == "timeout"
        assert proxy_status["final_route"] == "direct"

    @pytest.mark.unit
    @patch("phishkit._force_stop_container")
    @patch("phishkit._sync_config", return_value=None)
    def test_run_scanner_timeout_retry_disabled_raises(self, mock_sync, mock_force_stop, tmpdir):
        """Timeout with retry_on_timeout=False raises even with proxy."""
        from phishkit import _run_scanner

        config_path = self._write_config(tmpdir, {"proxy_fallback": {
            **FULL_PROXY_FALLBACK,
            "retry_on_timeout": False,
        }})
        output_dir = str(tmpdir.join("output"))
        os.makedirs(output_dir)

        proc = MagicMock()
        proc.communicate.side_effect = [
            TimeoutExpired(cmd="docker", timeout=10),
            ("", ""),
        ]
        proc.kill = MagicMock()
        proc.wait = MagicMock()

        with patch("phishkit.Popen", return_value=proc):
            with pytest.raises(TimeoutExpired):
                _run_scanner(
                    target_args=["https://example.com"],
                    output_dir=output_dir,
                    job_id="test-job",
                    timeout=10,
                    proxy="http://proxy:8080",
                    proxy_fallback_to_direct=True,
                    config_path=config_path,
                )

    @pytest.mark.unit
    @patch("phishkit._force_stop_container")
    @patch("phishkit._sync_config", return_value=None)
    def test_run_scanner_proxy_fallback(self, mock_sync, mock_force_stop, tmpdir):
        from phishkit import _run_scanner

        config_path = self._write_config(tmpdir)
        output_dir = str(tmpdir.join("output"))
        os.makedirs(output_dir)

        # first call has proxy error, second succeeds
        proxy_proc = self._make_mock_process(
            stdout="ERR_TUNNEL_CONNECTION_FAILED", stderr="", returncode=1
        )
        direct_proc = self._make_mock_process(
            stdout="scan complete", stderr="", returncode=0
        )

        call_count = 0

        def popen_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return proxy_proc
            return direct_proc

        with patch("phishkit.Popen", side_effect=popen_side_effect):
            stdout, stderr, rc = _run_scanner(
                target_args=["https://example.com"],
                output_dir=output_dir,
                job_id="test-job",
                timeout=30,
                proxy="http://proxy:8080",
                proxy_fallback_to_direct=True,
                config_path=config_path,
            )

        assert call_count == 2
        assert "PROXY ATTEMPT (failed, retried direct)" in stdout
        assert "DIRECT ATTEMPT" in stdout
        assert rc == 0

        with open(os.path.join(output_dir, "proxy.json")) as f:
            proxy_status = json.load(f)
        assert proxy_status["fallback_triggered"] is True
        assert proxy_status["fallback_reason"] == "error_pattern"
        assert proxy_status["fallback_details"]["matched_error_patterns"] == [
            "ERR_TUNNEL_CONNECTION_FAILED",
        ]
        assert proxy_status["final_route"] == "direct"

    @pytest.mark.unit
    @patch("phishkit._force_stop_container")
    @patch("phishkit._sync_config", return_value=None)
    def test_run_scanner_proxy_status_code_fallback(self, mock_sync, mock_force_stop, tmpdir):
        """Proxy error status code in requests.json triggers retry."""
        from phishkit import _run_scanner

        config_path = self._write_config(tmpdir)
        output_dir = str(tmpdir.join("output"))
        os.makedirs(output_dir)

        # write requests.json with a 502 main page response
        requests_data = [
            {"type": "request", "url": "https://example.com", "requestId": "1"},
            {"type": "response", "url": "https://example.com", "requestId": "1", "status_code": 502},
        ]
        with open(os.path.join(output_dir, "requests.json"), "w") as f:
            json.dump(requests_data, f)

        proxy_proc = self._make_mock_process(stdout="proxy page", stderr="", returncode=0)
        direct_proc = self._make_mock_process(stdout="scan complete", stderr="", returncode=0)

        call_count = 0

        def popen_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return proxy_proc
            return direct_proc

        with patch("phishkit.Popen", side_effect=popen_side_effect):
            stdout, stderr, rc = _run_scanner(
                target_args=["https://example.com"],
                output_dir=output_dir,
                job_id="test-job",
                timeout=30,
                proxy="http://proxy:8080",
                proxy_fallback_to_direct=True,
                config_path=config_path,
            )

        assert call_count == 2
        assert "PROXY ATTEMPT (failed, retried direct)" in stdout
        assert rc == 0

        with open(os.path.join(output_dir, "proxy.json")) as f:
            proxy_status = json.load(f)
        assert proxy_status["fallback_triggered"] is True
        assert proxy_status["fallback_reason"] == "status_code"
        assert proxy_status["fallback_details"]["matched_status_code"] == 502
        assert proxy_status["final_route"] == "direct"

    @pytest.mark.unit
    @patch("phishkit._force_stop_container")
    @patch("phishkit._sync_config", return_value=None)
    def test_run_scanner_proxy_no_fallback(self, mock_sync, mock_force_stop, tmpdir):
        from phishkit import _run_scanner

        config_path = self._write_config(tmpdir)
        output_dir = str(tmpdir.join("output"))
        os.makedirs(output_dir)

        proc = self._make_mock_process(
            stdout="ERR_TUNNEL_CONNECTION_FAILED", stderr="", returncode=1
        )

        with patch("phishkit.Popen", return_value=proc) as mock_popen:
            _run_scanner(
                target_args=["https://example.com"],
                output_dir=output_dir,
                job_id="test-job",
                timeout=30,
                proxy="http://proxy:8080",
                proxy_fallback_to_direct=False,
                config_path=config_path,
            )

        # should only be called once (no retry)
        assert mock_popen.call_count == 1

        # proxy was configured but fallback disabled — final_route stays "proxy"
        with open(os.path.join(output_dir, "proxy.json")) as f:
            proxy_status = json.load(f)
        assert proxy_status["configured"] is True
        assert proxy_status["fallback_enabled"] is False
        assert proxy_status["fallback_triggered"] is False
        assert proxy_status["fallback_reason"] is None
        assert proxy_status["final_route"] == "proxy"

    @pytest.mark.unit
    @patch("phishkit._force_stop_container")
    @patch("phishkit._sync_config", return_value="/phishkit/config/phishkit_config.yaml")
    def test_run_scanner_with_config(self, mock_sync, mock_force_stop, tmpdir):
        from phishkit import _run_scanner

        config_path = self._write_config(tmpdir)
        output_dir = str(tmpdir.join("output"))
        os.makedirs(output_dir)

        proc = self._make_mock_process(stdout="ok", stderr="", returncode=0)

        with patch("phishkit.Popen", return_value=proc) as mock_popen:
            _run_scanner(
                target_args=["https://example.com"],
                output_dir=output_dir,
                job_id="test-job",
                timeout=30,
                proxy=None,
                proxy_fallback_to_direct=False,
                config_path=config_path,
            )

        cmd = mock_popen.call_args[0][0]
        assert "--config" in cmd
        assert "/phishkit/config/phishkit_config.yaml" in cmd

    @pytest.mark.unit
    @patch("phishkit._force_stop_container")
    @patch("phishkit._sync_config", return_value=None)
    def test_run_scanner_output_files_content(self, mock_sync, mock_force_stop, tmpdir):
        from phishkit import _run_scanner

        config_path = self._write_config(tmpdir)
        output_dir = str(tmpdir.join("output"))
        os.makedirs(output_dir)

        proc = self._make_mock_process(stdout="hello stdout", stderr="hello stderr", returncode=42)

        with patch("phishkit.Popen", return_value=proc):
            _run_scanner(
                target_args=["https://example.com"],
                output_dir=output_dir,
                job_id="test-job",
                timeout=30,
                proxy=None,
                proxy_fallback_to_direct=False,
                config_path=config_path,
            )

        with open(os.path.join(output_dir, "std.out")) as f:
            assert f.read() == "hello stdout"
        with open(os.path.join(output_dir, "std.err")) as f:
            assert f.read() == "hello stderr"
        with open(os.path.join(output_dir, "exit.code")) as f:
            assert f.read() == "42"


# ---------------------------------------------------------------------------
# _correct_file_extension
# ---------------------------------------------------------------------------

class TestCorrectFileExtension:

    @pytest.mark.unit
    def test_correct_file_extension_already_correct(self, tmpdir):
        from phishkit import _correct_file_extension

        file_path = str(tmpdir.join("page.html"))
        with open(file_path, "w") as f:
            f.write("<html></html>")

        with patch("phishkit.magic") as mock_magic:
            mock_magic.from_file.return_value = "text/html"
            result = _correct_file_extension(file_path)

        assert result == file_path

    @pytest.mark.unit
    def test_correct_file_extension_needs_correction(self, tmpdir):
        from phishkit import _correct_file_extension

        file_path = str(tmpdir.join("page.txt"))
        with open(file_path, "w") as f:
            f.write("<html></html>")

        with patch("phishkit.magic") as mock_magic:
            mock_magic.from_file.return_value = "text/html"
            result = _correct_file_extension(file_path)

        assert result.endswith(".html")
        assert not os.path.exists(file_path)

    @pytest.mark.unit
    def test_correct_file_extension_no_mime(self, tmpdir):
        from phishkit import _correct_file_extension

        file_path = str(tmpdir.join("mystery"))
        with open(file_path, "w") as f:
            f.write("data")

        with patch("phishkit.magic") as mock_magic:
            mock_magic.from_file.return_value = None
            result = _correct_file_extension(file_path)

        assert result == file_path

    @pytest.mark.unit
    def test_correct_file_extension_no_extension_guess(self, tmpdir):
        from phishkit import _correct_file_extension

        file_path = str(tmpdir.join("file.bin"))
        with open(file_path, "w") as f:
            f.write("data")

        with patch("phishkit.magic") as mock_magic, \
             patch("phishkit.mimetypes") as mock_mimetypes:
            mock_magic.from_file.return_value = "application/x-custom"
            mock_mimetypes.guess_extension.return_value = None
            result = _correct_file_extension(file_path)

        assert result == file_path


# ---------------------------------------------------------------------------
# Celery tasks: scan_url, scan_file
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Container resource-limit / reaper helpers
# ---------------------------------------------------------------------------

class TestBuildCmdArgs:

    @pytest.mark.unit
    @patch("phishkit._force_stop_container")
    @patch("phishkit._sync_config", return_value=None)
    def test_docker_run_includes_resource_limits_and_labels(self, mock_sync, mock_force_stop, tmpdir):
        """The docker run subprocess must include --memory, --init, --name, and labels."""
        from phishkit import _run_scanner

        config_data = {
            "proxy_fallback": FULL_PROXY_FALLBACK,
            "resource_limits": {
                "container_memory": "1g",
                "container_cpus": "1.5",
                "reaper_max_age_seconds": 600,
                "reaper_interval_seconds": 60,
                "scanner_timeout_hint": 15,
            },
        }
        config_file = tmpdir.join("phishkit_config.yaml")
        config_file.write(yaml.dump(config_data))

        output_dir = str(tmpdir.join("output"))
        os.makedirs(output_dir)

        proc = MagicMock()
        proc.communicate.return_value = ("ok", "")
        proc.returncode = 0

        with patch("phishkit.Popen", return_value=proc) as mock_popen:
            _run_scanner(
                target_args=["https://example.com"],
                output_dir=output_dir,
                job_id="abc-123",
                timeout=30,
                proxy=None,
                proxy_fallback_to_direct=False,
                config_path=str(config_file),
            )

        cmd = mock_popen.call_args[0][0]
        assert cmd[0] == "docker"
        assert "--init" in cmd
        assert "--rm" in cmd
        assert "--name" in cmd
        assert "phishkit-scan-abc-123" in cmd
        assert "--memory" in cmd
        # --memory and --memory-swap must both be 1g
        mem_idx = cmd.index("--memory")
        assert cmd[mem_idx + 1] == "1g"
        memswap_idx = cmd.index("--memory-swap")
        assert cmd[memswap_idx + 1] == "1g"
        assert "--cpus" in cmd
        assert cmd[cmd.index("--cpus") + 1] == "1.5"
        # label with job_id must be present
        label_vals = [cmd[i + 1] for i, v in enumerate(cmd) if v == "--label"]
        assert any(lv == "phishkit.job_id=abc-123" for lv in label_vals)
        assert any(lv.startswith("phishkit.worker=") for lv in label_vals)
        assert any(lv.startswith("phishkit.started_at=") for lv in label_vals)


class TestForceStopContainer:

    @pytest.mark.unit
    def test_force_stop_runs_docker_kill_and_rm(self):
        from phishkit import _force_stop_container
        with patch("phishkit.subprocess.run") as mock_run:
            _force_stop_container("phishkit-scan-xyz")
        cmds = [call.args[0] for call in mock_run.call_args_list]
        assert ["docker", "kill", "phishkit-scan-xyz"] in cmds
        assert ["docker", "rm", "-f", "phishkit-scan-xyz"] in cmds

    @pytest.mark.unit
    def test_force_stop_swallows_exceptions(self):
        """Must not raise even if docker CLI is unavailable."""
        from phishkit import _force_stop_container
        with patch("phishkit.subprocess.run", side_effect=FileNotFoundError("no docker")):
            _force_stop_container("phishkit-scan-xyz")  # should not raise


class TestReapOrphans:

    def _mock_docker_ps(self, containers):
        """Build a fake `docker ps` stdout from a list of container dicts."""
        lines = [
            f"{c['id']}|{c['name']}|{c['started_at']}|{c['worker']}"
            for c in containers
        ]
        result = MagicMock()
        result.stdout = "\n".join(lines) + ("\n" if lines else "")
        return result

    @pytest.mark.unit
    def test_reap_orphans_kills_old_containers(self):
        import phishkit
        from phishkit import _reap_orphans

        old = {"id": "a", "name": "phishkit-scan-old", "started_at": 100, "worker": "h1"}
        young = {"id": "b", "name": "phishkit-scan-young", "started_at": 9_999_999_999, "worker": "h1"}

        with patch("phishkit.subprocess.run", return_value=self._mock_docker_ps([old, young])), \
             patch("phishkit._force_stop_container") as mock_force, \
             patch("phishkit.time.time", return_value=10_000):
            killed = _reap_orphans(max_age_seconds=60)

        assert killed == 1
        mock_force.assert_called_once_with("phishkit-scan-old")

    @pytest.mark.unit
    def test_reap_orphans_only_this_worker_filters(self):
        from phishkit import _reap_orphans
        this_host = __import__("socket").gethostname()

        mine = {"id": "a", "name": "phishkit-scan-mine", "started_at": 0, "worker": this_host}
        theirs = {"id": "b", "name": "phishkit-scan-theirs", "started_at": 0, "worker": "other-host"}

        with patch("phishkit.subprocess.run",
                   return_value=TestReapOrphans()._mock_docker_ps([mine, theirs])), \
             patch("phishkit._force_stop_container") as mock_force, \
             patch("phishkit.time.time", return_value=1_000_000):
            killed = _reap_orphans(max_age_seconds=0, only_this_worker=True)

        assert killed == 1
        mock_force.assert_called_once_with("phishkit-scan-mine")

    @pytest.mark.unit
    def test_reap_orphans_empty_ps(self):
        from phishkit import _reap_orphans
        result = MagicMock()
        result.stdout = ""
        with patch("phishkit.subprocess.run", return_value=result), \
             patch("phishkit._force_stop_container") as mock_force:
            killed = _reap_orphans(max_age_seconds=60)
        assert killed == 0
        mock_force.assert_not_called()


class TestLoadResourceLimits:

    @pytest.mark.unit
    def test_load_resource_limits_uses_defaults_when_missing(self, tmpdir):
        from phishkit import _load_resource_limits, DEFAULT_RESOURCE_LIMITS
        cfg = _load_resource_limits(str(tmpdir.join("nonexistent.yaml")))
        assert cfg == DEFAULT_RESOURCE_LIMITS

    @pytest.mark.unit
    def test_load_resource_limits_merges_user_values(self, tmpdir):
        from phishkit import _load_resource_limits, DEFAULT_RESOURCE_LIMITS
        path = tmpdir.join("c.yaml")
        path.write(yaml.dump({"resource_limits": {"container_memory": "4g"}}))
        cfg = _load_resource_limits(str(path))
        assert cfg["container_memory"] == "4g"
        assert cfg["container_cpus"] == DEFAULT_RESOURCE_LIMITS["container_cpus"]

    @pytest.mark.unit
    def test_load_resource_limits_ignores_unknown_keys(self, tmpdir):
        from phishkit import _load_resource_limits
        path = tmpdir.join("c.yaml")
        path.write(yaml.dump({"resource_limits": {"bogus": "drop"}}))
        cfg = _load_resource_limits(str(path))
        assert "bogus" not in cfg


class TestScanUrl:

    @pytest.mark.unit
    @patch("phishkit._process_output", return_value="/phishkit/output/job-1")
    @patch("phishkit._run_scanner", return_value=("ok", "", 0))
    @patch("phishkit.os.makedirs")
    @patch("phishkit.uuid.uuid4", return_value="job-1")
    def test_scan_url_success(self, mock_uuid, mock_makedirs, mock_run, mock_process):
        from phishkit import scan_url

        result = scan_url("https://example.com", timeout=15)
        mock_run.assert_called_once()
        assert result == "/phishkit/output/job-1"

    @pytest.mark.unit
    @patch("phishkit._run_scanner", return_value=("", "error occurred", 1))
    @patch("phishkit.os.makedirs")
    @patch("phishkit.uuid.uuid4", return_value="job-1")
    def test_scan_url_nonzero_exit(self, mock_uuid, mock_makedirs, mock_run):
        from phishkit import scan_url

        with pytest.raises(Exception, match="scan failed"):
            scan_url("https://example.com", timeout=15)


class TestScanFile:

    @pytest.mark.unit
    @patch("phishkit._process_output", return_value="/phishkit/output/job-1")
    @patch("phishkit._run_scanner", return_value=("ok", "", 0))
    @patch("phishkit._correct_file_extension", side_effect=lambda p: p)
    @patch("phishkit.shutil.copy2")
    @patch("phishkit.os.makedirs")
    @patch("phishkit.uuid.uuid4", return_value="job-1")
    def test_scan_file_success(self, mock_uuid, mock_makedirs, mock_copy,
                               mock_correct, mock_run, mock_process):
        from phishkit import scan_file

        result = scan_file("/some/path/malware.html", timeout=15)
        mock_run.assert_called_once()
        # verify --file is in the target_args
        run_call = mock_run.call_args
        assert "--file" in run_call.kwargs["target_args"]
        assert result == "/phishkit/output/job-1"
