import json
import os
import shutil
from subprocess import TimeoutExpired
from unittest.mock import MagicMock, patch, call

import pytest


FULL_FALLBACK_CONFIG = {
    "error_patterns": [
        "ERR_TUNNEL_CONNECTION_FAILED",
        "ERR_PROXY_CONNECTION_FAILED",
        "ERR_PROXY_AUTH_FAILED",
        "ERR_PROXY_CERTIFICATE_INVALID",
    ],
    "proxy_status_codes": [400, 403, 407, 500, 502, 504, 522],
    "retry_on_timeout": True,
}

EMPTY_FALLBACK_CONFIG = {
    "error_patterns": [],
    "proxy_status_codes": [],
    "retry_on_timeout": False,
}


# ---------------------------------------------------------------------------
# _load_proxy_fallback_config
# ---------------------------------------------------------------------------

class TestLoadProxyFallbackConfig:

    @pytest.mark.unit
    def test_returns_empty_when_no_path(self):
        from phishkit.phishkit import _load_proxy_fallback_config

        result = _load_proxy_fallback_config(None)
        assert result == EMPTY_FALLBACK_CONFIG

    @pytest.mark.unit
    def test_returns_empty_when_file_missing(self):
        from phishkit.phishkit import _load_proxy_fallback_config

        result = _load_proxy_fallback_config("/nonexistent/config.yaml")
        assert result == EMPTY_FALLBACK_CONFIG

    @pytest.mark.unit
    def test_loads_full_config(self, tmpdir):
        from phishkit.phishkit import _load_proxy_fallback_config

        config = tmpdir.join("config.yaml")
        config.write(
            "proxy_fallback:\n"
            "  error_patterns:\n"
            '    - "CUSTOM_ERROR"\n'
            "  proxy_status_codes:\n"
            "    - 999\n"
            "  retry_on_timeout: false\n"
        )
        result = _load_proxy_fallback_config(str(config))
        assert result["error_patterns"] == ["CUSTOM_ERROR"]
        assert result["proxy_status_codes"] == [999]
        assert result["retry_on_timeout"] is False

    @pytest.mark.unit
    def test_partial_config_defaults_missing_keys(self, tmpdir):
        from phishkit.phishkit import _load_proxy_fallback_config

        config = tmpdir.join("config.yaml")
        config.write(
            "proxy_fallback:\n"
            "  retry_on_timeout: true\n"
        )
        result = _load_proxy_fallback_config(str(config))
        assert result["error_patterns"] == []
        assert result["proxy_status_codes"] == []
        assert result["retry_on_timeout"] is True

    @pytest.mark.unit
    def test_no_proxy_fallback_section(self, tmpdir):
        from phishkit.phishkit import _load_proxy_fallback_config

        config = tmpdir.join("config.yaml")
        config.write("skip_body_extensions:\n  - .png\n")
        result = _load_proxy_fallback_config(str(config))
        assert result == EMPTY_FALLBACK_CONFIG


# ---------------------------------------------------------------------------
# _has_proxy_error
# ---------------------------------------------------------------------------


class TestHasProxyError:

    @pytest.mark.unit
    @pytest.mark.parametrize("pattern", [
        "ERR_TUNNEL_CONNECTION_FAILED",
        "ERR_PROXY_CONNECTION_FAILED",
        "ERR_PROXY_AUTH_FAILED",
        "ERR_PROXY_CERTIFICATE_INVALID",
    ])
    def test_has_proxy_error_each_pattern(self, pattern):
        from phishkit.phishkit import _has_proxy_error
        patterns = FULL_FALLBACK_CONFIG["error_patterns"]

        assert _has_proxy_error(f"some output {pattern} here", "", patterns) is True

    @pytest.mark.unit
    def test_has_proxy_error_no_match(self):
        from phishkit.phishkit import _has_proxy_error
        patterns = FULL_FALLBACK_CONFIG["error_patterns"]

        assert _has_proxy_error("all good", "no errors", patterns) is False

    @pytest.mark.unit
    def test_has_proxy_error_none_inputs(self):
        from phishkit.phishkit import _has_proxy_error
        patterns = FULL_FALLBACK_CONFIG["error_patterns"]

        assert _has_proxy_error(None, None, patterns) is False

    @pytest.mark.unit
    def test_has_proxy_error_in_stderr_only(self):
        from phishkit.phishkit import _has_proxy_error
        patterns = FULL_FALLBACK_CONFIG["error_patterns"]

        assert _has_proxy_error("", "ERR_TUNNEL_CONNECTION_FAILED", patterns) is True

    @pytest.mark.unit
    def test_has_proxy_error_custom_patterns(self):
        from phishkit.phishkit import _has_proxy_error

        assert _has_proxy_error("CUSTOM_ERR occurred", "", ["CUSTOM_ERR"]) is True
        assert _has_proxy_error("CUSTOM_ERR occurred", "", ["OTHER_ERR"]) is False


# ---------------------------------------------------------------------------
# _has_proxy_status_code
# ---------------------------------------------------------------------------

class TestHasProxyStatusCode:

    @pytest.mark.unit
    def test_matching_status_code(self, tmpdir):
        from phishkit.phishkit import _has_proxy_status_code

        output_dir = str(tmpdir)
        requests_data = [
            {"type": "request", "url": "https://example.com", "requestId": "1"},
            {"type": "response", "url": "https://example.com", "requestId": "1", "status_code": 502},
        ]
        with open(os.path.join(output_dir, "requests.json"), "w") as f:
            json.dump(requests_data, f)

        assert _has_proxy_status_code(output_dir, [502, 504]) is True

    @pytest.mark.unit
    def test_non_matching_status_code(self, tmpdir):
        from phishkit.phishkit import _has_proxy_status_code

        output_dir = str(tmpdir)
        requests_data = [
            {"type": "request", "url": "https://example.com", "requestId": "1"},
            {"type": "response", "url": "https://example.com", "requestId": "1", "status_code": 200},
        ]
        with open(os.path.join(output_dir, "requests.json"), "w") as f:
            json.dump(requests_data, f)

        assert _has_proxy_status_code(output_dir, [502, 504]) is False

    @pytest.mark.unit
    def test_missing_requests_json(self, tmpdir):
        from phishkit.phishkit import _has_proxy_status_code

        assert _has_proxy_status_code(str(tmpdir), [502]) is False

    @pytest.mark.unit
    def test_empty_requests_json(self, tmpdir):
        from phishkit.phishkit import _has_proxy_status_code

        output_dir = str(tmpdir)
        with open(os.path.join(output_dir, "requests.json"), "w") as f:
            json.dump([], f)

        assert _has_proxy_status_code(output_dir, [502]) is False

    @pytest.mark.unit
    def test_empty_status_codes_list(self, tmpdir):
        from phishkit.phishkit import _has_proxy_status_code

        assert _has_proxy_status_code(str(tmpdir), []) is False

    @pytest.mark.unit
    def test_only_checks_first_response(self, tmpdir):
        from phishkit.phishkit import _has_proxy_status_code

        output_dir = str(tmpdir)
        requests_data = [
            {"type": "request", "url": "https://example.com", "requestId": "1"},
            {"type": "response", "url": "https://example.com", "requestId": "1", "status_code": 200},
            {"type": "response", "url": "https://cdn.example.com/bad", "requestId": "2", "status_code": 502},
        ]
        with open(os.path.join(output_dir, "requests.json"), "w") as f:
            json.dump(requests_data, f)

        assert _has_proxy_status_code(output_dir, [502]) is False


# ---------------------------------------------------------------------------
# _sync_config
# ---------------------------------------------------------------------------

class TestSyncConfig:

    @pytest.mark.unit
    def test_sync_config_valid_file(self, tmpdir, monkeypatch):
        import phishkit.phishkit as phishkit_mod

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
        from phishkit.phishkit import _sync_config

        assert _sync_config(None) is None

    @pytest.mark.unit
    def test_sync_config_nonexistent_path(self):
        from phishkit.phishkit import _sync_config

        assert _sync_config("/nonexistent/config.yaml") is None

    @pytest.mark.unit
    def test_sync_config_copy_failure(self, tmpdir, monkeypatch):
        import phishkit.phishkit as phishkit_mod

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

    @pytest.mark.unit
    @patch("phishkit.phishkit._load_proxy_fallback_config", return_value=FULL_FALLBACK_CONFIG)
    @patch("phishkit.phishkit._sync_config", return_value=None)
    def test_run_scanner_successful(self, mock_sync, mock_cfg, tmpdir):
        from phishkit.phishkit import _run_scanner

        output_dir = str(tmpdir.join("output"))
        os.makedirs(output_dir)

        proc = self._make_mock_process(stdout="scan complete", stderr="", returncode=0)
        with patch("phishkit.phishkit.Popen", return_value=proc):
            stdout, stderr, rc = _run_scanner(
                target_args=["https://example.com"],
                output_dir=output_dir,
                job_id="test-job",
                timeout=30,
                proxy=None,
                proxy_fallback_to_direct=False,
            )

        assert stdout == "scan complete"
        assert rc == 0
        assert os.path.isfile(os.path.join(output_dir, "std.out"))
        assert os.path.isfile(os.path.join(output_dir, "std.err"))
        assert os.path.isfile(os.path.join(output_dir, "exit.code"))

        with open(os.path.join(output_dir, "exit.code")) as f:
            assert f.read() == "0"

    @pytest.mark.unit
    @patch("phishkit.phishkit._load_proxy_fallback_config", return_value=FULL_FALLBACK_CONFIG)
    @patch("phishkit.phishkit._sync_config", return_value=None)
    def test_run_scanner_timeout_no_proxy_raises(self, mock_sync, mock_cfg, tmpdir):
        """Timeout without proxy still raises TimeoutExpired."""
        from phishkit.phishkit import _run_scanner

        output_dir = str(tmpdir.join("output"))
        os.makedirs(output_dir)

        proc = MagicMock()
        proc.communicate.side_effect = TimeoutExpired(cmd="docker", timeout=10)
        proc.kill = MagicMock()
        proc.wait = MagicMock()

        with patch("phishkit.phishkit.Popen", return_value=proc):
            with pytest.raises(TimeoutExpired):
                _run_scanner(
                    target_args=["https://example.com"],
                    output_dir=output_dir,
                    job_id="test-job",
                    timeout=10,
                    proxy=None,
                    proxy_fallback_to_direct=False,
                )
        proc.kill.assert_called_once()

    @pytest.mark.unit
    @patch("phishkit.phishkit._load_proxy_fallback_config", return_value=FULL_FALLBACK_CONFIG)
    @patch("phishkit.phishkit._sync_config", return_value=None)
    def test_run_scanner_timeout_with_proxy_retries(self, mock_sync, mock_cfg, tmpdir):
        """Timeout with proxy + fallback enabled retries without proxy."""
        from phishkit.phishkit import _run_scanner

        output_dir = str(tmpdir.join("output"))
        os.makedirs(output_dir)

        direct_proc = self._make_mock_process(stdout="scan complete", stderr="", returncode=0)

        call_count = 0

        def popen_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                proc = MagicMock()
                proc.communicate.side_effect = TimeoutExpired(cmd="docker", timeout=10)
                proc.kill = MagicMock()
                proc.wait = MagicMock()
                return proc
            return direct_proc

        with patch("phishkit.phishkit.Popen", side_effect=popen_side_effect):
            stdout, stderr, rc = _run_scanner(
                target_args=["https://example.com"],
                output_dir=output_dir,
                job_id="test-job",
                timeout=10,
                proxy="http://proxy:8080",
                proxy_fallback_to_direct=True,
            )

        assert call_count == 2
        assert "PROXY ATTEMPT (timed out, retried direct)" in stdout
        assert "DIRECT ATTEMPT" in stdout
        assert rc == 0

    @pytest.mark.unit
    @patch("phishkit.phishkit._load_proxy_fallback_config", return_value={
        **FULL_FALLBACK_CONFIG,
        "retry_on_timeout": False,
    })
    @patch("phishkit.phishkit._sync_config", return_value=None)
    def test_run_scanner_timeout_retry_disabled_raises(self, mock_sync, mock_cfg, tmpdir):
        """Timeout with retry_on_timeout=False raises even with proxy."""
        from phishkit.phishkit import _run_scanner

        output_dir = str(tmpdir.join("output"))
        os.makedirs(output_dir)

        proc = MagicMock()
        proc.communicate.side_effect = TimeoutExpired(cmd="docker", timeout=10)
        proc.kill = MagicMock()
        proc.wait = MagicMock()

        with patch("phishkit.phishkit.Popen", return_value=proc):
            with pytest.raises(TimeoutExpired):
                _run_scanner(
                    target_args=["https://example.com"],
                    output_dir=output_dir,
                    job_id="test-job",
                    timeout=10,
                    proxy="http://proxy:8080",
                    proxy_fallback_to_direct=True,
                )

    @pytest.mark.unit
    @patch("phishkit.phishkit._load_proxy_fallback_config", return_value=FULL_FALLBACK_CONFIG)
    @patch("phishkit.phishkit._sync_config", return_value=None)
    def test_run_scanner_proxy_fallback(self, mock_sync, mock_cfg, tmpdir):
        from phishkit.phishkit import _run_scanner

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

        with patch("phishkit.phishkit.Popen", side_effect=popen_side_effect):
            stdout, stderr, rc = _run_scanner(
                target_args=["https://example.com"],
                output_dir=output_dir,
                job_id="test-job",
                timeout=30,
                proxy="http://proxy:8080",
                proxy_fallback_to_direct=True,
            )

        assert call_count == 2
        assert "PROXY ATTEMPT (failed, retried direct)" in stdout
        assert "DIRECT ATTEMPT" in stdout
        assert rc == 0

    @pytest.mark.unit
    @patch("phishkit.phishkit._load_proxy_fallback_config", return_value=FULL_FALLBACK_CONFIG)
    @patch("phishkit.phishkit._sync_config", return_value=None)
    def test_run_scanner_proxy_status_code_fallback(self, mock_sync, mock_cfg, tmpdir):
        """Proxy error status code in requests.json triggers retry."""
        from phishkit.phishkit import _run_scanner

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

        with patch("phishkit.phishkit.Popen", side_effect=popen_side_effect):
            stdout, stderr, rc = _run_scanner(
                target_args=["https://example.com"],
                output_dir=output_dir,
                job_id="test-job",
                timeout=30,
                proxy="http://proxy:8080",
                proxy_fallback_to_direct=True,
            )

        assert call_count == 2
        assert "PROXY ATTEMPT (failed, retried direct)" in stdout
        assert rc == 0

    @pytest.mark.unit
    @patch("phishkit.phishkit._load_proxy_fallback_config", return_value=FULL_FALLBACK_CONFIG)
    @patch("phishkit.phishkit._sync_config", return_value=None)
    def test_run_scanner_proxy_no_fallback(self, mock_sync, mock_cfg, tmpdir):
        from phishkit.phishkit import _run_scanner

        output_dir = str(tmpdir.join("output"))
        os.makedirs(output_dir)

        proc = self._make_mock_process(
            stdout="ERR_TUNNEL_CONNECTION_FAILED", stderr="", returncode=1
        )

        with patch("phishkit.phishkit.Popen", return_value=proc) as mock_popen:
            _run_scanner(
                target_args=["https://example.com"],
                output_dir=output_dir,
                job_id="test-job",
                timeout=30,
                proxy="http://proxy:8080",
                proxy_fallback_to_direct=False,
            )

        # should only be called once (no retry)
        assert mock_popen.call_count == 1

    @pytest.mark.unit
    @patch("phishkit.phishkit._load_proxy_fallback_config", return_value=FULL_FALLBACK_CONFIG)
    @patch("phishkit.phishkit._sync_config", return_value="/phishkit/config/phishkit_config.yaml")
    def test_run_scanner_with_config(self, mock_sync, mock_cfg, tmpdir):
        from phishkit.phishkit import _run_scanner

        output_dir = str(tmpdir.join("output"))
        os.makedirs(output_dir)

        proc = self._make_mock_process(stdout="ok", stderr="", returncode=0)

        with patch("phishkit.phishkit.Popen", return_value=proc) as mock_popen:
            _run_scanner(
                target_args=["https://example.com"],
                output_dir=output_dir,
                job_id="test-job",
                timeout=30,
                proxy=None,
                proxy_fallback_to_direct=False,
                config_path="etc/phishkit_config.yaml",
            )

        cmd = mock_popen.call_args[0][0]
        assert "--config" in cmd
        assert "/phishkit/config/phishkit_config.yaml" in cmd

    @pytest.mark.unit
    @patch("phishkit.phishkit._load_proxy_fallback_config", return_value=FULL_FALLBACK_CONFIG)
    @patch("phishkit.phishkit._sync_config", return_value=None)
    def test_run_scanner_output_files_content(self, mock_sync, mock_cfg, tmpdir):
        from phishkit.phishkit import _run_scanner

        output_dir = str(tmpdir.join("output"))
        os.makedirs(output_dir)

        proc = self._make_mock_process(stdout="hello stdout", stderr="hello stderr", returncode=42)

        with patch("phishkit.phishkit.Popen", return_value=proc):
            _run_scanner(
                target_args=["https://example.com"],
                output_dir=output_dir,
                job_id="test-job",
                timeout=30,
                proxy=None,
                proxy_fallback_to_direct=False,
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
        from phishkit.phishkit import _correct_file_extension

        file_path = str(tmpdir.join("page.html"))
        with open(file_path, "w") as f:
            f.write("<html></html>")

        with patch("phishkit.phishkit.magic") as mock_magic:
            mock_magic.from_file.return_value = "text/html"
            result = _correct_file_extension(file_path)

        assert result == file_path

    @pytest.mark.unit
    def test_correct_file_extension_needs_correction(self, tmpdir):
        from phishkit.phishkit import _correct_file_extension

        file_path = str(tmpdir.join("page.txt"))
        with open(file_path, "w") as f:
            f.write("<html></html>")

        with patch("phishkit.phishkit.magic") as mock_magic:
            mock_magic.from_file.return_value = "text/html"
            result = _correct_file_extension(file_path)

        assert result.endswith(".html")
        assert not os.path.exists(file_path)

    @pytest.mark.unit
    def test_correct_file_extension_no_mime(self, tmpdir):
        from phishkit.phishkit import _correct_file_extension

        file_path = str(tmpdir.join("mystery"))
        with open(file_path, "w") as f:
            f.write("data")

        with patch("phishkit.phishkit.magic") as mock_magic:
            mock_magic.from_file.return_value = None
            result = _correct_file_extension(file_path)

        assert result == file_path

    @pytest.mark.unit
    def test_correct_file_extension_no_extension_guess(self, tmpdir):
        from phishkit.phishkit import _correct_file_extension

        file_path = str(tmpdir.join("file.bin"))
        with open(file_path, "w") as f:
            f.write("data")

        with patch("phishkit.phishkit.magic") as mock_magic, \
             patch("phishkit.phishkit.mimetypes") as mock_mimetypes:
            mock_magic.from_file.return_value = "application/x-custom"
            mock_mimetypes.guess_extension.return_value = None
            result = _correct_file_extension(file_path)

        assert result == file_path


# ---------------------------------------------------------------------------
# Celery tasks: scan_url, scan_file
# ---------------------------------------------------------------------------

class TestScanUrl:

    @pytest.mark.unit
    @patch("phishkit.phishkit._process_output", return_value="/phishkit/output/job-1")
    @patch("phishkit.phishkit._run_scanner", return_value=("ok", "", 0))
    @patch("phishkit.phishkit.os.makedirs")
    @patch("phishkit.phishkit.uuid.uuid4", return_value="job-1")
    def test_scan_url_success(self, mock_uuid, mock_makedirs, mock_run, mock_process):
        from phishkit.phishkit import scan_url

        result = scan_url("https://example.com", timeout=15)
        mock_run.assert_called_once()
        assert result == "/phishkit/output/job-1"

    @pytest.mark.unit
    @patch("phishkit.phishkit._run_scanner", return_value=("", "error occurred", 1))
    @patch("phishkit.phishkit.os.makedirs")
    @patch("phishkit.phishkit.uuid.uuid4", return_value="job-1")
    def test_scan_url_nonzero_exit(self, mock_uuid, mock_makedirs, mock_run):
        from phishkit.phishkit import scan_url

        with pytest.raises(Exception, match="scan failed"):
            scan_url("https://example.com", timeout=15)


class TestScanFile:

    @pytest.mark.unit
    @patch("phishkit.phishkit._process_output", return_value="/phishkit/output/job-1")
    @patch("phishkit.phishkit._run_scanner", return_value=("ok", "", 0))
    @patch("phishkit.phishkit._correct_file_extension", side_effect=lambda p: p)
    @patch("phishkit.phishkit.shutil.copy2")
    @patch("phishkit.phishkit.os.makedirs")
    @patch("phishkit.phishkit.uuid.uuid4", return_value="job-1")
    def test_scan_file_success(self, mock_uuid, mock_makedirs, mock_copy,
                               mock_correct, mock_run, mock_process):
        from phishkit.phishkit import scan_file

        result = scan_file("/some/path/malware.html", timeout=15)
        mock_run.assert_called_once()
        # verify --file is in the target_args
        run_call = mock_run.call_args
        assert "--file" in run_call.kwargs["target_args"]
        assert result == "/phishkit/output/job-1"
