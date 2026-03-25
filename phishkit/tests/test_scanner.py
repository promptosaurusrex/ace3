import asyncio
import time
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml


# ---------------------------------------------------------------------------
# _load_config
# ---------------------------------------------------------------------------

class TestLoadConfig:

    @pytest.mark.unit
    def test_load_config_valid(self, config_file, sample_config_data):
        from scanner import _load_config

        config = _load_config(config_file)
        assert config.skip_body_ext == sample_config_data["skip_body_extensions"]
        assert config.skip_body_url_patterns == sample_config_data["skip_body_url_patterns"]
        assert config.handlers == sample_config_data["handlers"]
        assert len(config.bypasses) == len(sample_config_data["bypasses"])

    @pytest.mark.unit
    def test_load_config_missing_file(self):
        from scanner import _load_config

        with pytest.raises(FileNotFoundError):
            _load_config("/nonexistent/config.yaml")

    @pytest.mark.unit
    def test_load_config_not_a_dict(self, tmpdir):
        from scanner import _load_config

        path = str(tmpdir.join("bad.yaml"))
        with open(path, "w") as f:
            yaml.dump(["a", "b"], f)

        with pytest.raises(ValueError, match="not a YAML mapping"):
            _load_config(path)

    @pytest.mark.unit
    def test_load_config_empty_file(self, tmpdir):
        from scanner import _load_config

        path = str(tmpdir.join("empty.yaml"))
        with open(path, "w") as f:
            f.write("")

        with pytest.raises(ValueError, match="not a YAML mapping"):
            _load_config(path)

    @pytest.mark.unit
    def test_load_config_missing_keys_uses_defaults(self, tmpdir):
        from scanner import _load_config

        path = str(tmpdir.join("minimal.yaml"))
        with open(path, "w") as f:
            yaml.dump({}, f)

        config = _load_config(path)
        assert config.skip_body_ext == []
        assert config.skip_body_url_patterns == []
        assert config.handlers == {}
        assert config.bypasses == []


# ---------------------------------------------------------------------------
# Scanner.__init__
# ---------------------------------------------------------------------------

class TestScannerInit:

    @pytest.mark.unit
    def test_scanner_init_populates_attributes(self, scanner, sample_config_data):
        assert scanner.SKIP_BODY_EXT == sample_config_data["skip_body_extensions"]
        assert scanner.SKIP_BODY_URL_PATTERNS == sample_config_data["skip_body_url_patterns"]
        assert scanner.HANDLERS == sample_config_data["handlers"]
        assert len(scanner.BYPASSES) == len(sample_config_data["bypasses"])
        assert scanner.requests == []
        assert scanner.bytes_downloaded == 0
        assert scanner.domain_stats == {}

    @pytest.mark.unit
    def test_scanner_init_bypass_handlers_map(self, scanner):
        assert "visual_checkbox_bypass" in scanner._bypass_handlers
        assert callable(scanner._bypass_handlers["visual_checkbox_bypass"])


# ---------------------------------------------------------------------------
# Scanner._get_domain_stats
# ---------------------------------------------------------------------------

class TestGetDomainStats:

    @pytest.mark.unit
    def test_get_domain_stats_new_domain(self, scanner):
        stats = scanner._get_domain_stats("example.com")
        assert stats["bytes_downloaded"] == 0
        assert stats["request_count"] == 0
        assert stats["response_count"] == 0
        assert stats["first_request_time"] is None
        assert stats["last_finished_time"] is None

    @pytest.mark.unit
    def test_get_domain_stats_existing_domain(self, scanner):
        first = scanner._get_domain_stats("example.com")
        first["request_count"] = 5
        second = scanner._get_domain_stats("example.com")
        assert first is second
        assert second["request_count"] == 5

    @pytest.mark.unit
    def test_get_domain_stats_multiple_domains(self, scanner):
        a = scanner._get_domain_stats("a.com")
        b = scanner._get_domain_stats("b.com")
        assert a is not b
        assert len(scanner.domain_stats) == 2


# ---------------------------------------------------------------------------
# Scanner._compute_metrics
# ---------------------------------------------------------------------------

class TestComputeMetrics:

    @pytest.mark.unit
    def test_compute_metrics_empty_stats(self, scanner):
        metrics = scanner._compute_metrics("https://example.com", 1.5)
        assert metrics["url_scanned"] == "https://example.com"
        assert metrics["total_bytes_downloaded"] == 0
        assert metrics["scan_duration_seconds"] == 1.5
        assert metrics["domain_stats"] == {}

    @pytest.mark.unit
    def test_compute_metrics_with_timing(self, scanner):
        scanner.domain_stats["example.com"] = {
            "bytes_downloaded": 1024,
            "request_count": 3,
            "response_count": 3,
            "first_request_time": 100.0,
            "last_finished_time": 102.5,
        }
        scanner.bytes_downloaded = 1024

        metrics = scanner._compute_metrics("https://example.com", 5.0)
        domain = metrics["domain_stats"]["example.com"]
        assert domain["bytes_downloaded"] == 1024
        assert domain["request_count"] == 3
        assert domain["duration_seconds"] == 2.5

    @pytest.mark.unit
    def test_compute_metrics_missing_timing(self, scanner):
        scanner.domain_stats["example.com"] = {
            "bytes_downloaded": 0,
            "request_count": 1,
            "response_count": 0,
            "first_request_time": None,
            "last_finished_time": None,
        }

        metrics = scanner._compute_metrics("https://example.com", 1.0)
        assert metrics["domain_stats"]["example.com"]["duration_seconds"] == 0

    @pytest.mark.unit
    def test_compute_metrics_timestamp_format(self, scanner):
        metrics = scanner._compute_metrics("https://example.com", 0.0)
        ts = datetime.fromisoformat(metrics["timestamp"])
        assert ts.tzinfo is not None


# ---------------------------------------------------------------------------
# Scanner.check_dom_filter
# ---------------------------------------------------------------------------

class TestCheckDomFilter:

    @pytest.mark.unit
    def test_check_dom_filter_matching_url_pattern(self, scanner):
        assert scanner.check_dom_filter("https://fonts.googleapis.com/css?family=Roboto") is True

    @pytest.mark.unit
    def test_check_dom_filter_matching_extension(self, scanner):
        assert scanner.check_dom_filter("https://example.com/image.png") is True

    @pytest.mark.unit
    def test_check_dom_filter_data_url(self, scanner):
        assert scanner.check_dom_filter("data:image/png;base64,abc") is True

    @pytest.mark.unit
    def test_check_dom_filter_blob_url(self, scanner):
        assert scanner.check_dom_filter("blob:https://example.com/abc") is True

    @pytest.mark.unit
    def test_check_dom_filter_non_matching(self, scanner):
        assert scanner.check_dom_filter("https://example.com/page.html") is False


# ---------------------------------------------------------------------------
# Async event handlers
# ---------------------------------------------------------------------------

def _make_response_event(url="https://example.com/page", request_id="req-1",
                         status=200, headers=None, encoded_data_length=100):
    event = MagicMock()
    event.response.url = url
    event.request_id = request_id
    event.response.headers = headers or {}
    event.response.status = status
    event.response.encoded_data_length = encoded_data_length
    event.response.to_json.return_value = "{}"
    return event


def _make_request_event(url="https://example.com/page", request_id="req-1", method="GET", headers=None):
    event = MagicMock()
    event.request.url = url
    event.request_id = request_id
    event.request.method = method
    event.request.headers = headers or {}
    event.request.to_json.return_value = "{}"
    return event


def _make_loading_finished_event(request_id="req-1", encoded_data_length=500):
    event = MagicMock()
    event.request_id = request_id
    event.encoded_data_length = encoded_data_length
    return event


def _make_loading_failed_event(request_id="req-1", error_text="net::ERR_FAILED",
                               canceled=False, blocked_reason=None):
    event = MagicMock()
    event.request_id = request_id
    event.error_text = error_text
    event.canceled = canceled
    event.blocked_reason = blocked_reason
    return event


def _make_attached_event(target_type="worker", session_id="sess-1"):
    event = MagicMock()
    event.target_info.type_ = target_type
    event.session_id = session_id
    return event


class TestReceiveHandler:

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_receive_handler_appends_response(self, scanner):
        event = _make_response_event()
        await scanner.receive_handler(event)
        assert len(scanner.requests) == 1
        assert scanner.requests[0]["type"] == "response"
        assert scanner.requests[0]["url"] == "https://example.com/page"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_receive_handler_updates_domain_stats(self, scanner):
        event = _make_response_event(url="https://test.org/resource")
        await scanner.receive_handler(event)
        assert scanner.domain_stats["test.org"]["response_count"] == 1


class TestSendHandler:

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_send_handler_appends_request(self, scanner):
        event = _make_request_event(method="POST")
        await scanner.send_handler(event)
        assert len(scanner.requests) == 1
        assert scanner.requests[0]["type"] == "request"
        assert scanner.requests[0]["method"] == "POST"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_send_handler_sets_first_request_time(self, scanner):
        event = _make_request_event()
        await scanner.send_handler(event)
        first_time = scanner.domain_stats["example.com"]["first_request_time"]
        assert first_time is not None

        # second call should not overwrite
        await scanner.send_handler(_make_request_event())
        assert scanner.domain_stats["example.com"]["first_request_time"] == first_time


class TestLoadingFinishedHandler:

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_loading_finished_handler_updates_bytes(self, scanner):
        # pre-populate a matching response entry
        scanner.requests.append({
            "requestId": "req-1",
            "type": "response",
            "url": "https://example.com/page",
        })
        event = _make_loading_finished_event(request_id="req-1", encoded_data_length=500)
        await scanner.loading_finished_handler(event)
        assert scanner.bytes_downloaded == 500
        assert scanner.domain_stats["example.com"]["bytes_downloaded"] == 500

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_loading_finished_handler_updates_last_finished_time(self, scanner):
        scanner.requests.append({
            "requestId": "req-1",
            "type": "response",
            "url": "https://example.com/page",
        })
        event = _make_loading_finished_event(request_id="req-1", encoded_data_length=100)
        await scanner.loading_finished_handler(event)
        assert scanner.domain_stats["example.com"]["last_finished_time"] is not None


class TestLoadingFailedHandler:

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_loading_failed_handler_appends_error(self, scanner):
        event = _make_loading_failed_event()
        await scanner.loading_failed_handler(event)
        assert len(scanner.requests) == 1
        assert scanner.requests[0]["type"] == "error"
        assert scanner.requests[0]["error_text"] == "net::ERR_FAILED"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_loading_failed_handler_includes_url_from_request(self, scanner):
        scanner.requests.append({
            "requestId": "req-1",
            "type": "request",
            "url": "https://example.com/page",
        })
        event = _make_loading_failed_event(request_id="req-1")
        await scanner.loading_failed_handler(event)
        error_entry = scanner.requests[-1]
        assert error_entry["type"] == "error"
        assert error_entry["url"] == "https://example.com/page"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_loading_failed_handler_with_blocked_reason(self, scanner):
        event = _make_loading_failed_event(blocked_reason="inspector")
        await scanner.loading_failed_handler(event)
        assert scanner.requests[-1]["blocked_reason"] == "inspector"


class TestTargetAttachedHandler:

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_target_attached_handler_worker(self, scanner):
        scanner._cdp_tab = MagicMock()
        scanner._cdp_tab.send = AsyncMock()
        event = _make_attached_event(target_type="worker")
        await scanner.target_attached_handler(event)
        # stealth inject + resume = 2 calls
        assert scanner._cdp_tab.send.call_count == 2

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_target_attached_handler_non_worker(self, scanner):
        scanner._cdp_tab = MagicMock()
        scanner._cdp_tab.send = AsyncMock()
        event = _make_attached_event(target_type="iframe")
        await scanner.target_attached_handler(event)
        # only resume, no stealth inject
        assert scanner._cdp_tab.send.call_count == 1

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_target_attached_handler_inject_failure_still_resumes(self, scanner):
        scanner._cdp_tab = MagicMock()
        call_count = 0

        async def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("inject failed")

        scanner._cdp_tab.send = AsyncMock(side_effect=side_effect)
        event = _make_attached_event(target_type="service_worker")
        await scanner.target_attached_handler(event)
        # should still attempt both calls even if first fails
        assert call_count == 2


# ---------------------------------------------------------------------------
# Scanner.bypass_warnings
# ---------------------------------------------------------------------------

class TestBypassWarnings:

    @pytest.mark.unit
    def test_bypass_warnings_no_match(self, scanner):
        sb = MagicMock()
        sb.cdp.get_page_source.return_value = "nothing interesting here"
        assert scanner.bypass_warnings(sb) is False

    @pytest.mark.unit
    def test_bypass_warnings_selector_success(self, scanner):
        sb = MagicMock()
        sb.cdp.get_page_source.return_value = "This site has been flagged as phishing by CloudFlare"
        sb.driver.uc_click.return_value = None
        assert scanner.bypass_warnings(sb) is True
        sb.driver.uc_click.assert_called()

    @pytest.mark.unit
    def test_bypass_warnings_selector_failure(self, scanner):
        sb = MagicMock()
        sb.cdp.get_page_source.return_value = "This site has been flagged as phishing by CloudFlare"
        sb.driver.uc_click.side_effect = Exception("element not found")
        assert scanner.bypass_warnings(sb) is False

    @pytest.mark.unit
    def test_bypass_warnings_handler_match(self, scanner):
        sb = MagicMock()
        sb.cdp.get_page_source.return_value = "Verify you are human"
        scanner._bypass_handlers["visual_checkbox_bypass"] = MagicMock()
        assert scanner.bypass_warnings(sb) is True
        scanner._bypass_handlers["visual_checkbox_bypass"].assert_called_once()

    @pytest.mark.unit
    def test_bypass_warnings_unknown_handler(self, config_file):
        from scanner import Scanner

        scanner = Scanner(config_path=config_file)
        # replace the antibot bypass handler name with something unknown
        for bypass in scanner.BYPASSES:
            if bypass.get("handler"):
                bypass["handler"] = "nonexistent_handler"

        sb = MagicMock()
        sb.cdp.get_page_source.return_value = "Verify you are human"
        assert scanner.bypass_warnings(sb) is False

    @pytest.mark.unit
    def test_bypass_warnings_invalid_bypass_skipped(self, scanner):
        # add an invalid bypass with missing keys
        scanner.BYPASSES.insert(0, {"type": None, "searches": None})
        sb = MagicMock()
        sb.cdp.get_page_source.return_value = "flagged as phishing"
        # should skip the invalid bypass and still find the valid one
        assert scanner.bypass_warnings(sb) is True

    @pytest.mark.unit
    def test_bypass_warnings_no_selectors_or_handler(self, scanner):
        # replace all bypasses with one that has searches but no selectors/handler
        scanner.BYPASSES = [{"type": "bare", "searches": ["match me"]}]
        sb = MagicMock()
        sb.cdp.get_page_source.return_value = "match me"
        assert scanner.bypass_warnings(sb) is False


# ---------------------------------------------------------------------------
# Scanner.bypass_recaptcha
# ---------------------------------------------------------------------------

class TestBypassRecaptcha:

    @pytest.mark.unit
    def test_bypass_recaptcha_not_detected(self, scanner):
        sb = MagicMock()
        sb.cdp.get_page_source.return_value = "no captcha here"
        scanner.bypass_recaptcha(sb)
        # solver should never be instantiated

    @pytest.mark.unit
    @patch("scanner.RecaptchaSolver")
    def test_bypass_recaptcha_detected(self, mock_solver_cls, scanner):
        sb = MagicMock()
        sb.cdp.get_page_source.return_value = "Please complete the security check to access the website."
        mock_solver = MagicMock()
        mock_solver_cls.return_value = mock_solver

        scanner.bypass_recaptcha(sb)
        mock_solver_cls.assert_called_once_with(driver=sb.driver)
        mock_solver.click_recaptcha_v2.assert_called_once()
        sb.driver.click.assert_called_once_with("#btn")


# ---------------------------------------------------------------------------
# Scanner.visual_checkbox_bypass
# ---------------------------------------------------------------------------

class TestVisualCheckboxBypass:

    @pytest.mark.unit
    @patch("scanner.Image.open", return_value=MagicMock())
    def test_visual_checkbox_bypass_found(self, mock_image_open, scanner):
        mock_pyautogui = MagicMock()
        rect = MagicMock()
        rect.left = 100
        rect.top = 200
        rect.width = 30
        rect.height = 30
        mock_pyautogui.locate.return_value = rect
        mock_pyautogui.screenshot.return_value = MagicMock()

        sb = MagicMock()
        config = {"checkbox_pngs": ["iVBORw0KGgo="]}

        import sys
        with patch.dict(sys.modules, {"pyautogui": mock_pyautogui}):
            scanner.visual_checkbox_bypass(sb, config)

        sb.uc_gui_click_x_y.assert_called_once_with(115, 215)

    @pytest.mark.unit
    @patch("scanner.Image.open", return_value=MagicMock())
    def test_visual_checkbox_bypass_not_found(self, mock_image_open, scanner, capsys):
        mock_pyautogui = MagicMock()
        mock_pyautogui.ImageNotFoundException = type("ImageNotFoundException", (Exception,), {})
        mock_pyautogui.locate.side_effect = mock_pyautogui.ImageNotFoundException()
        mock_pyautogui.screenshot.return_value = MagicMock()

        sb = MagicMock()
        config = {"checkbox_pngs": ["iVBORw0KGgo="]}

        import sys
        with patch.dict(sys.modules, {"pyautogui": mock_pyautogui}):
            scanner.visual_checkbox_bypass(sb, config)

        sb.uc_gui_click_x_y.assert_not_called()
        captured = capsys.readouterr()
        assert "Failed to find checkbox visually" in captured.out
