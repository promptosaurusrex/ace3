from unittest.mock import Mock, patch

import pytest
from flask import url_for

from saq.constants import DIRECTIVE_CLICKER_DETECTION, F_FQDN, F_IP, F_URL
from saq.gui.alert import GUIAlert

ROUTE = "app.analysis.views.edit.observable_action.clicker"


@pytest.fixture
def mock_alert():
    alert = Mock(spec=GUIAlert)
    alert.uuid = "test-alert-uuid"
    alert.load = Mock(return_value=True)
    alert.root_analysis = Mock()
    alert.root_analysis.get_observable = Mock()
    return alert


@pytest.mark.integration
class TestCheckForClickers:
    @patch(f"{ROUTE}.get_current_alert")
    def test_no_alert(self, mock_get_alert, web_client):
        mock_get_alert.return_value = None
        r = web_client.post(url_for("analysis.observable_action_check_for_clickers"),
                            data={"observable_uuid": "x", "alert_uuid": "y"})
        assert r.status_code == 404

    @patch(f"{ROUTE}.release_lock")
    @patch(f"{ROUTE}.acquire_lock", return_value=True)
    @patch(f"{ROUTE}.get_current_alert")
    def test_wrong_observable_type(self, mock_get_alert, _lock, _unlock, web_client, mock_alert):
        obs = Mock()
        obs.type = F_IP
        mock_alert.root_analysis.get_observable.return_value = obs
        mock_get_alert.return_value = mock_alert
        r = web_client.post(url_for("analysis.observable_action_check_for_clickers"),
                            data={"observable_uuid": "x", "alert_uuid": "y"})
        assert r.status_code == 400

    @patch(f"{ROUTE}.add_workload")
    @patch(f"{ROUTE}.release_lock")
    @patch(f"{ROUTE}.acquire_lock", return_value=True)
    @patch(f"{ROUTE}.get_current_alert")
    def test_adds_directive_and_requeues(self, mock_get_alert, _lock, _unlock, mock_add_workload,
                                         web_client, mock_alert):
        obs = Mock()
        obs.type = F_URL
        mock_alert.root_analysis.get_observable.return_value = obs
        mock_get_alert.return_value = mock_alert

        r = web_client.post(url_for("analysis.observable_action_check_for_clickers"),
                            data={"observable_uuid": "x", "alert_uuid": "y"})

        assert r.status_code == 200
        obs.add_directive.assert_called_once_with(DIRECTIVE_CLICKER_DETECTION)
        mock_alert.sync.assert_called_once()
        mock_add_workload.assert_called_once()


@pytest.mark.integration
class TestOpenSplunkClickerSearch:
    @patch(f"{ROUTE}.get_current_alert")
    def test_no_alert(self, mock_get_alert, web_client):
        mock_get_alert.return_value = None
        r = web_client.post(url_for("analysis.observable_action_open_clicker_search_splunk"),
                            data={"observable_uuid": "x", "alert_uuid": "y"})
        assert r.status_code == 404

    @patch(f"{ROUTE}.build_splunk_clicker_search_urls",
           return_value=[{"name": "safelinks", "url": "https://splunk.example/search?q=a"},
                         {"name": "proxy", "url": "https://splunk.example/search?q=b"}])
    @patch(f"{ROUTE}.get_current_alert")
    def test_returns_urls(self, mock_get_alert, _build, web_client, mock_alert):
        obs = Mock()
        obs.type = F_FQDN
        mock_alert.root_analysis.get_observable.return_value = obs
        mock_get_alert.return_value = mock_alert

        r = web_client.post(url_for("analysis.observable_action_open_clicker_search_splunk"),
                            data={"observable_uuid": "x", "alert_uuid": "y"})
        assert r.status_code == 200
        assert [u["name"] for u in r.json["urls"]] == ["safelinks", "proxy"]

    @patch(f"{ROUTE}.build_splunk_clicker_search_urls", return_value=[])
    @patch(f"{ROUTE}.get_current_alert")
    def test_no_search_configured(self, mock_get_alert, _build, web_client, mock_alert):
        obs = Mock()
        obs.type = F_URL
        mock_alert.root_analysis.get_observable.return_value = obs
        mock_get_alert.return_value = mock_alert

        r = web_client.post(url_for("analysis.observable_action_open_clicker_search_splunk"),
                            data={"observable_uuid": "x", "alert_uuid": "y"})
        assert r.status_code == 200
        assert "url" not in r.json
        assert "No Splunk clicker search" in r.json["message"]
