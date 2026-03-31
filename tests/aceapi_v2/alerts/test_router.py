"""Tests for aceapi_v2 alerts router — bulk add observable endpoint."""

from unittest.mock import MagicMock, patch

import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.integration


def _make_mock_alert(uuid: str):
    """Create a mock GUIAlert with the necessary attributes."""
    alert = MagicMock()
    alert.uuid = uuid
    alert.lock_uuid = None
    alert.root_analysis = MagicMock()
    alert.root_analysis.add_observable_by_spec = MagicMock(return_value=MagicMock())
    alert.root_analysis.analysis_mode = None
    return alert


class TestBulkAddObservable:
    """Test the POST /alerts/bulk-add-observable endpoint."""

    @pytest.mark.asyncio
    async def test_requires_auth(self, unauth_client: AsyncClient):
        """Unauthenticated requests should return 401."""
        response = await unauth_client.post("/alerts/bulk-add-observable", json={
            "alert_uuids": ["abc-123"],
            "observable_type": "ipv4",
            "observable_value": "1.2.3.4",
        })
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_empty_uuids(self, client: AsyncClient):
        """Empty alert_uuids list should return 400."""
        response = await client.post("/alerts/bulk-add-observable", json={
            "alert_uuids": [],
            "observable_type": "ipv4",
            "observable_value": "1.2.3.4",
        })
        assert response.status_code == 400
        assert "No alert UUIDs" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_missing_value(self, client: AsyncClient):
        """Empty observable_value should return 400."""
        response = await client.post("/alerts/bulk-add-observable", json={
            "alert_uuids": ["abc-123"],
            "observable_type": "ipv4",
            "observable_value": "",
        })
        assert response.status_code == 400
        assert "Missing observable value" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_missing_fields(self, client: AsyncClient):
        """Missing required fields should return 422."""
        response = await client.post("/alerts/bulk-add-observable", json={
            "alert_uuids": ["abc-123"],
        })
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_invalid_time_format(self, client: AsyncClient):
        """Invalid time format should return 400."""
        response = await client.post("/alerts/bulk-add-observable", json={
            "alert_uuids": ["abc-123"],
            "observable_type": "ipv4",
            "observable_value": "1.2.3.4",
            "observable_time": "not-a-date",
        })
        assert response.status_code == 400
        assert "Invalid time format" in response.json()["detail"]

    @pytest.mark.asyncio
    @patch("aceapi_v2.alerts.service.add_workload")
    @patch("aceapi_v2.alerts.service.release_lock")
    @patch("aceapi_v2.alerts.service.acquire_lock", return_value=True)
    @patch("aceapi_v2.alerts.service.get_db")
    async def test_bulk_add_observable_success(
        self,
        mock_get_db,
        mock_acquire_lock,
        mock_release_lock,
        mock_add_workload,
        client: AsyncClient,
    ):
        """Successfully adding an observable to multiple alerts."""
        alert1 = _make_mock_alert("uuid-1")
        alert2 = _make_mock_alert("uuid-2")

        mock_query = MagicMock()
        mock_filter = MagicMock()
        mock_get_db.return_value.query.return_value = mock_query
        mock_query.filter.return_value = mock_filter
        mock_filter.one_or_none.side_effect = [alert1, alert2]

        response = await client.post("/alerts/bulk-add-observable", json={
            "alert_uuids": ["uuid-1", "uuid-2"],
            "observable_type": "domain",
            "observable_value": "evil.example.com",
        })

        assert response.status_code == 200
        data = response.json()
        assert data["success_count"] == 2
        assert data["failed_count"] == 0
        assert data["failed_uuids"] == []

        # Verify observables were added to both alerts
        alert1.root_analysis.add_observable_by_spec.assert_called_once_with(
            "domain", "evil.example.com", None
        )
        alert2.root_analysis.add_observable_by_spec.assert_called_once_with(
            "domain", "evil.example.com", None
        )
        assert alert1.sync.called
        assert alert2.sync.called

    @pytest.mark.asyncio
    @patch("aceapi_v2.alerts.service.add_workload")
    @patch("aceapi_v2.alerts.service.release_lock")
    @patch("aceapi_v2.alerts.service.acquire_lock", return_value=True)
    @patch("aceapi_v2.alerts.service.get_db")
    async def test_bulk_add_observable_with_time(
        self,
        mock_get_db,
        mock_acquire_lock,
        mock_release_lock,
        mock_add_workload,
        client: AsyncClient,
    ):
        """Observable time should be parsed and passed to add_observable_by_spec."""
        alert = _make_mock_alert("uuid-1")

        mock_query = MagicMock()
        mock_filter = MagicMock()
        mock_get_db.return_value.query.return_value = mock_query
        mock_query.filter.return_value = mock_filter
        mock_filter.one_or_none.return_value = alert

        response = await client.post("/alerts/bulk-add-observable", json={
            "alert_uuids": ["uuid-1"],
            "observable_type": "ipv4",
            "observable_value": "10.0.0.1",
            "observable_time": "2026-03-31 12:00:00",
        })

        assert response.status_code == 200
        data = response.json()
        assert data["success_count"] == 1

        # Verify time was passed
        call_args = alert.root_analysis.add_observable_by_spec.call_args
        assert call_args[0][2] is not None  # o_time should be a datetime

    @pytest.mark.asyncio
    @patch("aceapi_v2.alerts.service.add_workload")
    @patch("aceapi_v2.alerts.service.release_lock")
    @patch("aceapi_v2.alerts.service.acquire_lock", return_value=True)
    @patch("aceapi_v2.alerts.service.get_db")
    async def test_bulk_add_observable_with_directives(
        self,
        mock_get_db,
        mock_acquire_lock,
        mock_release_lock,
        mock_add_workload,
        client: AsyncClient,
    ):
        """Directives should be applied to the created observable."""
        alert = _make_mock_alert("uuid-1")
        mock_observable = MagicMock()
        alert.root_analysis.add_observable_by_spec.return_value = mock_observable

        mock_query = MagicMock()
        mock_filter = MagicMock()
        mock_get_db.return_value.query.return_value = mock_query
        mock_query.filter.return_value = mock_filter
        mock_filter.one_or_none.return_value = alert

        response = await client.post("/alerts/bulk-add-observable", json={
            "alert_uuids": ["uuid-1"],
            "observable_type": "url",
            "observable_value": "https://bad.example.com",
            "directives": ["crawl", "sandbox"],
        })

        assert response.status_code == 200
        data = response.json()
        assert data["success_count"] == 1

        # Verify directives were applied
        mock_observable.add_directive.assert_any_call("crawl")
        mock_observable.add_directive.assert_any_call("sandbox")

    @pytest.mark.asyncio
    @patch("aceapi_v2.alerts.service.release_lock")
    @patch("aceapi_v2.alerts.service.acquire_lock", return_value=False)
    @patch("aceapi_v2.alerts.service.get_db")
    async def test_bulk_add_observable_lock_failure(
        self,
        mock_get_db,
        mock_acquire_lock,
        mock_release_lock,
        client: AsyncClient,
    ):
        """Alerts that can't be locked should be reported as failed."""
        alert = _make_mock_alert("uuid-1")

        mock_query = MagicMock()
        mock_filter = MagicMock()
        mock_get_db.return_value.query.return_value = mock_query
        mock_query.filter.return_value = mock_filter
        mock_filter.one_or_none.return_value = alert

        response = await client.post("/alerts/bulk-add-observable", json={
            "alert_uuids": ["uuid-1"],
            "observable_type": "ipv4",
            "observable_value": "1.2.3.4",
        })

        assert response.status_code == 200
        data = response.json()
        assert data["success_count"] == 0
        assert data["failed_count"] == 1
        assert data["failed_uuids"] == ["uuid-1"]
        assert data["failed_details"]["uuid-1"] == "alert is currently locked"

    @pytest.mark.asyncio
    @patch("aceapi_v2.alerts.service.get_db")
    async def test_bulk_add_observable_nonexistent_alert(
        self,
        mock_get_db,
        client: AsyncClient,
    ):
        """Nonexistent alerts should be reported as failed."""
        mock_query = MagicMock()
        mock_filter = MagicMock()
        mock_get_db.return_value.query.return_value = mock_query
        mock_query.filter.return_value = mock_filter
        mock_filter.one_or_none.return_value = None

        response = await client.post("/alerts/bulk-add-observable", json={
            "alert_uuids": ["nonexistent-uuid"],
            "observable_type": "domain",
            "observable_value": "evil.example.com",
        })

        assert response.status_code == 200
        data = response.json()
        assert data["success_count"] == 0
        assert data["failed_count"] == 1
        assert data["failed_uuids"] == ["nonexistent-uuid"]
        assert data["failed_details"]["nonexistent-uuid"] == "alert not found"

    @pytest.mark.asyncio
    @patch("aceapi_v2.alerts.service.add_workload")
    @patch("aceapi_v2.alerts.service.release_lock")
    @patch("aceapi_v2.alerts.service.acquire_lock", return_value=True)
    @patch("aceapi_v2.alerts.service.get_db")
    async def test_bulk_add_observable_partial_failure(
        self,
        mock_get_db,
        mock_acquire_lock,
        mock_release_lock,
        mock_add_workload,
        client: AsyncClient,
    ):
        """Mix of successful and failed alerts should be reported correctly."""
        alert1 = _make_mock_alert("uuid-1")
        # alert2 doesn't exist

        mock_query = MagicMock()
        mock_filter = MagicMock()
        mock_get_db.return_value.query.return_value = mock_query
        mock_query.filter.return_value = mock_filter
        mock_filter.one_or_none.side_effect = [alert1, None]

        response = await client.post("/alerts/bulk-add-observable", json={
            "alert_uuids": ["uuid-1", "uuid-2"],
            "observable_type": "domain",
            "observable_value": "evil.example.com",
        })

        assert response.status_code == 200
        data = response.json()
        assert data["success_count"] == 1
        assert data["failed_count"] == 1
        assert data["failed_uuids"] == ["uuid-2"]
        assert data["failed_details"]["uuid-2"] == "alert not found"

    @pytest.mark.asyncio
    @patch("aceapi_v2.alerts.service.add_workload")
    @patch("aceapi_v2.alerts.service.release_lock")
    @patch("aceapi_v2.alerts.service.acquire_lock", return_value=True)
    @patch("aceapi_v2.alerts.service.get_db")
    async def test_bulk_add_observable_invalid_directives_filtered(
        self,
        mock_get_db,
        mock_acquire_lock,
        mock_release_lock,
        mock_add_workload,
        client: AsyncClient,
    ):
        """Invalid directives should be silently filtered out."""
        alert = _make_mock_alert("uuid-1")
        mock_observable = MagicMock()
        alert.root_analysis.add_observable_by_spec.return_value = mock_observable

        mock_query = MagicMock()
        mock_filter = MagicMock()
        mock_get_db.return_value.query.return_value = mock_query
        mock_query.filter.return_value = mock_filter
        mock_filter.one_or_none.return_value = alert

        response = await client.post("/alerts/bulk-add-observable", json={
            "alert_uuids": ["uuid-1"],
            "observable_type": "ipv4",
            "observable_value": "1.2.3.4",
            "directives": ["sandbox", "totally_fake_directive"],
        })

        assert response.status_code == 200
        data = response.json()
        assert data["success_count"] == 1

        # Only valid directive should be applied
        mock_observable.add_directive.assert_called_once_with("sandbox")

    @pytest.mark.asyncio
    async def test_valid_time_format(self, client: AsyncClient):
        """Valid time format should be accepted (regression check)."""
        # This will fail at the service level since we're not mocking,
        # but should NOT return 400 for time format
        with patch("aceapi_v2.alerts.service.get_db") as mock_get_db:
            mock_query = MagicMock()
            mock_filter = MagicMock()
            mock_get_db.return_value.query.return_value = mock_query
            mock_query.filter.return_value = mock_filter
            mock_filter.one_or_none.return_value = None

            response = await client.post("/alerts/bulk-add-observable", json={
                "alert_uuids": ["uuid-1"],
                "observable_type": "ipv4",
                "observable_value": "1.2.3.4",
                "observable_time": "2026-03-31 14:30:00",
            })

            # Should not be a 400 for time format
            assert response.status_code == 200
