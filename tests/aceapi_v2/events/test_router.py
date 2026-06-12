"""Tests for the aceapi_v2 events router.

These are real integration tests: the events endpoints read/write through the
synchronous ``get_db()`` session (via ``asyncio.to_thread``), so data is seeded
through ``get_db()`` and cleaned up by the function-scoped database reset. The
``client`` fixture authenticates as the ``unittest`` user, which is granted
wildcard (``*``/``*``) permissions in the global test setup.
"""

from datetime import date

import pytest
from httpx import AsyncClient

from aceapi_v2.auth import create_access_token
from saq.database import (
    Event,
    EventPreventionTool,
    EventRemediation,
    EventRiskLevel,
    EventStatus,
    EventType,
    EventVector,
    get_db,
)

pytestmark = pytest.mark.integration


def _make_lookups() -> dict:
    """Create the required Event lookup rows (one OPEN + one CLOSED status)."""
    db = get_db()
    lookups = {
        "prevention_tool": EventPreventionTool(value="test_prevention_tool"),
        "remediation": EventRemediation(value="test_remediation"),
        "risk_level": EventRiskLevel(value="test_risk_level"),
        "type": EventType(value="test_type"),
        "vector": EventVector(value="test_vector"),
        "open_status": EventStatus(value="OPEN"),
        "closed_status": EventStatus(value="CLOSED"),
    }
    for obj in lookups.values():
        db.add(obj)
    db.commit()
    return lookups


def _make_event(name: str, lookups: dict, status: EventStatus) -> Event:
    db = get_db()
    event = Event(
        name=name,
        creation_date=date.today(),
        prevention_tool=lookups["prevention_tool"],
        remediation=lookups["remediation"],
        risk_level=lookups["risk_level"],
        status=status,
        type=lookups["type"],
        vector=lookups["vector"],
    )
    db.add(event)
    db.commit()
    return event


class TestOpenEvents:
    @pytest.mark.asyncio
    async def test_requires_auth(self, unauth_client: AsyncClient):
        response = await unauth_client.get("/events/open")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_returns_only_open_events(self, client: AsyncClient):
        lookups = _make_lookups()
        _make_event("open-event", lookups, lookups["open_status"])
        _make_event("closed-event", lookups, lookups["closed_status"])

        response = await client.get("/events/open")
        assert response.status_code == 200

        data = response.json()
        assert "data" in data
        names = [e["name"] for e in data["data"]]
        assert "open-event" in names
        assert "closed-event" not in names
        # every returned event reports OPEN status
        assert all(e["status"] == "OPEN" for e in data["data"])

    @pytest.mark.asyncio
    async def test_forbidden_without_permission(self, unauth_client: AsyncClient):
        token = create_access_token("noperm", 999999)
        response = await unauth_client.get(
            "/events/open", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 403


class TestUpdateEventStatus:
    @pytest.mark.asyncio
    async def test_requires_auth(self, unauth_client: AsyncClient):
        response = await unauth_client.patch("/events/1", json={"status": "CLOSED"})
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_updates_status(self, client: AsyncClient):
        lookups = _make_lookups()
        event = _make_event("status-event", lookups, lookups["open_status"])

        response = await client.patch(
            f"/events/{event.id}", json={"status": "CLOSED"}
        )
        assert response.status_code == 200
        assert response.json()["status"] == "CLOSED"

    @pytest.mark.asyncio
    async def test_unknown_event_returns_404(self, client: AsyncClient):
        _make_lookups()
        response = await client.patch("/events/999999", json={"status": "CLOSED"})
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_invalid_status_returns_400(self, client: AsyncClient):
        lookups = _make_lookups()
        event = _make_event("bad-status-event", lookups, lookups["open_status"])

        response = await client.patch(
            f"/events/{event.id}", json={"status": "NOT_A_REAL_STATUS"}
        )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_forbidden_without_permission(self, unauth_client: AsyncClient):
        token = create_access_token("noperm", 999999)
        response = await unauth_client.patch(
            "/events/1",
            json={"status": "CLOSED"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403


class TestExportEvents:
    @pytest.mark.asyncio
    async def test_requires_auth(self, unauth_client: AsyncClient):
        response = await unauth_client.get("/events/export", params={"type": "csv"})
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_exports_csv(self, client: AsyncClient):
        lookups = _make_lookups()
        event = _make_event("export-event", lookups, lookups["open_status"])

        response = await client.get(
            "/events/export",
            params={"type": "csv", "checked_events[]": [event.id]},
        )
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/csv")

        body = response.text
        # header row + the seeded event's data row
        assert '"id","uuid","creation_date"' in body
        assert '"export-event"' in body

    @pytest.mark.asyncio
    async def test_unsupported_format_returns_422(self, client: AsyncClient):
        response = await client.get("/events/export", params={"type": "xml"})
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_forbidden_without_permission(self, unauth_client: AsyncClient):
        token = create_access_token("noperm", 999999)
        response = await unauth_client.get(
            "/events/export",
            params={"type": "csv"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403
