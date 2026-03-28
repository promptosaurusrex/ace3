"""Tests for aceapi_v2 observables router."""

import hashlib

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from saq.database.model import Observable

pytestmark = pytest.mark.integration


def _sha256(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf8", errors="ignore")).digest()


class TestSetInteresting:
    """Test the PATCH /observables/interesting endpoint."""

    @pytest.mark.asyncio
    async def test_requires_auth(self, unauth_client: AsyncClient):
        response = await unauth_client.patch(
            "/observables/interesting",
            json={
                "observable_type": "ipv4",
                "observable_value": "192.168.1.1",
                "is_interesting": True,
            },
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_mark_existing_observable_interesting(
        self, session: AsyncSession, client: AsyncClient
    ):
        """Mark an existing observable as interesting."""
        obs = Observable(
            type="ipv4", sha256=_sha256("192.168.1.1"), value=b"192.168.1.1"
        )
        session.add(obs)
        await session.commit()

        response = await client.patch(
            "/observables/interesting",
            json={
                "observable_type": "ipv4",
                "observable_value": "192.168.1.1",
                "is_interesting": True,
            },
        )
        assert response.status_code == 200

        # Expire cached state so we re-read from DB
        session.expire_all()
        result = await session.execute(
            select(Observable).where(
                Observable.type == "ipv4",
                Observable.sha256 == _sha256("192.168.1.1"),
            )
        )
        db_obs = result.scalar_one()
        assert db_obs.is_interesting is True

    @pytest.mark.asyncio
    async def test_mark_nonexistent_observable_creates_it(
        self, session: AsyncSession, client: AsyncClient
    ):
        """Marking a nonexistent observable as interesting should create it."""
        response = await client.patch(
            "/observables/interesting",
            json={
                "observable_type": "domain",
                "observable_value": "evil.com",
                "is_interesting": True,
            },
        )
        assert response.status_code == 200

        result = await session.execute(
            select(Observable).where(
                Observable.type == "domain",
                Observable.sha256 == _sha256("evil.com"),
            )
        )
        db_obs = result.scalar_one()
        assert db_obs.is_interesting is True
        assert db_obs.value == b"evil.com"

    @pytest.mark.asyncio
    async def test_unmark_observable_interesting(
        self, session: AsyncSession, client: AsyncClient
    ):
        """Unmark an observable that was previously interesting."""
        obs = Observable(
            type="url",
            sha256=_sha256("https://evil.com"),
            value=b"https://evil.com",
            is_interesting=True,
        )
        session.add(obs)
        await session.commit()

        response = await client.patch(
            "/observables/interesting",
            json={
                "observable_type": "url",
                "observable_value": "https://evil.com",
                "is_interesting": False,
            },
        )
        assert response.status_code == 200

        session.expire_all()
        result = await session.execute(
            select(Observable).where(
                Observable.type == "url",
                Observable.sha256 == _sha256("https://evil.com"),
            )
        )
        db_obs = result.scalar_one()
        assert db_obs.is_interesting is False

    @pytest.mark.asyncio
    async def test_unmark_nonexistent_observable_is_noop(
        self, client: AsyncClient
    ):
        """Unmarking a nonexistent observable should succeed without creating it."""
        response = await client.patch(
            "/observables/interesting",
            json={
                "observable_type": "ipv4",
                "observable_value": "10.0.0.1",
                "is_interesting": False,
            },
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_toggle_interesting_idempotent(
        self, session: AsyncSession, client: AsyncClient
    ):
        """Marking as interesting twice should be idempotent."""
        obs = Observable(
            type="ipv4",
            sha256=_sha256("1.2.3.4"),
            value=b"1.2.3.4",
            is_interesting=True,
        )
        session.add(obs)
        await session.commit()

        response = await client.patch(
            "/observables/interesting",
            json={
                "observable_type": "ipv4",
                "observable_value": "1.2.3.4",
                "is_interesting": True,
            },
        )
        assert response.status_code == 200

        session.expire_all()
        result = await session.execute(
            select(Observable).where(
                Observable.type == "ipv4",
                Observable.sha256 == _sha256("1.2.3.4"),
            )
        )
        db_obs = result.scalar_one()
        assert db_obs.is_interesting is True

    @pytest.mark.asyncio
    async def test_does_not_affect_other_fields(
        self, session: AsyncSession, client: AsyncClient
    ):
        """Marking as interesting should not change other fields like for_detection."""
        obs = Observable(
            type="domain",
            sha256=_sha256("test.com"),
            value=b"test.com",
            for_detection=True,
        )
        session.add(obs)
        await session.commit()

        response = await client.patch(
            "/observables/interesting",
            json={
                "observable_type": "domain",
                "observable_value": "test.com",
                "is_interesting": True,
            },
        )
        assert response.status_code == 200

        session.expire_all()
        result = await session.execute(
            select(Observable).where(
                Observable.type == "domain",
                Observable.sha256 == _sha256("test.com"),
            )
        )
        db_obs = result.scalar_one()
        assert db_obs.is_interesting is True
        assert db_obs.for_detection is True

    @pytest.mark.asyncio
    async def test_response_message(self, client: AsyncClient):
        """Verify response message content."""
        response = await client.patch(
            "/observables/interesting",
            json={
                "observable_type": "ipv4",
                "observable_value": "8.8.8.8",
                "is_interesting": True,
            },
        )
        assert response.json()["message"] == "Observable marked as interesting"

        response = await client.patch(
            "/observables/interesting",
            json={
                "observable_type": "ipv4",
                "observable_value": "8.8.8.8",
                "is_interesting": False,
            },
        )
        assert response.json()["message"] == "Observable unmarked as interesting"
