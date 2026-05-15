from datetime import datetime, timedelta, timezone

import pytest

from saq.database.pool import get_db
from saq.remediation.external.collector import ExternalRemediationCheckCollector
from saq.remediation.external.types import CheckStatus


class CollectingListener:
    """Captures every work item the collector hands off."""
    def __init__(self):
        self.received = []

    def handle_external_check_request(self, work_item):
        self.received.append(work_item)


@pytest.fixture
def collector_with_listener():
    collector = ExternalRemediationCheckCollector(
        lock_timeout_seconds=300,
        initial_retry_delay_seconds=60,
        max_retry_delay_seconds=3600,
    )
    listener = CollectingListener()
    collector.register_listener("fake_probe", listener)
    return collector, listener


@pytest.mark.integration
def test_collect_picks_up_new_row(make_check, collector_with_listener):
    collector, listener = collector_with_listener
    check = make_check()

    items = collector.collect_work_items()

    assert [w.id for w in items] == [check.id]
    db = get_db()
    db.refresh(check)
    assert check.status == CheckStatus.IN_PROGRESS.value
    assert check.lock is not None


@pytest.mark.integration
def test_collect_skips_completed(make_check, collector_with_listener):
    collector, _ = collector_with_listener
    make_check(status=CheckStatus.COMPLETED.value, result="CONFIRMED")

    items = collector.collect_work_items()
    assert items == []


@pytest.mark.integration
def test_collect_skips_unregistered_probe(make_check, collector_with_listener):
    collector, _ = collector_with_listener
    make_check(probe_name="some_other_probe")

    items = collector.collect_work_items()
    assert items == []


@pytest.mark.integration
def test_collect_skips_locked_within_timeout(make_check, collector_with_listener):
    collector, _ = collector_with_listener
    make_check(
        lock="held-by-someone-else",
        lock_time=datetime.now(timezone.utc),
        status=CheckStatus.IN_PROGRESS.value,
    )

    items = collector.collect_work_items()
    assert items == []


@pytest.mark.integration
def test_collect_steals_timed_out_lock(make_check, collector_with_listener):
    collector, _ = collector_with_listener
    expired_lock_time = datetime.now(timezone.utc) - timedelta(seconds=collector.lock_timeout_seconds + 60)
    check = make_check(
        lock="abandoned-lock",
        lock_time=expired_lock_time,
        status=CheckStatus.IN_PROGRESS.value,
    )

    items = collector.collect_work_items()
    assert [w.id for w in items] == [check.id]


@pytest.mark.integration
def test_collect_respects_backoff(make_check, collector_with_listener):
    collector, _ = collector_with_listener
    # retry_count=1 -> required_delay = 60 * 2^1 = 120s. update_time 30s ago
    # is *inside* the window, so the row must NOT be picked up.
    make_check(
        retry_count=1,
        update_time=datetime.now(timezone.utc) - timedelta(seconds=30),
    )
    items = collector.collect_work_items()
    assert items == []


@pytest.mark.integration
def test_collect_includes_past_deadline_for_finalization(make_check, collector_with_listener):
    """Past-deadline rows must come through the collector so the worker can
    mark them EXPIRED — they can't be hidden from the loop."""
    collector, _ = collector_with_listener
    expired = make_check(deadline=datetime.now(timezone.utc) - timedelta(minutes=1))

    items = collector.collect_work_items()
    assert [w.id for w in items] == [expired.id]
