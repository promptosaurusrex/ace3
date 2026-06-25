"""Tests for ExtraAwareFluentFormatter and the transaction id correlation field."""
import logging
import threading
import uuid

import pytest

from saq.logging import (
    ExtraAwareFluentFormatter,
    TransactionIdFilter,
    _install_transaction_id_filter,
    get_transaction_id,
    initialize_transaction_id,
    set_transaction_id,
    transaction_id,
)


def _make_formatter():
    """Mirror the ``fmt`` dict shipped in etc/logging_configs/ace_logging.yaml
    so tests reflect the production wire format.
    """
    return ExtraAwareFluentFormatter(
        fmt={
            "asctime": "%(asctime)s",
            "filename": "%(filename)s",
            "lineno": "%(lineno)d",
            "threadName": "%(threadName)s",
            "process": "%(process)d",
            "severity": "%(levelname)s",
            "message": "%(message)s",
            "logSource": "%(name)s",
            "transactionId": "%(transactionId)s",
        },
    )


def _make_record(msg="test message", **extra):
    record = logging.LogRecord(
        name="root",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg=msg,
        args=(),
        exc_info=None,
    )
    # the TransactionIdFilter stamps this on every record in production before the
    # formatter runs; mirror that here so the %(transactionId)s field resolves
    record.transactionId = get_transaction_id()
    for k, v in extra.items():
        setattr(record, k, v)
    return record


@pytest.mark.unit
def test_existing_renames_preserved():
    """The current Splunk pipeline relies on severity/logSource rather than
    levelname/name. Switching to ExtraAwareFluentFormatter must not change
    those keys.
    """
    formatter = _make_formatter()
    record = _make_record(msg="hello")
    data = formatter.format(record)
    assert data["severity"] == "INFO"
    assert data["logSource"] == "root"
    assert "levelname" not in data
    # 'name' would be the logger name, but the fmt dict renames it to logSource.
    assert "name" not in data


@pytest.mark.unit
def test_extras_appear_as_top_level_fields():
    """``extra={"k": v}`` keys must land in the output dict so Splunk's
    JSON-mode auto-KV extraction can break them out as searchable fields.
    """
    formatter = _make_formatter()
    record = _make_record(
        msg="cache_stats summary",
        total_rows=121,
        expired_rows=0,
        modules=1,
        module_name="rdap_analyzer",
    )
    data = formatter.format(record)
    assert data["total_rows"] == 121
    assert data["expired_rows"] == 0
    assert data["modules"] == 1
    assert data["module_name"] == "rdap_analyzer"


@pytest.mark.unit
def test_standard_logrecord_attrs_excluded():
    """Walking record.__dict__ would otherwise dump noisy built-ins
    (msecs, pathname, args, etc.) into every log event. Confirm those
    are filtered.
    """
    formatter = _make_formatter()
    record = _make_record(msg="hello")
    data = formatter.format(record)
    for noisy in ("msecs", "pathname", "args", "created", "module",
                  "relativeCreated", "thread"):
        assert noisy not in data, f"unexpected noisy attr in output: {noisy}"


@pytest.mark.unit
def test_extras_do_not_clobber_existing_renames():
    """If an extras key collides with one already produced by the fmt dict,
    the fmt-dict value wins (preserves the configured rename semantics).
    """
    formatter = _make_formatter()
    record = _make_record(msg="hi")
    # Hypothetical (and bad-form) caller tries to override severity.
    record.severity = "OVERRIDE"
    data = formatter.format(record)
    # Parent formatter ran first and set severity=INFO from the fmt dict.
    # Our pass would have skipped because 'severity' is already in data.
    assert data["severity"] == "INFO"


@pytest.mark.unit
def test_via_logging_call_extra_flows_through():
    """End-to-end: ``logging.info(msg, extra={...})`` produces a LogRecord
    that the formatter renders with the extras as top-level fields.
    """
    formatter = _make_formatter()
    logger = logging.getLogger("test_via_logging_call_extra_flows_through")
    logger.handlers = []
    captured = []

    class _Probe(logging.Handler):
        def emit(self, record):
            captured.append(formatter.format(record))

    probe = _Probe()
    # in production the TransactionIdFilter stamps record.transactionId before the
    # handler formats it; mirror that so %(transactionId)s resolves
    probe.addFilter(TransactionIdFilter())
    logger.addHandler(probe)
    logger.setLevel(logging.INFO)
    logger.info(
        "wrote analysis cache entry op=%s",
        "insert",
        extra={
            "op": "insert",
            "module_name": "rdap_analyzer",
            "compressed_bytes": 187,
        },
    )

    assert captured
    rec = captured[0]
    assert rec["message"].startswith("wrote analysis cache entry op=insert")
    assert rec["op"] == "insert"
    assert rec["module_name"] == "rdap_analyzer"
    assert rec["compressed_bytes"] == 187


@pytest.mark.unit
def test_transaction_id_default_present():
    """a transaction id is always available, and initialize_transaction_id()
    installs a fresh uuid4 as the current value"""
    assert isinstance(get_transaction_id(), str)
    assert get_transaction_id()

    with transaction_id():
        new_id = initialize_transaction_id()
        # parseable as a uuid and reflected by get_transaction_id()
        uuid.UUID(new_id)
        assert get_transaction_id() == new_id


@pytest.mark.unit
def test_transaction_id_per_thread_isolation():
    """a transaction id set on another thread must not change this thread's value
    (confirms the ContextVar gives per-thread isolation)"""
    with transaction_id("main-thread"):

        def _worker():
            set_transaction_id("child-thread")
            assert get_transaction_id() == "child-thread"

        thread = threading.Thread(target=_worker)
        thread.start()
        thread.join()

        # the child's set did not leak into this thread
        assert get_transaction_id() == "main-thread"


@pytest.mark.unit
def test_transaction_id_context_manager_restores():
    """the context manager sets the id for the block then restores the prior
    value, including across nesting"""
    set_transaction_id("outer")
    try:
        with transaction_id("inner") as tid:
            assert tid == "inner"
            assert get_transaction_id() == "inner"
            with transaction_id("nested"):
                assert get_transaction_id() == "nested"
            assert get_transaction_id() == "inner"
        assert get_transaction_id() == "outer"
    finally:
        # leave a fresh default so the bare set above doesn't leak to later tests
        initialize_transaction_id()


@pytest.mark.unit
def test_transaction_id_context_manager_generates_uuid4():
    """with no argument the context manager generates a uuid4 and restores after"""
    before = get_transaction_id()
    with transaction_id() as tid:
        uuid.UUID(tid)
        assert get_transaction_id() == tid
        assert tid != before
    assert get_transaction_id() == before


@pytest.mark.unit
def test_transaction_id_filter_stamps_record():
    """the filter stamps the current transaction id onto the record and the
    formatter emits it exactly once"""
    with transaction_id("stamp-me"):
        record = logging.LogRecord(
            name="root", level=logging.INFO, pathname="test.py", lineno=1,
            msg="hello", args=(), exc_info=None,
        )
        result = TransactionIdFilter().filter(record)
        assert result is True
        assert record.transactionId == "stamp-me"

        data = _make_formatter().format(record)
        assert data["transactionId"] == "stamp-me"


@pytest.mark.unit
def test_install_transaction_id_filter_idempotent():
    """installing the filter twice leaves exactly one filter on the handler"""
    root_logger = logging.getLogger()
    handler = logging.NullHandler()
    root_logger.addHandler(handler)
    try:
        _install_transaction_id_filter()
        _install_transaction_id_filter()
        installed = [f for f in handler.filters if isinstance(f, TransactionIdFilter)]
        assert len(installed) == 1
    finally:
        root_logger.removeHandler(handler)
