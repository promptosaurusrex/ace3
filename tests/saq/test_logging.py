"""Tests for ExtraAwareFluentFormatter."""
import logging

import pytest

from saq.logging import ExtraAwareFluentFormatter


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

    logger.addHandler(_Probe())
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
