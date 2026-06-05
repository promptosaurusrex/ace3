import pytest

from saq.query.field_lookup import (
    FIELD_LOOKUP_TYPE_DOT,
    FIELD_LOOKUP_TYPE_KEY,
    extract_event_value,
)


@pytest.mark.unit
def test_key_lookup_present():
    """key lookup returns the literal dictionary value."""
    success, value = extract_event_value({"a.b": "x"}, FIELD_LOOKUP_TYPE_KEY, "a.b")
    assert (success, value) == (True, "x")


@pytest.mark.unit
def test_key_lookup_missing():
    success, value = extract_event_value({}, FIELD_LOOKUP_TYPE_KEY, "a.b")
    assert (success, value) == (False, None)


@pytest.mark.unit
def test_dot_lookup_nested():
    success, value = extract_event_value(
        {"device": {"hostname": "h1"}}, FIELD_LOOKUP_TYPE_DOT, "device.hostname"
    )
    assert (success, value) == (True, "h1")


@pytest.mark.unit
def test_dot_lookup_numeric_index_regression():
    """A non-wildcard numeric-index path still resolves a single list element."""
    success, value = extract_event_value(
        {"logs": [{"cid": "a"}, {"cid": "b"}]}, FIELD_LOOKUP_TYPE_DOT, "logs.1.cid"
    )
    assert (success, value) == (True, "b")


@pytest.mark.unit
def test_dot_lookup_missing_path():
    success, value = extract_event_value({}, FIELD_LOOKUP_TYPE_DOT, "device.hostname")
    assert (success, value) == (False, None)


@pytest.mark.unit
def test_dot_lookup_empty_segment_rejected():
    success, value = extract_event_value({"a": {"b": 1}}, FIELD_LOOKUP_TYPE_DOT, "a..b")
    assert (success, value) == (False, None)


@pytest.mark.unit
def test_wildcard_plucks_each_item():
    success, value = extract_event_value(
        {"logs": [{"cid": "a"}, {"cid": "b"}, {"cid": "c"}]},
        FIELD_LOOKUP_TYPE_DOT,
        "logs.*.cid",
    )
    assert (success, value) == (True, ["a", "b", "c"])


@pytest.mark.unit
def test_wildcard_skips_items_missing_subkey():
    success, value = extract_event_value(
        {"logs": [{"cid": "a"}, {"other": "x"}, {"cid": "c"}]},
        FIELD_LOOKUP_TYPE_DOT,
        "logs.*.cid",
    )
    assert (success, value) == (True, ["a", "c"])


@pytest.mark.unit
def test_wildcard_empty_list():
    success, value = extract_event_value(
        {"logs": []}, FIELD_LOOKUP_TYPE_DOT, "logs.*.cid"
    )
    assert (success, value) == (True, [])


@pytest.mark.unit
def test_wildcard_missing_top_key_is_not_present():
    """Missing top-level list key reports not-present (success=False), not an empty list."""
    success, value = extract_event_value({}, FIELD_LOOKUP_TYPE_DOT, "logs.*.cid")
    assert (success, value) == (False, None)


@pytest.mark.unit
def test_trailing_wildcard_returns_items():
    success, value = extract_event_value(
        {"ips": ["1.1.1.1", "2.2.2.2"]}, FIELD_LOOKUP_TYPE_DOT, "ips.*"
    )
    assert (success, value) == (True, ["1.1.1.1", "2.2.2.2"])


@pytest.mark.unit
def test_wildcard_nested_subpath():
    """The segments after '*' may themselves be a multi-level path."""
    success, value = extract_event_value(
        {"logs": [{"meta": {"id": 1}}, {"meta": {"id": 2}}]},
        FIELD_LOOKUP_TYPE_DOT,
        "logs.*.meta.id",
    )
    assert (success, value) == (True, [1, 2])
