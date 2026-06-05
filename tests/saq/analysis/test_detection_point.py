import pytest

from saq.analysis.detection_point import DetectionPoint


@pytest.mark.unit
def test_queue_round_trips_through_json():
    dp = DetectionPoint("matched a rule", details={"k": "v"}, queue="experimental")
    restored = DetectionPoint.from_json(dp.json)

    assert restored.description == "matched a rule"
    assert restored.details == {"k": "v"}
    assert restored.queue == "experimental"


@pytest.mark.unit
def test_queue_defaults_to_none():
    dp = DetectionPoint("matched a rule")
    assert dp.queue is None
    assert DetectionPoint.from_json(dp.json).queue is None


@pytest.mark.unit
def test_equality_considers_queue():
    a = DetectionPoint("same", queue="alpha")
    b = DetectionPoint("same", queue="bravo")
    c = DetectionPoint("same", queue="alpha")

    assert a != b
    assert a == c
