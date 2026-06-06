import json

import pytest
from sqlalchemy.exc import IntegrityError

from saq.database import db_DetectionPoint
from saq.database.model import Alert
from saq.database.pool import get_db
from tests.saq.helpers import insert_alert


def _make_row(alert_id, content_hash="hash-1", **kwargs):
    fields = dict(
        alert_id=alert_id,
        description="matched a rule",
        details=json.dumps({"k": "v"}),
        queue="default",
        signature_uuid="11111111-1111-1111-1111-111111111111",
        signature_version="deadbeef",
        content_hash=content_hash,
    )
    fields.update(kwargs)
    return db_DetectionPoint(**fields)


@pytest.mark.integration
def test_insert_and_read_back():
    alert = insert_alert()
    row = _make_row(alert.id)
    get_db().add(row)
    get_db().commit()

    read = get_db().query(db_DetectionPoint).filter(db_DetectionPoint.id == row.id).one()
    assert read.alert_id == alert.id
    assert read.description == "matched a rule"
    assert read.queue == "default"
    assert read.signature_uuid == "11111111-1111-1111-1111-111111111111"
    assert read.signature_version == "deadbeef"
    assert read.content_hash == "hash-1"
    assert read.insert_date is not None
    # details is JSON-as-text
    assert json.loads(read.details) == {"k": "v"}


@pytest.mark.integration
def test_cascade_delete_with_alert():
    alert = insert_alert()
    alert_id = alert.id
    row = _make_row(alert_id, content_hash="cascade-hash")
    get_db().add(row)
    get_db().commit()
    dp_id = row.id

    # delete the alert -> the detection_points row should be gone (ON DELETE CASCADE)
    get_db().query(Alert).filter(Alert.id == alert_id).delete()
    get_db().commit()

    assert get_db().query(db_DetectionPoint).filter(db_DetectionPoint.id == dp_id).first() is None


@pytest.mark.integration
def test_unique_alert_content_hash():
    alert = insert_alert()
    get_db().add(_make_row(alert.id, content_hash="dup"))
    get_db().commit()

    get_db().add(_make_row(alert.id, content_hash="dup"))
    with pytest.raises(IntegrityError):
        get_db().commit()
    get_db().rollback()


@pytest.mark.integration
@pytest.mark.parametrize("missing", ["alert_id", "signature_uuid", "signature_version", "content_hash"])
def test_not_null_columns(missing):
    alert = insert_alert()
    kwargs = dict(
        alert_id=alert.id,
        signature_uuid="u",
        signature_version="v",
        content_hash="c-" + missing,
    )
    kwargs[missing] = None
    row = db_DetectionPoint(description="d", **kwargs)
    get_db().add(row)
    with pytest.raises(IntegrityError):
        get_db().commit()
    get_db().rollback()


@pytest.mark.integration
def test_details_nullable():
    alert = insert_alert()
    row = _make_row(alert.id, content_hash="null-details", details=None)
    get_db().add(row)
    get_db().commit()
    read = get_db().query(db_DetectionPoint).filter(db_DetectionPoint.id == row.id).one()
    assert read.details is None
