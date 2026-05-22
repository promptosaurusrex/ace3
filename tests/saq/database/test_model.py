import pytest

from saq.constants import F_TEST
from saq.database.model import Alert, load_alert
from saq.database.pool import get_db
from saq.database.util.alert import ALERT
from tests.saq.helpers import create_root_analysis, insert_alert

from saq.database import Observable
from sqlalchemy import func

@pytest.mark.integration
def test_load_alert():
    # since we're storing the data in two places (json and database)
    # make sure that when we load() and Alert we don't immediately make it "dirty" to the ORM

    alert = insert_alert()
    alert_id = alert.id
    get_db().close()
    assert not get_db().dirty

    for alert in get_db().query(Alert).filter(Alert.id == alert_id):
        assert not get_db().dirty
        alert.load()
        assert not get_db().dirty

@pytest.mark.integration
def test_alert_log_error_on_load(caplog):
    # the log_error_on_load flag set on an Alert should propagate to the
    # RootAnalysis created by load() and produce an ERROR log message
    alert = insert_alert()
    alert_id = alert.id
    get_db().close()

    for alert in get_db().query(Alert).filter(Alert.id == alert_id):
        # default is False, so no error is logged
        alert.load()
        assert not [r for r in caplog.records if r.levelname == "ERROR"]

        # with the flag set, load() logs an error
        alert.set_log_error_on_load(True)
        alert.load()
        error_records = [r for r in caplog.records if r.levelname == "ERROR"]
        assert len(error_records) == 1
        assert alert.storage_dir in error_records[0].getMessage()

@pytest.mark.integration
def test_insert_alert_name_too_long():
    # make an alert with a description that is too long
    root_analysis = create_root_analysis(desc = 'A' * 1025)
    root_analysis.save()
    ALERT(root_analysis)
    alert = load_alert(root_analysis.uuid)
    assert alert is not None

    assert len(alert.description) == 1024

@pytest.mark.integration
def test_sync_observable_mapping():
    root_analysis = create_root_analysis()
    root_analysis.save()
    ALERT(root_analysis)
    alert = load_alert(root_analysis.uuid)
    assert alert is not None

    test_observable = alert.root_analysis.add_observable_by_spec(F_TEST, 'test_1')
    assert test_observable
    alert.sync_observable_mapping(test_observable)

    observable = get_db().query(Observable).filter(Observable.type == test_observable.type, Observable.sha256 == func.UNHEX(test_observable.sha256_hash)).first()
    assert observable