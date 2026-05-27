from aceapi.blueprints import register_blueprints
from saq.configuration import get_config
from saq.configuration.config import get_database_config
from saq.database.pool import remove_all_sessions, set_db

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event

from saq.monitor import emit_monitor
from saq.monitor_definitions import MONITOR_SQLALCHEMY_DB_POOL_STATUS
from saq.util import abs_path

class CustomSQLAlchemy(SQLAlchemy):
    def apply_driver_hacks(self, app, info, options):
        # are we using SSL for MySQL connections? (you should be)
        SQLAlchemy.apply_driver_hacks(self, app, info, options)

def create_app(testing=False):
    class _config(object):
        SECRET_KEY = get_config().api.secret_key
        SQLALCHEMY_TRACK_MODIFICATIONS = False

        INSTANCE_NAME = get_config().global_settings.instance_name

        # also see lib/saq/database.py:initialize_database
        db_config = get_database_config()
        if db_config.unix_socket:
            SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://{username}:{password}@{hostname}/{database}?unix_socket={unix_socket}&charset=utf8mb4'.format(
                username=db_config.username,
                password=db_config.password,
                hostname=db_config.hostname,
                database=db_config.database,
                unix_socket=db_config.unix_socket)
        else:
            SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://{username}:{password}@{hostname}:{port}/{database}?charset=utf8mb4'.format(
                username=db_config.username,
                password=db_config.password,
                hostname=db_config.hostname,
                port=db_config.port,
                database=db_config.database)

        SQLALCHEMY_POOL_TIMEOUT = 30
        SQLALCHEMY_POOL_RECYCLE = 60 * 10

        # gets passed as **kwargs to create_engine call of SQLAlchemy
        # this is used by the non-flask applications to configure SQLAlchemy db connection
        SQLALCHEMY_DATABASE_OPTIONS = { 
            'pool_recycle': SQLALCHEMY_POOL_RECYCLE,
            'pool_timeout': SQLALCHEMY_POOL_TIMEOUT,
            'pool_size': 5,
            'connect_args': { 'init_command': "SET NAMES utf8mb4" },
        }

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)

            # are we using SSL for MySQL connections? (you should be)
            db_config = get_database_config()
            if not db_config.unix_socket:
                if db_config.ssl_ca or db_config.ssl_cert or db_config.ssl_key:
                    ssl_options = { 'ca': abs_path(db_config.ssl_ca) }
                    if db_config.ssl_cert:
                        ssl_options['cert'] = abs_path(db_config.ssl_cert)
                    if db_config.ssl_key:
                        ssl_options['key'] = abs_path(db_config.ssl_key)
                    self.SQLALCHEMY_DATABASE_OPTIONS['connect_args']['ssl'] = ssl_options

    class _test_config(_config):
        TESTING = True

    flask_app = Flask(__name__)
    app_config = _test_config() if testing else _config()
    flask_app.config.from_object(app_config)

    db = CustomSQLAlchemy(engine_options=app_config.SQLALCHEMY_DATABASE_OPTIONS)
    if not testing:
        # XXX hack: tests will create test contexts but the database pool is global
        # we don't want to change it because things like collectors *also* manage the connections
        set_db(db.session)
    #set_g(G_DB, db)
    db.init_app(flask_app)

    @flask_app.teardown_appcontext
    def _remove_all_sessions(exception):
        # release thread-local sessions for every registered engine, not just
        # the ace session that flask-sqlalchemy manages on its own
        remove_all_sessions()

    with flask_app.app_context():
        @event.listens_for(db.engine, 'checkin')
        def checkin(dbapi_connection, connection_record):
            emit_monitor(MONITOR_SQLALCHEMY_DB_POOL_STATUS, db.engine.pool.status())

        @event.listens_for(db.engine, 'checkout')
        def checkout(dbapi_connection, connection_record, connection_proxy):
            emit_monitor(MONITOR_SQLALCHEMY_DB_POOL_STATUS, db.engine.pool.status())

    register_blueprints(flask_app)
    return flask_app
