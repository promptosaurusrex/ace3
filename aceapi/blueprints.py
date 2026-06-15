from flask import Blueprint, Flask

analysis_bp = Blueprint('analysis', __name__, url_prefix='/analysis')
engine_bp = Blueprint('engine', __name__, url_prefix='/engine')
email_bp = Blueprint('email', __name__, url_prefix='/email')
intel_bp = Blueprint('intel', __name__, url_prefix='/intel')
hunt_bp = Blueprint('hunt', __name__, url_prefix='/hunt')

def register_blueprints(flask_app: Flask):
    import aceapi.analysis
    import aceapi.engine
    import aceapi.email
    import aceapi.intel
    import aceapi.hunt

    flask_app.register_blueprint(analysis_bp)
    flask_app.register_blueprint(engine_bp)
    flask_app.register_blueprint(email_bp)
    flask_app.register_blueprint(intel_bp)
    flask_app.register_blueprint(hunt_bp)