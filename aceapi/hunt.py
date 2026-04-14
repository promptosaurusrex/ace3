from datetime import datetime
import logging
import os
import shutil
import tempfile
from typing import List, Optional

import pytz
import yaml
from flask import jsonify, request
from pydantic import BaseModel, ValidationError

from aceapi.auth import api_auth_check
from aceapi.blueprints import hunt_bp
from hunt_compiler import CompiledHunt, load_compiled_hunt
from saq.analysis.root import RootAnalysis
from saq.collectors.hunter.loader import peek_hunt_type
from saq.collectors.hunter.query_hunter import QueryHunt
from saq.collectors.hunter.service import HunterService
from saq.configuration import get_config
from saq.constants import ANALYSIS_MODE_CORRELATION, QUEUE_DEFAULT
from saq.error.remote import RemoteApiError
from saq.database.util.alert import ALERT
from saq.environment import get_data_dir
from saq.util.uuid import storage_dir_from_uuid


def get_compiled_hunt_dir() -> str:
    """Return a directory for compiled hunt temp files that supports execution.

    The default temp directory (/tmp) may be mounted as a noexec tmpfs in Docker,
    preventing extracted scripts from being executed. This uses a configurable
    subdirectory under the data directory instead.
    """
    path = os.path.join(get_data_dir(), get_config().global_settings.compiled_hunt_dir)
    os.makedirs(path, exist_ok=True)
    return path


class ListLogHandler(logging.Handler):
    """A logging handler that collects log records into a list."""
    def __init__(self, log_list: List[logging.LogRecord]):
        super().__init__()
        self.log_list = log_list
        self.setLevel(logging.INFO)

    def emit(self, record: logging.LogRecord):
        """Append the log record to the list."""
        self.log_list.append(record)


class ExecutionArguments(BaseModel):
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    timezone: Optional[str] = None
    analyze_results: bool = False
    create_alerts: bool = False
    queue: str = QUEUE_DEFAULT
    # Optional override: when set, the hunt's data-source query is skipped and these
    # events are fed directly into process_query_results. Useful for iterating on
    # correlation logic against a previously captured event list. When provided,
    # start_time/end_time are not required.
    query_results: Optional[list[dict]] = None


def _validate_and_execute(target_file_path: str, request_json: dict):
    """Validate and optionally execute a hunt from its target file path.

    Returns:
        Flask response tuple (response, status_code).
    """
    try:
        hunt_type = peek_hunt_type(target_file_path)
    except FileNotFoundError:
        return jsonify({"valid": False, "error": "target file not found"}), 400
    except yaml.YAMLError as e:
        return jsonify({"valid": False, "error": f"YAML syntax error: {e}"}), 400
    except ValueError as e:
        return jsonify({"valid": False, "error": f"invalid hunt config: {e}"}), 400

    # load it using the HuntManager
    hunter_service = HunterService()
    hunter_service.load_hunt_managers()
    try:
        manager = hunter_service.hunt_managers[hunt_type]
    except KeyError:
        return jsonify({"valid": False, "error": f"invalid hunt type {hunt_type}"}), 400

    # validate the hunt config with the appropriate class
    try:
        hunt = manager.load_hunt_from_config(target_file_path)
    except ValidationError as e:
        return jsonify({"valid": False, "error": f"invalid hunt config: {e}"}), 400

    # are we executing the hunt?
    execution_arguments_dict = request_json.get("execution_arguments", {})
    if not execution_arguments_dict:
        return jsonify({"valid": True}), 200

    try:
        execution_arguments = ExecutionArguments.model_validate(execution_arguments_dict)
    except ValidationError as e:
        return jsonify({"valid": False, "error": f"invalid execution_arguments: {e}"}), 400

    exec_kwargs = {}
    use_query_results_override = execution_arguments.query_results is not None

    if isinstance(hunt, QueryHunt) and not use_query_results_override:
        if execution_arguments.start_time is None:
            return jsonify({"valid": False, "error": "start_time is required for query hunts"}), 400

        if execution_arguments.end_time is None:
            return jsonify({"valid": False, "error": "end_time is required for query hunts"}), 400

        try:
            start_time = datetime.strptime(execution_arguments.start_time, '%m/%d/%Y:%H:%M:%S')
        except ValueError:
            return jsonify({"valid": False, "error": "invalid start_time format: expected MM/DD/YYYY:HH:MM:SS"}), 400

        try:
            end_time = datetime.strptime(execution_arguments.end_time, '%m/%d/%Y:%H:%M:%S')
        except ValueError:
            return jsonify({"valid": False, "error": "invalid end_time format: expected MM/DD/YYYY:HH:MM:SS"}), 400

        if execution_arguments.timezone is not None:
            try:
                tz = pytz.timezone(execution_arguments.timezone)
            except pytz.exceptions.UnknownTimeZoneError:
                return jsonify({"valid": False, "error": f"invalid timezone: '{execution_arguments.timezone}'"}), 400
            start_time = tz.localize(start_time)
            end_time = tz.localize(end_time)
        else:
            start_time = pytz.utc.localize(start_time)
            end_time = pytz.utc.localize(end_time)

        exec_kwargs['start_time'] = start_time
        exec_kwargs['end_time'] = end_time

    # Set up logging handler to collect all logs
    collected_logs: List[logging.LogRecord] = []
    log_handler = ListLogHandler(collected_logs)
    root_logger = logging.getLogger()
    root_logger.addHandler(log_handler)

    try:
        try:
            # Don't persist execution state; validation runs must not affect scheduled automation
            hunt.manual_hunt = True
            if use_query_results_override:
                # Skip the data-source query and feed the supplied events directly
                # into process_query_results so correlation logic can be exercised
                # against a previously captured event list.
                submissions = hunt.process_query_results(execution_arguments.query_results)
            else:
                submissions = hunt.execute(**exec_kwargs)
        except RemoteApiError as e:
            return jsonify({"valid": False, "error": e.message, "remote_status_code": e.status_code}), 400
        except Exception as e:
            return jsonify({"valid": False, "error": f"error executing hunt: {e}"}), 400

        if submissions is None:
            submissions = []

        roots: list[RootAnalysis] = []
        for submission in submissions:
            if execution_arguments.analyze_results or execution_arguments.create_alerts:
                # we duplicate because we could be sending multiple copies to multiple remote nodes
                new_root = submission.root.duplicate()
                new_root.move(storage_dir_from_uuid(new_root.uuid))
                new_root.queue = execution_arguments.queue
                new_root.save()

                # if we received a submission for correlation mode then we go ahead and add it to the database
                if execution_arguments.create_alerts:
                    new_root.analysis_mode = ANALYSIS_MODE_CORRELATION
                    ALERT(new_root)

                new_root.schedule()
                roots.append(new_root)
            else:
                roots.append(submission.root)

        # a little quirck which how ACE works
        # the details are typically not loaded until they are needed
        # so we need to explicitly load them here

        root_json_results = []
        for root in roots:
            root_json = root.json
            # this forces the load and places the result in the json
            root_json["details"] = root.details
            root_json_results.append(root_json)

        log_format = '[%(asctime)s] [%(filename)s:%(lineno)d] [%(threadName)s] [%(process)d] [%(levelname)s] - %(message)s'
        log_formatter = logging.Formatter(log_format)
        formatted_logs = []
        for record in collected_logs:
            formatted_logs.append(log_formatter.format(record))

        correlation_trace = None
        if hasattr(hunt, "correlation_trace") and hunt.correlation_trace is not None:
            correlation_trace = hunt.correlation_trace.model_dump()

        original_events = None
        if getattr(hunt, "original_query_results", None) is not None:
            original_events = hunt.original_query_results

        return jsonify({
            "valid": True,
            "roots": root_json_results,
            "logs": formatted_logs,
            "correlation_trace": correlation_trace,
            "original_events": original_events,
        }), 200
    finally:
        root_logger.removeHandler(log_handler)


@hunt_bp.route('/validate', methods=['POST'])
@api_auth_check("hunt", "write")
def validate_hunt():
    if not request.json:
        return jsonify({"valid": False, "error": "request body must be JSON"}), 400

    if "compiled_hunt" not in request.json:
        return jsonify({"valid": False, "error": "missing 'compiled_hunt' field"}), 400

    try:
        compiled = CompiledHunt.model_validate(request.json["compiled_hunt"])
    except ValidationError as e:
        return jsonify({"valid": False, "error": f"invalid compiled_hunt: {e}"}), 400

    temp_dir = tempfile.mkdtemp(dir=get_compiled_hunt_dir())

    try:
        try:
            logging.debug(
                "loading compiled hunt version=%s package_root=%s assets=%s",
                compiled.version,
                compiled.package_root,
                len(compiled.assets),
            )
            target_file_path = load_compiled_hunt(compiled, temp_dir)
        except Exception as e:
            return jsonify({"valid": False, "error": f"error loading compiled hunt: {e}"}), 400

        return _validate_and_execute(target_file_path, request.json)
    finally:
        shutil.rmtree(temp_dir)
