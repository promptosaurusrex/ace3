import logging
from typing import override
import redis

from saq.analysis import Analysis
from saq.signatures import OBSERVABLE_FLAGGED
from saq.configuration.config import get_config
from saq.constants import REDIS_DB_FOR_DETECTION_A, AnalysisExecutionResult
from saq.modules import AnalysisModule

KEY_FOR_DETECTION = "for_detection"

class ObservableDetectionAnalysis(Analysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_FOR_DETECTION: False,
        }

    @override
    @property
    def display_name(self) -> str:
        return "Observable Detection Analysis"

    @property
    def for_detection(self) -> bool:
        return self.details[KEY_FOR_DETECTION]

    @for_detection.setter
    def for_detection(self, value: bool):
        self.details[KEY_FOR_DETECTION] = value

    def generate_summary(self):
        # Only generate a summary if the observable is enabled for detection
        if self.for_detection:
            return f"{self.display_name}: enabled for detection"
        else:
            return None


class ObservableDetectionAnalyzer(AnalysisModule):
    """Checks if any observable is enabled for detection and, if so, will add a detection point."""

    @property
    def generated_analysis_type(self):
        return ObservableDetectionAnalysis

    @property
    def valid_observable_types(self):
        # None here denotes that it will run on all observable types
        return None

    def execute_analysis(self, observable, **kwargs) -> AnalysisExecutionResult:
        analysis = self.create_analysis(observable)
        assert isinstance(analysis, ObservableDetectionAnalysis)

        if "redis_connection" in kwargs:
            redis_connection = kwargs["redis_connection"]
        else:
            redis_connection = redis.Redis(
                host=get_config().redis_local.host,
                port=get_config().redis_local.port,
                username=get_config().redis_local.username,
                password=get_config().redis_local.password,
                db=REDIS_DB_FOR_DETECTION_A,
                decode_responses=True,
                encoding="utf-8"
            )

        if redis_connection.get(f"{observable.type}:{observable.value}"):
            logging.info(f"observable {observable.type}:{observable.value} is enabled for detection")
            analysis.for_detection = True
            observable.add_detection_point(f"Observable {observable.type}:{observable.value} is enabled for detection", signature_uuid=OBSERVABLE_FLAGGED.uuid)
            observable.add_tag(f"detect_{observable.type}")
        else:
            logging.debug(f"observable {observable.type}:{observable.value} is not enabled for detection")

        return AnalysisExecutionResult.COMPLETED