from saq.util import sha256_str

KEY_DESCRIPTION = 'description'
KEY_DETAILS = 'details'
KEY_QUEUE = 'queue'

class DetectionPoint:
    """Represents an observation that would result in a detection."""

    def __init__(self, description=None, details=None, queue=None):
        self.description = description
        self.details = details
        # an optional queue this detection requests the resulting alert be routed to
        # (see saq.engine.analysis_orchestrator._apply_detection_queue)
        self.queue = queue

    @property
    def json(self):
        return {
            KEY_DESCRIPTION: self.description,
            KEY_DETAILS: self.details,
            KEY_QUEUE: self.queue }

    @json.setter
    def json(self, value):
        assert isinstance(value, dict)
        if KEY_DESCRIPTION in value:
            self.description = value[KEY_DESCRIPTION]
        if KEY_DETAILS in value:
            self.details = value[KEY_DETAILS]
        if KEY_QUEUE in value:
            self.queue = value[KEY_QUEUE]

    @staticmethod
    def from_json(dp_json):
        """Loads a DetectionPoint from a JSON dict. Used by _materalize."""
        dp = DetectionPoint()
        dp.json = dp_json
        return dp

    @property
    def display_description(self):
        if isinstance(self.description, str):
            return self.description.encode('unicode_escape').decode()
        else:
            return self.description

    @property
    def id(self):
        return sha256_str(str(self))

    def __str__(self):
        return "DetectionPoint({})".format(self.description)

    def __eq__(self, other):
        if not isinstance(other, DetectionPoint):
            return False

        return self.description == other.description and self.details == other.details and self.queue == other.queue