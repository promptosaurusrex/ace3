from saq.analysis.detection_point import DetectionPoint


class DetectionManager:
    """Manages detection-related functionality for any object through composition."""

    KEY_DETECTIONS = 'detections'

    def __init__(self, detections: list[DetectionPoint]):
        self._detections: list[DetectionPoint] = detections

    @property
    def detections(self) -> list[DetectionPoint]:
        return self._detections

    @detections.setter
    def detections(self, value: DetectionPoint):
        assert isinstance(value, list)
        assert all([isinstance(x, DetectionPoint) for x in value]) or all([isinstance(x, dict) for x in value])
        # we manage a reference to the list so we can't just set it to the new value
        self._detections.clear()
        self._detections.extend(value)

    def has_detection_points(self) -> bool:
        """Returns True if this object has at least one detection point, False otherwise."""
        return len(self._detections) != 0

    def add_detection_point(self, description: str, details=None, queue=None,
                            signature_uuid=None, signature_version=None) -> DetectionPoint:
        """Adds the given detection point to this object."""
        assert isinstance(description, str)
        assert description

        detection = DetectionPoint(description, details, queue, signature_uuid, signature_version)

        if detection in self._detections:
            return detection

        self._detections.append(detection)
        return detection

    def clear_detection_points(self):
        self._detections.clear()

    def get_json_data(self) -> dict:
        """Returns detection data for JSON serialization."""
        return {DetectionManager.KEY_DETECTIONS: self._detections}

    def set_json_data(self, value):
        """Sets detection data from JSON deserialization."""
        if DetectionManager.KEY_DETECTIONS in value:
            self._detections = value[DetectionManager.KEY_DETECTIONS]
