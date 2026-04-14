import pytest
from unittest.mock import Mock, patch

from hunt_compiler.models import CompiledHunt, EmbeddedFile
from saq.configuration.config import get_config


# Valid hunt YAML content for reuse in tests
VALID_HUNT_YAML = """rule:
  uuid: 7b5f2270-4a1d-4009-86a0-de3f8c9c82e7
  enabled: yes
  name: test_hunt
  description: Test Hunt Description
  type: test
  alert_type: test - alert
  frequency: '00:10:00'
  instance_types:
    - unittest
  tags:
    - tag1
"""

# URL for the hunt validate endpoint
HUNT_VALIDATE_URL = "/hunt/validate"


def _make_compiled_payload(yaml_content, target="test.yaml", **kwargs):
    """Build a compiled_hunt request payload from raw YAML content."""
    compiled = CompiledHunt(
        target=target,
        root_dir="/tmp/test",
        yaml_files=[EmbeddedFile(path=target, content=yaml_content)],
        **kwargs,
    )
    return {"compiled_hunt": compiled.model_dump()}


@pytest.fixture
def auth_headers():
    """Returns authentication headers for API requests."""
    return {"x-ace-auth": get_config().api.api_key}


# =============================================================================
# Integration Tests for /hunt/validate Endpoint - Request Body Validation
# =============================================================================

@pytest.mark.integration
def test_validate_hunt_missing_json_body(test_client, auth_headers):
    """Verify missing JSON body (empty string) returns 400 Bad Request."""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        headers=auth_headers,
        data="",
        content_type="application/json"
    )
    assert result.status_code == 400


@pytest.mark.integration
def test_validate_hunt_non_json_content_type(test_client, auth_headers):
    """Verify non-JSON content type returns 415 Unsupported Media Type."""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        headers=auth_headers,
        data="some text",
        content_type="text/plain"
    )
    assert result.status_code == 415


@pytest.mark.integration
def test_validate_hunt_empty_json_body(test_client, auth_headers):
    """Verify empty JSON object returns error about missing compiled_hunt."""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json={},
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "request body must be JSON" in data["error"]


@pytest.mark.integration
def test_validate_hunt_missing_compiled_hunt_field(test_client, auth_headers):
    """Verify missing 'compiled_hunt' field returns appropriate error."""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json={"other_field": "value"},
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "missing 'compiled_hunt' field" in data["error"]


@pytest.mark.integration
def test_validate_hunt_invalid_compiled_hunt_format(test_client, auth_headers):
    """Verify invalid compiled_hunt format returns validation error."""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json={"compiled_hunt": "not-a-dict"},
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "invalid compiled_hunt" in data["error"]


@pytest.mark.integration
def test_validate_hunt_compiled_hunt_missing_required_fields(test_client, auth_headers):
    """Verify compiled_hunt missing required fields returns validation error."""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json={"compiled_hunt": {"version": 1}},
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "invalid compiled_hunt" in data["error"]


# =============================================================================
# Integration Tests for /hunt/validate Endpoint - YAML/Config Validation
# =============================================================================

@pytest.mark.integration
def test_validate_hunt_invalid_yaml_syntax(test_client, auth_headers):
    """Verify invalid YAML syntax returns validation error."""
    invalid_yaml = """rule:
  name: test
  invalid: yaml: : : syntax
  [broken
"""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json=_make_compiled_payload(invalid_yaml),
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "yaml syntax error" in data["error"].lower()


@pytest.mark.integration
def test_validate_hunt_missing_required_field_uuid(test_client, auth_headers):
    """Verify hunt config missing uuid field returns validation error."""
    yaml_missing_uuid = """rule:
  enabled: yes
  name: test_hunt
  description: Test Hunt
  type: test
  alert_type: test - alert
  frequency: '00:10:00'
"""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json=_make_compiled_payload(yaml_missing_uuid),
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "error" in data


@pytest.mark.integration
def test_validate_hunt_missing_required_field_name(test_client, auth_headers):
    """Verify hunt config missing name field returns validation error."""
    yaml_missing_name = """rule:
  uuid: 7b5f2270-4a1d-4009-86a0-de3f8c9c82e7
  enabled: yes
  description: Test Hunt
  type: test
  alert_type: test - alert
  frequency: '00:10:00'
"""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json=_make_compiled_payload(yaml_missing_name),
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "error" in data


@pytest.mark.integration
def test_validate_hunt_missing_required_field_type(test_client, auth_headers):
    """Verify hunt config missing type field returns validation error."""
    yaml_missing_type = """rule:
  uuid: 7b5f2270-4a1d-4009-86a0-de3f8c9c82e7
  enabled: yes
  name: test_hunt
  description: Test Hunt
  alert_type: test - alert
  frequency: '00:10:00'
"""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json=_make_compiled_payload(yaml_missing_type),
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "error" in data


@pytest.mark.integration
def test_validate_hunt_missing_required_field_frequency(test_client, auth_headers):
    """Verify hunt config missing frequency field returns validation error."""
    yaml_missing_frequency = """rule:
  uuid: 7b5f2270-4a1d-4009-86a0-de3f8c9c82e7
  enabled: yes
  name: test_hunt
  description: Test Hunt
  type: test
  alert_type: test - alert
"""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json=_make_compiled_payload(yaml_missing_frequency),
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "error" in data


@pytest.mark.integration
def test_validate_hunt_invalid_frequency_format(test_client, auth_headers):
    """Verify hunt config with invalid frequency format returns error."""
    yaml_invalid_frequency = """rule:
  uuid: 7b5f2270-4a1d-4009-86a0-de3f8c9c82e7
  enabled: yes
  name: test_hunt
  description: Test Hunt
  type: test
  alert_type: test - alert
  frequency: 'invalid_frequency'
"""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json=_make_compiled_payload(yaml_invalid_frequency),
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "error" in data


@pytest.mark.integration
def test_validate_hunt_unknown_hunt_type(test_client, auth_headers):
    """Verify unknown hunt type returns appropriate error."""
    yaml_unknown_type = """rule:
  uuid: 7b5f2270-4a1d-4009-86a0-de3f8c9c82e7
  enabled: yes
  name: test_hunt
  description: Test Hunt
  type: nonexistent_hunt_type_xyz
  alert_type: test - alert
  frequency: '00:10:00'
"""
    result = test_client.post(
        HUNT_VALIDATE_URL,
        json=_make_compiled_payload(yaml_unknown_type),
        headers=auth_headers
    )
    assert result.status_code == 400
    data = result.get_json()
    assert data["valid"] is False
    assert "invalid hunt type" in data["error"].lower()


# =============================================================================
# Integration Tests for /hunt/validate Endpoint - Success Cases
# =============================================================================

@pytest.mark.integration
def test_validate_hunt_valid_hunt_with_mock(test_client, auth_headers):
    """Verify a completely valid hunt passes validation with mocked service."""
    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        mock_manager.load_hunt_from_config.return_value = Mock()
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        result = test_client.post(
            HUNT_VALIDATE_URL,
            json=_make_compiled_payload(VALID_HUNT_YAML),
            headers=auth_headers
        )

        assert result.status_code == 200
        data = result.get_json()
        assert data["valid"] is True


@pytest.mark.integration
def test_validate_hunt_valid_hunt_with_includes(test_client, auth_headers):
    """Verify valid hunt with include files passes validation."""
    base_yaml = """rule:
  uuid: 7b5f2270-4a1d-4009-86a0-de3f8c9c82e7
  enabled: yes
  name: base_hunt
  description: Base Hunt Description
  type: test
  alert_type: test - alert
  frequency: '00:10:00'
  tags:
    - base_tag
"""
    main_yaml = """include:
  - includes/base.yaml
rule:
  name: main_hunt
  tags:
    - main_tag
"""

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        mock_manager.load_hunt_from_config.return_value = Mock()
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        payload = {
            "compiled_hunt": CompiledHunt(
                target="main.yaml",
                root_dir="/tmp/test",
                yaml_files=[
                    EmbeddedFile(path="includes/base.yaml", content=base_yaml),
                    EmbeddedFile(path="main.yaml", content=main_yaml),
                ],
            ).model_dump()
        }

        result = test_client.post(
            HUNT_VALIDATE_URL,
            json=payload,
            headers=auth_headers
        )

        assert result.status_code == 200
        data = result.get_json()
        assert data["valid"] is True


@pytest.mark.integration
def test_validate_hunt_nested_directory_structure(test_client, auth_headers):
    """Verify hunts with nested directory paths work correctly."""
    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        mock_manager.load_hunt_from_config.return_value = Mock()
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        result = test_client.post(
            HUNT_VALIDATE_URL,
            json=_make_compiled_payload(VALID_HUNT_YAML, target="hunts/subdir/nested/test.yaml"),
            headers=auth_headers
        )

        assert result.status_code == 200
        data = result.get_json()
        assert data["valid"] is True


# =============================================================================
# Integration Tests for /hunt/validate Endpoint - Execution Arguments Validation
# =============================================================================

@pytest.mark.integration
@pytest.mark.parametrize("execution_arguments,error_contains", [
    # Invalid type for analyze_results (non-coercible to bool)
    ({"analyze_results": "invalid"}, "execution_arguments"),
    ({"analyze_results": []}, "execution_arguments"),
    ({"analyze_results": {}}, "execution_arguments"),
    # Invalid type for create_alerts (non-coercible to bool)
    ({"create_alerts": "nope"}, "execution_arguments"),
    # Invalid type for queue (must be string)
    ({"queue": 123}, "execution_arguments"),
    ({"queue": ["default"]}, "execution_arguments"),
    # Invalid type for start_time (must be string or None)
    ({"start_time": 123}, "execution_arguments"),
])
def test_validate_hunt_execution_arguments_invalid_types(test_client, auth_headers, execution_arguments, error_contains):
    """Verify invalid execution_arguments field types return validation error."""
    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        mock_hunt = Mock()
        mock_manager.load_hunt_from_config.return_value = mock_hunt
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        payload = _make_compiled_payload(VALID_HUNT_YAML)
        payload["execution_arguments"] = execution_arguments

        result = test_client.post(
            HUNT_VALIDATE_URL,
            json=payload,
            headers=auth_headers
        )

        assert result.status_code == 400
        data = result.get_json()
        assert data["valid"] is False
        assert error_contains in data["error"].lower()


# =============================================================================
# Integration Tests for /hunt/validate Endpoint - Time Parsing (QueryHunt)
# =============================================================================

@pytest.mark.integration
def test_validate_hunt_execution_query_hunt_missing_start_time(test_client, auth_headers):
    """Verify QueryHunt without start_time returns clear error."""
    from saq.collectors.hunter.query_hunter import QueryHunt

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        mock_hunt = Mock(spec=QueryHunt)
        mock_manager.load_hunt_from_config.return_value = mock_hunt
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        payload = _make_compiled_payload(VALID_HUNT_YAML)
        payload["execution_arguments"] = {"end_time": "01/15/2025:12:00:00"}

        result = test_client.post(
            HUNT_VALIDATE_URL,
            json=payload,
            headers=auth_headers
        )

        assert result.status_code == 400
        data = result.get_json()
        assert data["valid"] is False
        assert "start_time is required" in data["error"]


@pytest.mark.integration
def test_validate_hunt_execution_query_hunt_missing_end_time(test_client, auth_headers):
    """Verify QueryHunt without end_time returns clear error."""
    from saq.collectors.hunter.query_hunter import QueryHunt

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        mock_hunt = Mock(spec=QueryHunt)
        mock_manager.load_hunt_from_config.return_value = mock_hunt
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        payload = _make_compiled_payload(VALID_HUNT_YAML)
        payload["execution_arguments"] = {"start_time": "01/15/2025:12:00:00"}

        result = test_client.post(
            HUNT_VALIDATE_URL,
            json=payload,
            headers=auth_headers
        )

        assert result.status_code == 400
        data = result.get_json()
        assert data["valid"] is False
        assert "end_time is required" in data["error"]


@pytest.mark.integration
@pytest.mark.parametrize("invalid_time,field_name", [
    ("2025-01-15 12:00:00", "start_time"),
    ("01-15-2025:12:00:00", "start_time"),
    ("01/15/2025 12:00:00", "start_time"),
    ("15/01/2025:12:00:00", "start_time"),
    ("not-a-date", "start_time"),
    ("", "start_time"),
    ("01/15/2025:25:00:00", "start_time"),
    ("01/15/2025:12:60:00", "start_time"),
])
def test_validate_hunt_execution_invalid_start_time_format(test_client, auth_headers, invalid_time, field_name):
    """Verify invalid start_time format returns clear error with expected format."""
    from saq.collectors.hunter.query_hunter import QueryHunt

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        mock_hunt = Mock(spec=QueryHunt)
        mock_manager.load_hunt_from_config.return_value = mock_hunt
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        payload = _make_compiled_payload(VALID_HUNT_YAML)
        payload["execution_arguments"] = {
            "start_time": invalid_time,
            "end_time": "01/15/2025:12:00:00"
        }

        result = test_client.post(
            HUNT_VALIDATE_URL,
            json=payload,
            headers=auth_headers
        )

        assert result.status_code == 400
        data = result.get_json()
        assert data["valid"] is False
        assert "start_time" in data["error"].lower()
        assert "MM/DD/YYYY:HH:MM:SS" in data["error"]


@pytest.mark.integration
@pytest.mark.parametrize("invalid_time", [
    "2025-01-15 12:00:00",
    "not-a-date",
    "",
])
def test_validate_hunt_execution_invalid_end_time_format(test_client, auth_headers, invalid_time):
    """Verify invalid end_time format returns clear error with expected format."""
    from saq.collectors.hunter.query_hunter import QueryHunt

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        mock_hunt = Mock(spec=QueryHunt)
        mock_manager.load_hunt_from_config.return_value = mock_hunt
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        payload = _make_compiled_payload(VALID_HUNT_YAML)
        payload["execution_arguments"] = {
            "start_time": "01/15/2025:10:00:00",
            "end_time": invalid_time
        }

        result = test_client.post(
            HUNT_VALIDATE_URL,
            json=payload,
            headers=auth_headers
        )

        assert result.status_code == 400
        data = result.get_json()
        assert data["valid"] is False
        assert "end_time" in data["error"].lower()
        assert "MM/DD/YYYY:HH:MM:SS" in data["error"]


# =============================================================================
# Integration Tests for /hunt/validate Endpoint - Timezone Handling
# =============================================================================

@pytest.mark.integration
def test_validate_hunt_execution_invalid_timezone(test_client, auth_headers):
    """Verify invalid timezone returns clear error."""
    from saq.collectors.hunter.query_hunter import QueryHunt

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        mock_hunt = Mock(spec=QueryHunt)
        mock_manager.load_hunt_from_config.return_value = mock_hunt
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        payload = _make_compiled_payload(VALID_HUNT_YAML)
        payload["execution_arguments"] = {
            "start_time": "01/15/2025:10:00:00",
            "end_time": "01/15/2025:12:00:00",
            "timezone": "Invalid/Timezone"
        }

        result = test_client.post(
            HUNT_VALIDATE_URL,
            json=payload,
            headers=auth_headers
        )

        assert result.status_code == 400
        data = result.get_json()
        assert data["valid"] is False
        assert "invalid timezone" in data["error"].lower()
        assert "Invalid/Timezone" in data["error"]


@pytest.mark.integration
@pytest.mark.parametrize("timezone", [
    "America/New_York",
    "Europe/London",
    "Asia/Tokyo",
    "UTC",
    "US/Eastern",
])
def test_validate_hunt_execution_valid_timezones(test_client, auth_headers, timezone):
    """Verify valid timezones are accepted."""
    from saq.collectors.hunter.query_hunter import QueryHunt

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        mock_hunt = Mock(spec=QueryHunt)
        mock_hunt.execute.return_value = []
        mock_manager.load_hunt_from_config.return_value = mock_hunt
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        payload = _make_compiled_payload(VALID_HUNT_YAML)
        payload["execution_arguments"] = {
            "start_time": "01/15/2025:10:00:00",
            "end_time": "01/15/2025:12:00:00",
            "timezone": timezone
        }

        result = test_client.post(
            HUNT_VALIDATE_URL,
            json=payload,
            headers=auth_headers
        )

        assert result.status_code == 200
        data = result.get_json()
        assert data["valid"] is True


# =============================================================================
# Integration Tests for /hunt/validate Endpoint - Execution Success Cases
# =============================================================================

@pytest.mark.integration
def test_validate_hunt_execution_success_no_analyze_no_alerts(test_client, auth_headers):
    """Verify successful execution without analyze_results or create_alerts."""
    from saq.collectors.hunter.query_hunter import QueryHunt
    from saq.analysis.root import Submission, RootAnalysis

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        mock_hunt = Mock(spec=QueryHunt)

        mock_root = Mock(spec=RootAnalysis)
        mock_root.json = {"uuid": "test-uuid-123", "description": "Test Hunt"}
        mock_root.details = {"query": "test query", "events": []}
        mock_submission = Mock(spec=Submission)
        mock_submission.root = mock_root

        mock_hunt.execute.return_value = [mock_submission]
        mock_manager.load_hunt_from_config.return_value = mock_hunt
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        payload = _make_compiled_payload(VALID_HUNT_YAML)
        payload["execution_arguments"] = {
            "start_time": "01/15/2025:10:00:00",
            "end_time": "01/15/2025:12:00:00"
        }

        result = test_client.post(
            HUNT_VALIDATE_URL,
            json=payload,
            headers=auth_headers
        )

        assert result.status_code == 200
        data = result.get_json()
        assert data["valid"] is True
        assert "roots" in data
        assert "logs" in data
        assert len(data["roots"]) == 1
        assert data["roots"][0]["details"] == {"query": "test query", "events": []}


@pytest.mark.integration
def test_validate_hunt_execution_success_with_analyze_results(test_client, auth_headers):
    """Verify successful execution with analyze_results=True."""
    from saq.collectors.hunter.query_hunter import QueryHunt
    from saq.analysis.root import Submission, RootAnalysis

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        with patch("aceapi.hunt.storage_dir_from_uuid") as mock_storage_dir:
            mock_storage_dir.return_value = "/tmp/test-storage"

            mock_manager = Mock()
            mock_hunt = Mock(spec=QueryHunt)

            mock_root = Mock(spec=RootAnalysis)
            mock_root.json = {"uuid": "test-uuid-123", "description": "Test Hunt"}
            mock_root.details = {"query": "test query"}

            mock_new_root = Mock(spec=RootAnalysis)
            mock_new_root.json = {"uuid": "new-uuid-456", "description": "Test Hunt"}
            mock_new_root.details = {"query": "test query"}
            mock_new_root.uuid = "new-uuid-456"
            mock_root.duplicate.return_value = mock_new_root

            mock_submission = Mock(spec=Submission)
            mock_submission.root = mock_root

            mock_hunt.execute.return_value = [mock_submission]
            mock_manager.load_hunt_from_config.return_value = mock_hunt
            mock_instance = mock_hunter_service.return_value
            mock_instance.hunt_managers = {"test": mock_manager}
            mock_instance.load_hunt_managers = Mock()

            payload = _make_compiled_payload(VALID_HUNT_YAML)
            payload["execution_arguments"] = {
                "start_time": "01/15/2025:10:00:00",
                "end_time": "01/15/2025:12:00:00",
                "analyze_results": True
            }

            result = test_client.post(
                HUNT_VALIDATE_URL,
                json=payload,
                headers=auth_headers
            )

            assert result.status_code == 200
            data = result.get_json()
            assert data["valid"] is True
            assert "roots" in data
            mock_root.duplicate.assert_called_once()
            mock_new_root.move.assert_called_once_with("/tmp/test-storage")
            mock_new_root.save.assert_called()
            mock_new_root.schedule.assert_called_once()


@pytest.mark.integration
def test_validate_hunt_execution_success_with_create_alerts(test_client, auth_headers):
    """Verify successful execution with create_alerts=True."""
    from saq.collectors.hunter.query_hunter import QueryHunt
    from saq.analysis.root import Submission, RootAnalysis
    from saq.constants import ANALYSIS_MODE_CORRELATION

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        with patch("aceapi.hunt.storage_dir_from_uuid") as mock_storage_dir:
            with patch("aceapi.hunt.ALERT") as mock_alert:
                mock_storage_dir.return_value = "/tmp/test-storage"

                mock_manager = Mock()
                mock_hunt = Mock(spec=QueryHunt)

                mock_root = Mock(spec=RootAnalysis)
                mock_root.json = {"uuid": "test-uuid-123", "description": "Test Hunt"}
                mock_root.details = {"query": "test query"}

                mock_new_root = Mock(spec=RootAnalysis)
                mock_new_root.json = {"uuid": "new-uuid-456", "description": "Test Hunt"}
                mock_new_root.details = {"query": "test query"}
                mock_new_root.uuid = "new-uuid-456"
                mock_root.duplicate.return_value = mock_new_root

                mock_submission = Mock(spec=Submission)
                mock_submission.root = mock_root

                mock_hunt.execute.return_value = [mock_submission]
                mock_manager.load_hunt_from_config.return_value = mock_hunt
                mock_instance = mock_hunter_service.return_value
                mock_instance.hunt_managers = {"test": mock_manager}
                mock_instance.load_hunt_managers = Mock()

                payload = _make_compiled_payload(VALID_HUNT_YAML)
                payload["execution_arguments"] = {
                    "start_time": "01/15/2025:10:00:00",
                    "end_time": "01/15/2025:12:00:00",
                    "create_alerts": True
                }

                result = test_client.post(
                    HUNT_VALIDATE_URL,
                    json=payload,
                    headers=auth_headers
                )

                assert result.status_code == 200
                data = result.get_json()
                assert data["valid"] is True
                mock_alert.assert_called_once_with(mock_new_root)
                assert mock_new_root.analysis_mode == ANALYSIS_MODE_CORRELATION


@pytest.mark.integration
def test_validate_hunt_execution_success_with_custom_queue(test_client, auth_headers):
    """Verify successful execution with custom queue."""
    from saq.collectors.hunter.query_hunter import QueryHunt
    from saq.analysis.root import Submission, RootAnalysis

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        with patch("aceapi.hunt.storage_dir_from_uuid") as mock_storage_dir:
            mock_storage_dir.return_value = "/tmp/test-storage"

            mock_manager = Mock()
            mock_hunt = Mock(spec=QueryHunt)

            mock_root = Mock(spec=RootAnalysis)
            mock_root.json = {"uuid": "test-uuid-123"}
            mock_root.details = {}

            mock_new_root = Mock(spec=RootAnalysis)
            mock_new_root.json = {"uuid": "new-uuid-456"}
            mock_new_root.details = {}
            mock_new_root.uuid = "new-uuid-456"
            mock_root.duplicate.return_value = mock_new_root

            mock_submission = Mock(spec=Submission)
            mock_submission.root = mock_root

            mock_hunt.execute.return_value = [mock_submission]
            mock_manager.load_hunt_from_config.return_value = mock_hunt
            mock_instance = mock_hunter_service.return_value
            mock_instance.hunt_managers = {"test": mock_manager}
            mock_instance.load_hunt_managers = Mock()

            payload = _make_compiled_payload(VALID_HUNT_YAML)
            payload["execution_arguments"] = {
                "start_time": "01/15/2025:10:00:00",
                "end_time": "01/15/2025:12:00:00",
                "analyze_results": True,
                "queue": "custom-queue"
            }

            result = test_client.post(
                HUNT_VALIDATE_URL,
                json=payload,
                headers=auth_headers
            )

            assert result.status_code == 200
            data = result.get_json()
            assert data["valid"] is True
            assert mock_new_root.queue == "custom-queue"


@pytest.mark.integration
def test_validate_hunt_execution_empty_submissions(test_client, auth_headers):
    """Verify execution with no submissions returns empty roots."""
    from saq.collectors.hunter.query_hunter import QueryHunt

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        mock_hunt = Mock(spec=QueryHunt)
        mock_hunt.execute.return_value = []
        mock_manager.load_hunt_from_config.return_value = mock_hunt
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        payload = _make_compiled_payload(VALID_HUNT_YAML)
        payload["execution_arguments"] = {
            "start_time": "01/15/2025:10:00:00",
            "end_time": "01/15/2025:12:00:00"
        }

        result = test_client.post(
            HUNT_VALIDATE_URL,
            json=payload,
            headers=auth_headers
        )

        assert result.status_code == 200
        data = result.get_json()
        assert data["valid"] is True
        assert data["roots"] == []
        assert "logs" in data


@pytest.mark.integration
def test_validate_hunt_execution_returns_none(test_client, auth_headers):
    """Verify execution when hunt.execute() returns None is handled."""
    from saq.collectors.hunter.query_hunter import QueryHunt

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        mock_hunt = Mock(spec=QueryHunt)
        mock_hunt.execute.return_value = None
        mock_manager.load_hunt_from_config.return_value = mock_hunt
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        payload = _make_compiled_payload(VALID_HUNT_YAML)
        payload["execution_arguments"] = {
            "start_time": "01/15/2025:10:00:00",
            "end_time": "01/15/2025:12:00:00"
        }

        result = test_client.post(
            HUNT_VALIDATE_URL,
            json=payload,
            headers=auth_headers
        )

        assert result.status_code == 200
        data = result.get_json()
        assert data["valid"] is True
        assert data["roots"] == []
        assert "logs" in data


# =============================================================================
# Integration Tests for /hunt/validate Endpoint - Execution Error Cases
# =============================================================================

@pytest.mark.integration
def test_validate_hunt_execution_raises_exception(test_client, auth_headers):
    """Verify hunt execution exception returns wrapped error message."""
    from saq.collectors.hunter.query_hunter import QueryHunt

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        mock_hunt = Mock(spec=QueryHunt)
        mock_hunt.execute.side_effect = Exception("Connection failed to SIEM")
        mock_manager.load_hunt_from_config.return_value = mock_hunt
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        payload = _make_compiled_payload(VALID_HUNT_YAML)
        payload["execution_arguments"] = {
            "start_time": "01/15/2025:10:00:00",
            "end_time": "01/15/2025:12:00:00"
        }

        result = test_client.post(
            HUNT_VALIDATE_URL,
            json=payload,
            headers=auth_headers
        )

        assert result.status_code == 400
        data = result.get_json()
        assert data["valid"] is False
        assert "error executing hunt" in data["error"].lower()
        assert "Connection failed to SIEM" in data["error"]


@pytest.mark.integration
def test_validate_hunt_execution_remote_api_error(test_client, auth_headers):
    """Verify RemoteApiError propagates status code and message from remote API."""
    from saq.collectors.hunter.query_hunter import QueryHunt
    from saq.error.remote import RemoteApiError

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        mock_hunt = Mock(spec=QueryHunt)
        mock_hunt.execute.side_effect = RemoteApiError(403, "Forbidden")
        mock_manager.load_hunt_from_config.return_value = mock_hunt
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        payload = _make_compiled_payload(VALID_HUNT_YAML)
        payload["execution_arguments"] = {
            "start_time": "01/15/2025:10:00:00",
            "end_time": "01/15/2025:12:00:00"
        }

        result = test_client.post(
            HUNT_VALIDATE_URL,
            json=payload,
            headers=auth_headers
        )

        assert result.status_code == 400
        data = result.get_json()
        assert data["valid"] is False
        assert data["error"] == "Forbidden"
        assert data["remote_status_code"] == 403


@pytest.mark.integration
def test_validate_hunt_execution_non_query_hunt_no_time_required(test_client, auth_headers):
    """Verify non-QueryHunt types don't require start_time/end_time."""
    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        mock_hunt = Mock()
        mock_hunt.execute.return_value = []
        mock_manager.load_hunt_from_config.return_value = mock_hunt
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        payload = _make_compiled_payload(VALID_HUNT_YAML)
        payload["execution_arguments"] = {}

        result = test_client.post(
            HUNT_VALIDATE_URL,
            json=payload,
            headers=auth_headers
        )

        assert result.status_code == 200
        data = result.get_json()
        assert data["valid"] is True


@pytest.mark.integration
def test_validate_hunt_execution_logs_collected(test_client, auth_headers):
    """Verify logs are collected during execution."""
    from saq.collectors.hunter.query_hunter import QueryHunt
    import logging

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        mock_hunt = Mock(spec=QueryHunt)

        def execute_with_logging(**kwargs):
            logging.info("Test log message from hunt execution")
            return []

        mock_hunt.execute.side_effect = execute_with_logging
        mock_manager.load_hunt_from_config.return_value = mock_hunt
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        payload = _make_compiled_payload(VALID_HUNT_YAML)
        payload["execution_arguments"] = {
            "start_time": "01/15/2025:10:00:00",
            "end_time": "01/15/2025:12:00:00"
        }

        result = test_client.post(
            HUNT_VALIDATE_URL,
            json=payload,
            headers=auth_headers
        )

        assert result.status_code == 200
        data = result.get_json()
        assert data["valid"] is True
        assert "logs" in data
        log_messages = " ".join(data["logs"])
        assert "Test log message from hunt execution" in log_messages


# =============================================================================
# Integration Tests for /hunt/validate Endpoint - Original (pre-correlation) Events
# =============================================================================

@pytest.mark.integration
def test_validate_hunt_response_includes_original_events(test_client, auth_headers):
    """When the executed hunt captured original_query_results (i.e. correlate ran),
    the validate response should expose them at the top level."""
    from saq.collectors.hunter.query_hunter import QueryHunt
    from saq.analysis.root import Submission, RootAnalysis

    captured = [{"src": "1.2.3.4", "tag": "keep"}, {"src": "5.6.7.8", "tag": "drop"}]

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        mock_hunt = Mock(spec=QueryHunt)

        mock_root = Mock(spec=RootAnalysis)
        mock_root.json = {"uuid": "test-uuid-123", "description": "Test Hunt"}
        mock_root.details = {"query": "q", "events": [], "original_events": captured}
        mock_submission = Mock(spec=Submission)
        mock_submission.root = mock_root

        mock_hunt.execute.return_value = [mock_submission]
        mock_hunt.original_query_results = captured
        mock_manager.load_hunt_from_config.return_value = mock_hunt
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        payload = _make_compiled_payload(VALID_HUNT_YAML)
        payload["execution_arguments"] = {
            "start_time": "01/15/2025:10:00:00",
            "end_time": "01/15/2025:12:00:00",
        }

        result = test_client.post(HUNT_VALIDATE_URL, json=payload, headers=auth_headers)

        assert result.status_code == 200
        data = result.get_json()
        assert data["valid"] is True
        assert data["original_events"] == captured
        # the per-root details also carry the originals (set by process_query_results)
        assert data["roots"][0]["details"]["original_events"] == captured


@pytest.mark.integration
def test_validate_hunt_response_original_events_none_when_no_correlate(test_client, auth_headers):
    """When the hunt did not capture original_query_results (no correlate block),
    original_events on the response should be None — not an empty list, not missing."""
    from saq.collectors.hunter.query_hunter import QueryHunt
    from saq.analysis.root import Submission, RootAnalysis

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        mock_hunt = Mock(spec=QueryHunt)

        mock_root = Mock(spec=RootAnalysis)
        mock_root.json = {"uuid": "test-uuid-123"}
        mock_root.details = {"query": "q", "events": []}
        mock_submission = Mock(spec=Submission)
        mock_submission.root = mock_root

        mock_hunt.execute.return_value = [mock_submission]
        mock_hunt.original_query_results = None
        mock_manager.load_hunt_from_config.return_value = mock_hunt
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        payload = _make_compiled_payload(VALID_HUNT_YAML)
        payload["execution_arguments"] = {
            "start_time": "01/15/2025:10:00:00",
            "end_time": "01/15/2025:12:00:00",
        }

        result = test_client.post(HUNT_VALIDATE_URL, json=payload, headers=auth_headers)

        assert result.status_code == 200
        data = result.get_json()
        assert data["valid"] is True
        assert "original_events" in data
        assert data["original_events"] is None


# =============================================================================
# Integration Tests for /hunt/validate Endpoint - query_results override
# =============================================================================

@pytest.mark.integration
def test_validate_hunt_query_results_override(test_client, auth_headers):
    """When execution_arguments.query_results is set, the API should call
    hunt.process_query_results directly with those events and skip hunt.execute."""
    from saq.collectors.hunter.query_hunter import QueryHunt
    from saq.analysis.root import Submission, RootAnalysis

    override_events = [{"src": "1.2.3.4"}, {"src": "5.6.7.8"}]

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        mock_hunt = Mock(spec=QueryHunt)

        mock_root = Mock(spec=RootAnalysis)
        mock_root.json = {"uuid": "test-uuid-123"}
        mock_root.details = {"query": None, "events": override_events, "original_events": override_events}
        mock_submission = Mock(spec=Submission)
        mock_submission.root = mock_root

        mock_hunt.process_query_results.return_value = [mock_submission]
        mock_hunt.original_query_results = override_events
        mock_manager.load_hunt_from_config.return_value = mock_hunt
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        payload = _make_compiled_payload(VALID_HUNT_YAML)
        payload["execution_arguments"] = {"query_results": override_events}

        result = test_client.post(HUNT_VALIDATE_URL, json=payload, headers=auth_headers)

        assert result.status_code == 200
        data = result.get_json()
        assert data["valid"] is True
        # The override path must call process_query_results directly with the events,
        # not hunt.execute() which would re-run the data-source query.
        mock_hunt.process_query_results.assert_called_once_with(override_events)
        mock_hunt.execute.assert_not_called()
        assert data["original_events"] == override_events
        assert data["roots"][0]["details"]["events"] == override_events


@pytest.mark.integration
def test_validate_hunt_query_results_override_without_times(test_client, auth_headers):
    """The override path should NOT require start_time/end_time — those are only
    needed when actually querying the data source."""
    from saq.collectors.hunter.query_hunter import QueryHunt

    with patch("aceapi.hunt.HunterService") as mock_hunter_service:
        mock_manager = Mock()
        mock_hunt = Mock(spec=QueryHunt)
        mock_hunt.process_query_results.return_value = []
        mock_hunt.original_query_results = []
        mock_manager.load_hunt_from_config.return_value = mock_hunt
        mock_instance = mock_hunter_service.return_value
        mock_instance.hunt_managers = {"test": mock_manager}
        mock_instance.load_hunt_managers = Mock()

        payload = _make_compiled_payload(VALID_HUNT_YAML)
        # No start_time or end_time at all
        payload["execution_arguments"] = {"query_results": [{"src": "1.1.1.1"}]}

        result = test_client.post(HUNT_VALIDATE_URL, json=payload, headers=auth_headers)

        # Without the override this would 400 with "start_time is required"
        assert result.status_code == 200
        data = result.get_json()
        assert data["valid"] is True
        mock_hunt.process_query_results.assert_called_once()
