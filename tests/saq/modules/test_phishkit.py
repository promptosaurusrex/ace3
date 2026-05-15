import json
import os
import subprocess
import tempfile
from unittest.mock import MagicMock

import pytest

from saq.configuration.config import get_analysis_module_config
from saq.constants import ANALYSIS_MODE_CORRELATION, ANALYSIS_MODULE_PHISHKIT_ANALYZER, DIRECTIVE_CRAWL, DIRECTIVE_RENDER, F_FILE, F_URL, AnalysisExecutionResult
from saq.modules.phishkit import (
    PhishkitAnalysis,
    PhishkitAnalyzer,
    FIELD_OUTPUT_DIR,
    FIELD_JOB_ID,
    FIELD_SCAN_TYPE,
    FIELD_SCAN_RESULT,
    FIELD_OUTPUT_FILES,
    FIELD_ERROR,
    FIELD_EXIT_CODE,
    FIELD_STDOUT,
    FIELD_STDERR,
    FIELD_PROXY_STATUS,
    SCAN_TYPE_URL,
    SCAN_TYPE_FILE
)
from saq.modules.file_analysis import FileTypeAnalysis
from tests.saq.helpers import create_root_analysis
from tests.saq.test_util import create_test_context


@pytest.mark.unit
def test_phishkit_analysis_init():
    """Test PhishkitAnalysis initialization."""
    analysis = PhishkitAnalysis()
    assert analysis.details[FIELD_EXIT_CODE] is None
    assert analysis.details[FIELD_STDOUT] is None
    assert analysis.details[FIELD_STDERR] is None
    assert analysis.details[FIELD_OUTPUT_DIR] is None
    assert analysis.details[FIELD_JOB_ID] is None
    assert analysis.details[FIELD_SCAN_TYPE] is None
    assert analysis.details[FIELD_SCAN_RESULT] is None
    assert analysis.details[FIELD_OUTPUT_FILES] == []
    assert analysis.details[FIELD_ERROR] is None
    assert analysis.details[FIELD_PROXY_STATUS] is None


@pytest.mark.unit
def test_phishkit_analysis_properties():
    """Test PhishkitAnalysis property getters and setters."""
    analysis = PhishkitAnalysis()

    # Test exit_code
    analysis.exit_code = 0
    assert analysis.exit_code == 0

    # Test stdout
    analysis.stdout = "test stdout"
    assert analysis.stdout == "test stdout"

    # Test stderr
    analysis.stderr = "test stderr"
    assert analysis.stderr == "test stderr"

    # Test output_dir
    analysis.output_dir = "/tmp/test"
    assert analysis.output_dir == "/tmp/test"

    # Test job_id
    analysis.job_id = "test-job-123"
    assert analysis.job_id == "test-job-123"

    # Test scan_type
    analysis.scan_type = SCAN_TYPE_URL
    assert analysis.scan_type == SCAN_TYPE_URL

    # Test scan_result
    analysis.scan_result = "test result"
    assert analysis.scan_result == "test result"

    # Test output_files
    analysis.output_files = ["/tmp/file1.txt", "/tmp/file2.txt"]
    assert analysis.output_files == ["/tmp/file1.txt", "/tmp/file2.txt"]

    # Test error
    analysis.error = "test error"
    assert analysis.error == "test error"

    # Test proxy_status
    proxy_payload = {"configured": True, "final_route": "proxy"}
    analysis.proxy_status = proxy_payload
    assert analysis.proxy_status == proxy_payload


@pytest.mark.unit
def test_phishkit_analysis_generate_summary():
    """Test PhishkitAnalysis summary generation."""
    analysis = PhishkitAnalysis()

    # Test error state
    analysis.error = "Something went wrong"
    assert analysis.generate_summary() == "Phishkit Analysis: failed: Something went wrong"

    # Test URL scan
    analysis.error = None
    analysis.scan_type = SCAN_TYPE_URL
    analysis.output_files = ["/tmp/file1.txt", "/tmp/file2.txt"]
    assert analysis.generate_summary() == "Phishkit Analysis: output files created (/tmp/file1.txt, /tmp/file2.txt)"

    # Test file scan
    analysis.scan_type = SCAN_TYPE_FILE
    analysis.output_files = ["/tmp/file1.txt"]
    assert analysis.generate_summary() == "Phishkit Analysis: output files created (/tmp/file1.txt)"

    # Test unknown scan type
    analysis.scan_type = "unknown"
    assert analysis.generate_summary() == "Phishkit Analysis: completed"


@pytest.mark.unit
@pytest.mark.parametrize("proxy_status,expected_suffix", [
    # No proxy configured — no clause
    ({"configured": False, "fallback_triggered": False, "fallback_reason": None, "final_route": "none"}, ""),
    # Proxy used successfully
    ({"configured": True, "fallback_triggered": False, "fallback_reason": None, "final_route": "proxy"}, " - fetched via proxy"),
    # Proxy failed via error pattern, fell back to direct
    ({"configured": True, "fallback_triggered": True, "fallback_reason": "error_pattern", "final_route": "direct"},
     " - proxy failed (error_pattern), fetched direct"),
    # Proxy failed via status code, fell back to direct
    ({"configured": True, "fallback_triggered": True, "fallback_reason": "status_code", "final_route": "direct"},
     " - proxy failed (status_code), fetched direct"),
    # Proxy timed out, fell back to direct
    ({"configured": True, "fallback_triggered": True, "fallback_reason": "timeout", "final_route": "direct"},
     " - proxy failed (timeout), fetched direct"),
])
def test_phishkit_analysis_generate_summary_proxy_routes(proxy_status, expected_suffix):
    """The summary appends a proxy clause that matches the final_route."""
    analysis = PhishkitAnalysis()
    analysis.scan_type = SCAN_TYPE_URL
    analysis.output_files = ["/tmp/file1.txt"]
    analysis.proxy_status = proxy_status
    expected = "Phishkit Analysis: output files created (/tmp/file1.txt)" + expected_suffix
    assert analysis.generate_summary() == expected


@pytest.mark.integration
def test_phishkit_analyzer_properties():
    """Test PhishkitAnalyzer properties."""
    analyzer = PhishkitAnalyzer(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER))

    assert analyzer.generated_analysis_type == PhishkitAnalysis
    assert analyzer.valid_observable_types == [F_URL, F_FILE]


def _analyzer_with_deny_patterns(tmp_path, root, patterns):
    """Build a PhishkitAnalyzer whose YAML config has the given deny_crawl_url_patterns."""
    import yaml as _yaml
    config_file = tmp_path / "phishkit_config.yaml"
    config_file.write_text(_yaml.safe_dump({"deny_crawl_url_patterns": list(patterns)}))
    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root),
    )
    analyzer._yaml_config_path = str(config_file)
    analyzer._load_deny_patterns()
    return analyzer


@pytest.mark.integration
def test_phishkit_custom_requirement_denies_matching_url(tmp_path):
    """custom_requirement returns False for URLs matching a deny pattern."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    url = root.add_observable_by_spec(F_URL, "https://login.windows.net/common/oauth2")

    analyzer = _analyzer_with_deny_patterns(tmp_path, root, ["login.windows.net"])

    assert analyzer.custom_requirement(url) is False


@pytest.mark.integration
def test_phishkit_custom_requirement_allows_non_matching_url(tmp_path):
    """custom_requirement returns True for URLs that don't match any deny pattern."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    url = root.add_observable_by_spec(F_URL, "https://winecellarsbycoastalblog.com/ls/click")

    analyzer = _analyzer_with_deny_patterns(tmp_path, root, ["login.windows.net", "microsoft.com"])

    assert analyzer.custom_requirement(url) is True


@pytest.mark.integration
def test_phishkit_custom_requirement_case_insensitive(tmp_path):
    """Deny pattern match is case-insensitive."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    url = root.add_observable_by_spec(F_URL, "https://LOGIN.Microsoftonline.COM/authorize")

    analyzer = _analyzer_with_deny_patterns(tmp_path, root, ["login.microsoftonline.com"])

    assert analyzer.custom_requirement(url) is False


@pytest.mark.integration
def test_phishkit_custom_requirement_empty_deny_list(tmp_path):
    """Missing deny_crawl_url_patterns means nothing is denied."""
    import yaml as _yaml
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    url = root.add_observable_by_spec(F_URL, "https://login.windows.net/common")

    config_file = tmp_path / "phishkit_config.yaml"
    config_file.write_text(_yaml.safe_dump({"skip_body_url_patterns": ["unrelated.com"]}))
    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root),
    )
    analyzer._yaml_config_path = str(config_file)
    analyzer._load_deny_patterns()

    assert analyzer._deny_crawl_patterns == []
    assert analyzer.custom_requirement(url) is True


@pytest.mark.integration
def test_phishkit_custom_requirement_missing_yaml_file(tmp_path):
    """A missing YAML config must not crash; deny list stays empty."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    url = root.add_observable_by_spec(F_URL, "https://login.windows.net/common")

    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root),
    )
    analyzer._yaml_config_path = str(tmp_path / "does_not_exist.yaml")
    analyzer._load_deny_patterns()

    assert analyzer._deny_crawl_patterns == []
    assert analyzer.custom_requirement(url) is True


@pytest.mark.integration
def test_phishkit_custom_requirement_invalid_deny_pattern_type(tmp_path):
    """A non-list deny_crawl_url_patterns value should be ignored safely."""
    import yaml as _yaml

    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    url = root.add_observable_by_spec(F_URL, "https://login.windows.net/common")

    config_file = tmp_path / "phishkit_config.yaml"
    config_file.write_text(_yaml.safe_dump({"deny_crawl_url_patterns": "login.windows.net"}))
    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root),
    )
    analyzer._yaml_config_path = str(config_file)
    analyzer._load_deny_patterns()

    assert analyzer._deny_crawl_patterns == []
    assert analyzer.custom_requirement(url) is True


@pytest.mark.integration
def test_phishkit_analyzer_verify_environment(test_context):
    """Test PhishkitAnalyzer environment verification."""
    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=test_context
    )
    
    # This should raise an exception if config items are missing
    try:
        analyzer.verify_environment()
    except Exception as e:
        # Expected if config items are not set up
        assert "valid_file_extensions" in str(e) or "valid_mime_types" in str(e)


@pytest.mark.integration
def test_phishkit_analyzer_execute_analysis_url_success(monkeypatch, test_context):
    """Test successful URL analysis execution."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    
    # Create URL observable with render directive
    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    url_observable.add_directive(DIRECTIVE_CRAWL)
    
    # Mock saq.phishkit functions
    def mock_scan_url(url, output_dir, is_async=True, **kwargs):
        return "test-job-123"
    
    monkeypatch.setattr("saq.modules.phishkit.scan_url", mock_scan_url)
    
    # Mock delay_analysis to avoid delayed execution issues
    def mock_delay_analysis(*args, **kwargs):
        pass
    
    monkeypatch.setattr("saq.modules.phishkit.PhishkitAnalyzer.delay_analysis", mock_delay_analysis)
    
    # Mock create_temporary_directory
    def mock_create_temporary_directory():
        return "/tmp/test-output"
    
    monkeypatch.setattr("saq.util.filesystem.create_temporary_directory", mock_create_temporary_directory)
    
    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root))
    result = analyzer.execute_analysis(url_observable)
    
    assert result == AnalysisExecutionResult.COMPLETED
    
    analysis = url_observable.get_and_load_analysis(PhishkitAnalysis)
    assert analysis is not None
    assert analysis.job_id == "test-job-123"
    assert analysis.scan_type == SCAN_TYPE_URL
    # Don't check exact output_dir since it uses temp directory


@pytest.mark.integration
def test_phishkit_analyzer_execute_analysis_url_no_directive(test_context):
    """Test URL analysis skipped when no directive present."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    
    # Create URL observable without directive
    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    
    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root))
    result = analyzer.execute_analysis(url_observable)
    
    assert result == AnalysisExecutionResult.COMPLETED
    
    # No analysis should be created
    analysis = url_observable.get_and_load_analysis(PhishkitAnalysis)
    assert analysis is None


@pytest.mark.integration
def test_phishkit_analyzer_execute_analysis_url_with_crawl_directive(monkeypatch, test_context):
    """Test URL analysis with crawl directive."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    
    # Create URL observable with crawl directive
    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    url_observable.add_directive(DIRECTIVE_CRAWL)
    
    # Mock saq.phishkit functions
    def mock_scan_url(url, output_dir, is_async=True, **kwargs):
        return "test-job-456"
    
    monkeypatch.setattr("saq.modules.phishkit.scan_url", mock_scan_url)
    
    # Mock delay_analysis to avoid delayed execution issues
    def mock_delay_analysis(*args, **kwargs):
        pass
    
    monkeypatch.setattr("saq.modules.phishkit.PhishkitAnalyzer.delay_analysis", mock_delay_analysis)
    
    # Mock create_temporary_directory
    def mock_create_temporary_directory():
        return "/tmp/test-output-2"
    
    monkeypatch.setattr("saq.util.filesystem.create_temporary_directory", mock_create_temporary_directory)
    
    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root))
    result = analyzer.execute_analysis(url_observable)
    
    assert result == AnalysisExecutionResult.COMPLETED
    
    analysis = url_observable.get_and_load_analysis(PhishkitAnalysis)
    assert analysis is not None
    assert analysis.job_id == "test-job-456"
    assert analysis.scan_type == SCAN_TYPE_URL


@pytest.mark.integration
def test_phishkit_analyzer_execute_analysis_url_error(monkeypatch, test_context):
    """Test URL analysis with error."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    
    # Create URL observable with render directive
    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    url_observable.add_directive(DIRECTIVE_CRAWL)
    
    # Mock saq.phishkit functions to raise exception
    def mock_scan_url(url, output_dir, is_async=True, **kwargs):
        raise Exception("Network error")
    
    monkeypatch.setattr("saq.modules.phishkit.scan_url", mock_scan_url)
    
    # Mock create_temporary_directory
    def mock_create_temporary_directory():
        return "/tmp/test-output"
    
    monkeypatch.setattr("saq.util.filesystem.create_temporary_directory", mock_create_temporary_directory)
    
    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root))
    result = analyzer.execute_analysis(url_observable)
    
    assert result == AnalysisExecutionResult.COMPLETED
    
    analysis = url_observable.get_and_load_analysis(PhishkitAnalysis)
    assert analysis is not None
    assert analysis.error == "failed to scan URL https://example.com/phish: Network error"
    assert analysis.scan_type == SCAN_TYPE_URL


@pytest.mark.integration
def test_phishkit_analyzer_execute_analysis_file_success(monkeypatch, test_context):
    """Test successful file analysis execution."""
    root = create_root_analysis(analysis_mode='correlation')
    root.initialize_storage()
    
    # Create a test file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
        f.write('<html><body>Test content</body></html>')
        test_file_path = f.name
    
    try:
        # Create file observable
        file_observable = root.add_file_observable(test_file_path)
        file_observable.add_directive(DIRECTIVE_RENDER)
        
        # Mock file type analysis
        file_type_analysis = FileTypeAnalysis()
        file_type_analysis.details = {'type': 'HTML document', 'mime': 'text/html'}
        file_observable.add_analysis(file_type_analysis)
        
        # Configure analyzer to accept html files
        analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root))
        
        monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'valid_file_extensions', ['.html'])
        monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'valid_mime_types', ['text/html'])
        
        # Mock saq.phishkit functions
        def mock_scan_file(file_path, output_dir, is_async=True, **kwargs):
            return "file-job-123"
        
        monkeypatch.setattr("saq.modules.phishkit.scan_file", mock_scan_file)
        
        # Mock delay_analysis to return the expected result
        def mock_delay_analysis(*args, **kwargs):
            return AnalysisExecutionResult.INCOMPLETE
        
        monkeypatch.setattr("saq.modules.phishkit.PhishkitAnalyzer.delay_analysis", mock_delay_analysis)
        
        # Mock create_temporary_directory
        def mock_create_temporary_directory():
            return "/tmp/test-file-output"
        
        monkeypatch.setattr("saq.util.filesystem.create_temporary_directory", mock_create_temporary_directory)
        
        # Mock wait_for_analysis
        def mock_wait_for_analysis(observable, analysis_type):
            return file_type_analysis
        
        monkeypatch.setattr(analyzer, "wait_for_analysis", mock_wait_for_analysis)
        
        result = analyzer.execute_analysis(file_observable)
        
        # Since file analysis now returns the result of delay_analysis
        assert result == AnalysisExecutionResult.INCOMPLETE
        
        analysis = file_observable.get_and_load_analysis(PhishkitAnalysis)
        assert analysis is not None
        assert analysis.job_id == "file-job-123"
        assert analysis.scan_type == SCAN_TYPE_FILE
        # Don't check exact output_dir since it uses temp directory
        
    finally:
        # Clean up
        if os.path.exists(test_file_path):
            os.unlink(test_file_path)

@pytest.mark.integration
def test_phishkit_analyzer_execute_analysis_file_invalid_extension(monkeypatch, test_context):
    """Test file analysis skipped for invalid extension."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    
    # Create a test file with invalid extension
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write('Test content')
        test_file_path = f.name
    
    try:
        file_observable = root.add_file_observable(test_file_path)
        
        # Configure analyzer to only accept html files
        analyzer = PhishkitAnalyzer(
            get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
            context=create_test_context(root=root))
        
        monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'valid_file_extensions', ['.html'])
        monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'valid_mime_types', ['text/html'])
        
        # Mock file type analysis
        file_type_analysis = FileTypeAnalysis()
        file_type_analysis.details = {'type': 'Plain text', 'mime': 'text/plain'}
        file_observable.add_analysis(file_type_analysis)

        # Mock wait_for_analysis
        def mock_wait_for_analysis(observable, analysis_type):
            return file_type_analysis
        
        monkeypatch.setattr(analyzer, "wait_for_analysis", mock_wait_for_analysis)
        
        # No need for adapter
        result = analyzer.execute_analysis(file_observable)
        
        assert result == AnalysisExecutionResult.COMPLETED
        
        # No analysis should be created
        analysis = file_observable.get_and_load_analysis(PhishkitAnalysis)
        assert analysis is None
        
    finally:
        if os.path.exists(test_file_path):
            os.unlink(test_file_path)


@pytest.mark.integration
def test_phishkit_analyzer_execute_analysis_file_invalid_mime_type(monkeypatch, test_context):
    """Test file analysis skipped for invalid MIME type."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    
    # Create a test file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write('Whatever.')
        test_file_path = f.name
    
    try:
        file_observable = root.add_file_observable(test_file_path)
        
        # Mock file type analysis with wrong MIME type
        file_type_analysis = FileTypeAnalysis()
        file_type_analysis.details = {'type': 'Plain text', 'mime': 'text/plain'}
        file_observable.add_analysis(file_type_analysis)
        
        # Configure analyzer to only accept html MIME types
        analyzer = PhishkitAnalyzer(
            get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
            context=create_test_context(root=root))
        
        monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'valid_file_extensions', ['.html'])
        monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'valid_mime_types', ['text/html'])
        
        # Mock wait_for_analysis
        def mock_wait_for_analysis(observable, analysis_type):
            return file_type_analysis
        
        monkeypatch.setattr(analyzer, "wait_for_analysis", mock_wait_for_analysis)
        
        # No need for adapter
        result = analyzer.execute_analysis(file_observable)
        
        assert result == AnalysisExecutionResult.COMPLETED
        
        # No analysis should be created
        analysis = file_observable.get_and_load_analysis(PhishkitAnalysis)
        assert analysis is None
        
    finally:
        if os.path.exists(test_file_path):
            os.unlink(test_file_path)


@pytest.mark.integration
def test_phishkit_analyzer_execute_analysis_file_error(monkeypatch, test_context):
    """Test file analysis with error."""
    root = create_root_analysis(analysis_mode='correlation')
    root.initialize_storage()
    
    # Create a test file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
        f.write('<html><body>Test content</body></html>')
        test_file_path = f.name
    
    try:
        file_observable = root.add_file_observable(test_file_path)
        file_observable.add_directive(DIRECTIVE_RENDER)
        
        # Mock file type analysis
        file_type_analysis = FileTypeAnalysis()
        file_type_analysis.details = {'type': 'HTML document', 'mime': 'text/html'}
        file_observable.add_analysis(file_type_analysis)
        
        # Configure analyzer to accept html files
        analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root))
        
        monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'valid_file_extensions', ['.html'])
        monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'valid_mime_types', ['text/html'])
        
        # Mock saq.phishkit functions to raise exception
        def mock_scan_file(file_path, output_dir, is_async=True, **kwargs):
            raise Exception("File processing error")
        
        monkeypatch.setattr("saq.modules.phishkit.scan_file", mock_scan_file)
        
        # Mock create_temporary_directory
        def mock_create_temporary_directory():
            return "/tmp/test-file-output"
        
        monkeypatch.setattr("saq.util.filesystem.create_temporary_directory", mock_create_temporary_directory)
        
        # Mock wait_for_analysis
        def mock_wait_for_analysis(observable, analysis_type):
            return file_type_analysis
        
        monkeypatch.setattr(analyzer, "wait_for_analysis", mock_wait_for_analysis)
        
        result = analyzer.execute_analysis(file_observable)
        
        assert result == AnalysisExecutionResult.COMPLETED
        
        analysis = file_observable.get_and_load_analysis(PhishkitAnalysis)
        assert analysis is not None
        assert "Failed to scan file" in analysis.error
        assert "File processing error" in analysis.error
        assert analysis.scan_type == SCAN_TYPE_FILE
        
    finally:
        if os.path.exists(test_file_path):
            os.unlink(test_file_path)


@pytest.mark.integration
def test_phishkit_analyzer_continue_analysis_no_job_id(test_context):
    """Test completing analysis with no job ID."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    
    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    analysis = PhishkitAnalysis()
    # Don't set job_id
    url_observable.add_analysis(analysis)
    
    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root))
    result = analyzer.continue_analysis(url_observable, analysis)
    
    assert result == AnalysisExecutionResult.COMPLETED


@pytest.mark.integration
def test_phishkit_analyzer_continue_analysis_not_ready(monkeypatch, test_context):
    """Test completing analysis when results not ready."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    
    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    analysis = PhishkitAnalysis()
    analysis.job_id = "test-job-123"
    analysis.output_dir = "/tmp/test-output"
    url_observable.add_analysis(analysis)
    
    # Mock get_async_scan_result to return None (not ready)
    def mock_get_async_scan_result(job_id, output_dir, timeout=1):
        return None
    
    monkeypatch.setattr("saq.modules.phishkit.get_async_scan_result", mock_get_async_scan_result)
    
    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root))
    analyzer.config.scanner_timeout = 100

    # Mock delay_analysis to return the expected result
    def mock_delay_analysis(*args, **kwargs):
        return AnalysisExecutionResult.INCOMPLETE

    analyzer.delay_analysis = MagicMock(side_effect=mock_delay_analysis)

    result = analyzer.continue_analysis(url_observable, analysis)

    # Should call delay_analysis and return its result
    analyzer.delay_analysis.assert_called_once_with(url_observable, analysis, seconds=3, timeout_seconds=230)
    assert result == AnalysisExecutionResult.INCOMPLETE


@pytest.mark.integration
def test_phishkit_analyzer_continue_analysis_timeout(monkeypatch, test_context):
    """continue_analysis should treat TimeoutError from the async scan as a warning, not an error."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    analysis = PhishkitAnalysis()
    analysis.job_id = "test-job-timeout"
    analysis.output_dir = "/tmp/test-output"
    url_observable.add_analysis(analysis)

    def mock_get_async_scan_result(job_id, output_dir, timeout=1):
        raise TimeoutError("scan exceeded budget")

    monkeypatch.setattr("saq.modules.phishkit.get_async_scan_result", mock_get_async_scan_result)

    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root))
    result = analyzer.continue_analysis(url_observable, analysis)

    assert result == AnalysisExecutionResult.COMPLETED
    assert "timed out" in analysis.error
    assert "test-job-timeout" in analysis.error


@pytest.mark.integration
def test_phishkit_analyzer_continue_analysis_subprocess_timeout(monkeypatch, test_context):
    """continue_analysis should treat subprocess.TimeoutExpired propagated from the celery worker as a warning, not an error."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    analysis = PhishkitAnalysis()
    analysis.job_id = "test-job-subprocess-timeout"
    analysis.output_dir = "/tmp/test-output"
    url_observable.add_analysis(analysis)

    def mock_get_async_scan_result(job_id, output_dir, timeout=1):
        raise subprocess.TimeoutExpired(cmd=["docker", "run", "scanner"], timeout=60)

    monkeypatch.setattr("saq.modules.phishkit.get_async_scan_result", mock_get_async_scan_result)

    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root))
    result = analyzer.continue_analysis(url_observable, analysis)

    assert result == AnalysisExecutionResult.COMPLETED
    assert "timed out" in analysis.error
    assert "test-job-subprocess-timeout" in analysis.error


@pytest.mark.integration
def test_phishkit_analyzer_continue_analysis_worker_exception(monkeypatch, test_context):
    """continue_analysis should absorb worker-side exceptions from the Celery AsyncResult and mark the analysis failed."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    analysis = PhishkitAnalysis()
    analysis.job_id = "test-job-worker-exc"
    analysis.output_dir = "/tmp/test-output"
    url_observable.add_analysis(analysis)

    worker_error = "scan failed: TypeError: argument of type 'NoneType' is not iterable"

    def mock_get_async_scan_result(job_id, output_dir, timeout=1):
        raise Exception(worker_error)

    monkeypatch.setattr("saq.modules.phishkit.get_async_scan_result", mock_get_async_scan_result)

    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root))
    result = analyzer.continue_analysis(url_observable, analysis)

    assert result == AnalysisExecutionResult.COMPLETED
    assert "test-job-worker-exc" in analysis.error
    assert worker_error in analysis.error


@pytest.mark.integration
def test_phishkit_analyzer_continue_analysis_success(monkeypatch, test_context):
    """Test successful analysis completion."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    analysis = PhishkitAnalysis()
    analysis.job_id = "test-job-123"
    analysis.output_dir = "/tmp/test-output"
    url_observable.add_analysis(analysis)

    # Create temporary files for test
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create mock output files
        exit_code_file = os.path.join(temp_dir, "exit.code")
        stdout_file = os.path.join(temp_dir, "std.out")
        stderr_file = os.path.join(temp_dir, "std.err")
        proxy_file = os.path.join(temp_dir, "proxy.json")
        other_file = os.path.join(temp_dir, "result.json")

        with open(exit_code_file, "w") as f:
            f.write("0")
        with open(stdout_file, "w") as f:
            f.write("scan completed")
        with open(stderr_file, "w") as f:
            f.write("no errors")
        proxy_payload = {
            "configured": True,
            "host": "socks5://gate.proxy.example:1080",
            "fallback_enabled": True,
            "fallback_triggered": True,
            "fallback_reason": "error_pattern",
            "fallback_details": {"matched_error_patterns": ["ERR_PROXY_CONNECTION_FAILED"]},
            "final_route": "direct",
        }
        with open(proxy_file, "w") as f:
            json.dump(proxy_payload, f)
        with open(other_file, "w") as f:
            f.write('{"result": "success"}')

        output_files = [exit_code_file, stdout_file, stderr_file, proxy_file, other_file]

        # Mock get_async_scan_result to return file list
        def mock_get_async_scan_result(job_id, output_dir, timeout=1):
            return output_files

        monkeypatch.setattr("saq.modules.phishkit.get_async_scan_result", mock_get_async_scan_result)

        analyzer = PhishkitAnalyzer(
            get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
            context=create_test_context(root=root))
        result = analyzer.continue_analysis(url_observable, analysis)

        assert result == AnalysisExecutionResult.COMPLETED
        # Only non-special files are added to output_files, and they're stored as relative paths
        assert len(analysis.output_files) == 1  # Only result.json should be in output_files
        assert analysis.output_files[0].startswith("phishkit/") and analysis.output_files[0].endswith("/result.json")
        assert analysis.scan_result == f"successfully scanned {url_observable}"
        assert analysis.error is None
        assert analysis.exit_code == 0
        assert analysis.stdout == "scan completed"
        assert analysis.stderr == "no errors"
        assert analysis.proxy_status == proxy_payload


@pytest.mark.integration
def test_phishkit_analyzer_continue_analysis_no_proxy_json(monkeypatch, test_context):
    """Missing proxy.json (older worker / in-flight scan) leaves proxy_status None."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    analysis = PhishkitAnalysis()
    analysis.job_id = "test-job-no-proxy-json"
    analysis.output_dir = "/tmp/test-output"
    url_observable.add_analysis(analysis)

    with tempfile.TemporaryDirectory() as temp_dir:
        exit_code_file = os.path.join(temp_dir, "exit.code")
        stdout_file = os.path.join(temp_dir, "std.out")
        with open(exit_code_file, "w") as f:
            f.write("0")
        with open(stdout_file, "w") as f:
            f.write("scan completed")

        output_files = [exit_code_file, stdout_file]
        monkeypatch.setattr("saq.modules.phishkit.get_async_scan_result",
                            lambda job_id, output_dir, timeout=1: output_files)

        analyzer = PhishkitAnalyzer(
            get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
            context=create_test_context(root=root))
        result = analyzer.continue_analysis(url_observable, analysis)

        assert result == AnalysisExecutionResult.COMPLETED
        assert analysis.exit_code == 0
        assert analysis.proxy_status is None


@pytest.mark.unit
def test_phishkit_analyzer_continue_analysis_extracts_marker_urls(monkeypatch, test_context):
    """Test that MARKER URL lines in dom.html are extracted as URL observables."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    analysis = PhishkitAnalysis()
    analysis.job_id = "test-job-marker"
    analysis.output_dir = "/tmp/test-output"
    url_observable.add_analysis(analysis)

    with tempfile.TemporaryDirectory() as temp_dir:
        # Create dom.html with MARKER URL lines mixed with HTML content
        dom_file = os.path.join(temp_dir, "dom.html")
        with open(dom_file, "w") as f:
            f.write("<html><body>page content</body></html>\n")
            f.write("\n\nMARKER URL: https://evil.com/login.php\n\n")
            f.write("<script>var x = 1;</script>\n")
            f.write("\n\nMARKER URL: https://evil.com/steal.js\n\n")
            f.write("more response content\n")
            f.write("\n\nMARKER URL: https://cdn.example.com/payload.html\n\n")

        exit_code_file = os.path.join(temp_dir, "exit.code")
        with open(exit_code_file, "w") as f:
            f.write("0")

        output_files = [exit_code_file, dom_file]
        analysis.output_dir = temp_dir

        monkeypatch.setattr("saq.modules.phishkit.get_async_scan_result",
                            lambda job_id, output_dir, timeout=1: output_files)

        # Track calls to add_observable_by_spec on the analysis
        added_urls = []
        original_add = analysis.add_observable_by_spec
        def tracking_add(o_type, o_value, **kwargs):
            if o_type == F_URL:
                added_urls.append(o_value)
            return original_add(o_type, o_value, **kwargs)
        monkeypatch.setattr(analysis, "add_observable_by_spec", tracking_add)

        analyzer = PhishkitAnalyzer(
            get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
            context=create_test_context(root=root))
        result = analyzer.continue_analysis(url_observable, analysis)

        assert result == AnalysisExecutionResult.COMPLETED
        assert added_urls == [
            "https://evil.com/login.php",
            "https://evil.com/steal.js",
            "https://cdn.example.com/payload.html",
        ]


@pytest.mark.unit
def test_phishkit_analyzer_continue_analysis_extracts_requests_json_urls(monkeypatch, test_context):
    """Every type=request entry in requests.json should yield a URL observable,
    including URLs that never made it into dom.html as MARKER URLs."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    analysis = PhishkitAnalysis()
    analysis.job_id = "test-job-requests-json"
    analysis.output_dir = "/tmp/test-output"
    url_observable.add_analysis(analysis)

    with tempfile.TemporaryDirectory() as temp_dir:
        # dom.html carries one MARKER URL; requests.json carries three more
        # (a filtered CSS, a failed endpoint, and a duplicate of the MARKER URL)
        # plus noise (response, error, file://, data:, blob:).
        dom_file = os.path.join(temp_dir, "dom.html")
        with open(dom_file, "w") as f:
            f.write("\n\nMARKER URL: https://evil.com/login.php\n\n")

        requests_file = os.path.join(temp_dir, "requests.json")
        with open(requests_file, "w") as f:
            json.dump([
                {"type": "request", "url": "https://evil.com/login.php"},  # dup of MARKER
                {"type": "request", "url": "https://cdn.example.com/styles.css"},  # filtered from dom.html
                {"type": "response", "url": "https://evil.com/login.php"},  # ignored
                {"type": "request", "url": "https://blocked.example.com/captcha.png"},  # failed fetch
                {"type": "error", "url": "https://blocked.example.com/captcha.png"},  # ignored
                {"type": "request", "url": "file:///local/path.html"},  # skipped
                {"type": "request", "url": "data:image/svg+xml;base64,PHN2Zw=="},  # skipped
                {"type": "request", "url": "blob:https://evil.com/abc123"},  # skipped
                {"type": "websocket_created", "url": "wss://evil.com/ws"},  # not a request, ignored here
            ], f)

        exit_code_file = os.path.join(temp_dir, "exit.code")
        with open(exit_code_file, "w") as f:
            f.write("0")

        output_files = [exit_code_file, dom_file, requests_file]
        analysis.output_dir = temp_dir

        monkeypatch.setattr("saq.modules.phishkit.get_async_scan_result",
                            lambda job_id, output_dir, timeout=1: output_files)

        added_urls = []
        original_add = analysis.add_observable_by_spec
        def tracking_add(o_type, o_value, **kwargs):
            if o_type == F_URL:
                added_urls.append(o_value)
            return original_add(o_type, o_value, **kwargs)
        monkeypatch.setattr(analysis, "add_observable_by_spec", tracking_add)

        analyzer = PhishkitAnalyzer(
            get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
            context=create_test_context(root=root))
        result = analyzer.continue_analysis(url_observable, analysis)

        assert result == AnalysisExecutionResult.COMPLETED
        # MARKER URL pass emits login.php once. requests.json pass then emits
        # login.php (dedup), styles.css, and captcha.png. file:/data:/blob: and
        # non-request types are skipped.
        assert added_urls == [
            "https://evil.com/login.php",
            "https://evil.com/login.php",
            "https://cdn.example.com/styles.css",
            "https://blocked.example.com/captcha.png",
        ]


@pytest.mark.unit
def test_phishkit_analyzer_continue_analysis_no_marker_urls(monkeypatch, test_context):
    """Test that dom.html with no MARKER URL lines adds no URL observables."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    analysis = PhishkitAnalysis()
    analysis.job_id = "test-job-no-markers"
    analysis.output_dir = "/tmp/test-output"
    url_observable.add_analysis(analysis)

    with tempfile.TemporaryDirectory() as temp_dir:
        dom_file = os.path.join(temp_dir, "dom.html")
        with open(dom_file, "w") as f:
            f.write("<html><body>just a normal page</body></html>\n")

        exit_code_file = os.path.join(temp_dir, "exit.code")
        with open(exit_code_file, "w") as f:
            f.write("0")

        output_files = [exit_code_file, dom_file]
        analysis.output_dir = temp_dir

        monkeypatch.setattr("saq.modules.phishkit.get_async_scan_result",
                            lambda job_id, output_dir, timeout=1: output_files)

        added_urls = []
        original_add = analysis.add_observable_by_spec
        def tracking_add(o_type, o_value, **kwargs):
            if o_type == F_URL:
                added_urls.append(o_value)
            return original_add(o_type, o_value, **kwargs)
        monkeypatch.setattr(analysis, "add_observable_by_spec", tracking_add)

        analyzer = PhishkitAnalyzer(
            get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
            context=create_test_context(root=root))
        result = analyzer.continue_analysis(url_observable, analysis)

        assert result == AnalysisExecutionResult.COMPLETED
        assert added_urls == []


@pytest.mark.integration
def test_phishkit_analyzer_file_not_analyzed_in_non_correlation_mode(monkeypatch, test_context):
    """Test that F_FILE observables are NOT analyzed when root analysis is NOT in correlation mode."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    
    # Create a test file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
        f.write('<html><body>Test content</body></html>')
        test_file_path = f.name
    
    try:
        # Create file observable
        file_observable = root.add_file_observable(test_file_path)
        file_observable.add_directive(DIRECTIVE_RENDER)
        
        # Mock file type analysis
        file_type_analysis = FileTypeAnalysis()
        file_type_analysis.details = {'type': 'HTML document', 'mime': 'text/html'}
        file_observable.add_analysis(file_type_analysis)
        
        # Configure analyzer to accept html files
        analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root))
        
        monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'valid_file_extensions', ['.html'])
        monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'valid_mime_types', ['text/html'])
        
        # Mock wait_for_analysis
        def mock_wait_for_analysis(observable, analysis_type):
            return file_type_analysis
        
        monkeypatch.setattr(analyzer, "wait_for_analysis", mock_wait_for_analysis)
        
        # Verify that accepts returns False (custom_requirement check)
        # This is the gatekeeper - if accepts returns False, execute_analysis should not be called
        assert not analyzer.accepts(file_observable)
        
    finally:
        if os.path.exists(test_file_path):
            os.unlink(test_file_path)


@pytest.mark.integration
def test_phishkit_analyzer_file_analyzed_after_mode_switch_to_correlation(monkeypatch, test_context):
    """Test that F_FILE observables ARE analyzed after switching root analysis to correlation mode."""
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    
    # Create a test file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
        f.write('<html><body>Test content</body></html>')
        test_file_path = f.name
    
    try:
        # Create file observable
        file_observable = root.add_file_observable(test_file_path)
        file_observable.add_directive(DIRECTIVE_RENDER)
        
        # Mock file type analysis
        file_type_analysis = FileTypeAnalysis()
        file_type_analysis.details = {'type': 'HTML document', 'mime': 'text/html'}
        file_observable.add_analysis(file_type_analysis)
        
        # Configure analyzer to accept html files
        analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root))
        
        monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'valid_file_extensions', ['.html'])
        monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'valid_mime_types', ['text/html'])
        
        # Mock wait_for_analysis
        def mock_wait_for_analysis(observable, analysis_type):
            return file_type_analysis
        
        monkeypatch.setattr(analyzer, "wait_for_analysis", mock_wait_for_analysis)
        
        # First, verify that in non-correlation mode, it's NOT accepted for analysis
        # The accepts method checks custom_requirement, which should return False
        assert not analyzer.accepts(file_observable)
        
        # Now switch to correlation mode
        root.analysis_mode = ANALYSIS_MODE_CORRELATION
        
        # Verify that accepts now returns True (custom_requirement should pass)
        assert analyzer.accepts(file_observable)
        
        # Mock saq.phishkit functions
        def mock_scan_file(file_path, output_dir, is_async=True, **kwargs):
            return "file-job-after-switch"
        
        monkeypatch.setattr("saq.modules.phishkit.scan_file", mock_scan_file)
        
        # Mock delay_analysis to return the expected result
        def mock_delay_analysis(*args, **kwargs):
            return AnalysisExecutionResult.INCOMPLETE
        
        monkeypatch.setattr("saq.modules.phishkit.PhishkitAnalyzer.delay_analysis", mock_delay_analysis)
        
        # Mock create_temporary_directory
        def mock_create_temporary_directory():
            return "/tmp/test-file-output-after-switch"
        
        monkeypatch.setattr("saq.util.filesystem.create_temporary_directory", mock_create_temporary_directory)
        
        # Now execute analysis - it should create analysis
        result = analyzer.execute_analysis(file_observable)
        
        # Since file analysis now returns the result of delay_analysis
        assert result == AnalysisExecutionResult.INCOMPLETE
        
        # Analysis should now be created
        analysis = file_observable.get_and_load_analysis(PhishkitAnalysis)
        assert analysis is not None
        assert analysis.job_id == "file-job-after-switch"
        assert analysis.scan_type == SCAN_TYPE_FILE

    finally:
        if os.path.exists(test_file_path):
            os.unlink(test_file_path)


@pytest.mark.integration
def test_phishkit_analyzer_url_scan_passes_proxy(monkeypatch, test_context):
    """Test that proxy string is passed through to scan_url when configured."""
    from saq.configuration.config import get_config
    from saq.configuration.schema import ProxyConfig

    # set up a named proxy config
    proxy_config = ProxyConfig(name="testproxy", transport="http", host="proxy.test", port=9090, user="u", password="p")
    get_config().clear_proxy_configs()
    get_config().add_proxy_config("testproxy", proxy_config)

    # set the phishkit analyzer config to use this proxy
    monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'proxy', 'testproxy')

    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    url_observable.add_directive(DIRECTIVE_CRAWL)

    captured_kwargs = {}

    def mock_scan_url(url, output_dir, is_async=True, **kwargs):
        captured_kwargs.update(kwargs)
        return "proxy-job-123"

    monkeypatch.setattr("saq.modules.phishkit.scan_url", mock_scan_url)
    monkeypatch.setattr("saq.modules.phishkit.PhishkitAnalyzer.delay_analysis", lambda *a, **kw: None)
    monkeypatch.setattr("saq.util.filesystem.create_temporary_directory", lambda: "/tmp/proxy-test")

    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root))
    analyzer.execute_analysis(url_observable)

    assert captured_kwargs.get("proxy") == "u:p@proxy.test:9090"


@pytest.mark.integration
def test_phishkit_analyzer_url_scan_no_proxy(monkeypatch, test_context):
    """Test that proxy is None when no proxy is configured."""
    # ensure no proxy is set
    monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'proxy', None)

    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    url_observable.add_directive(DIRECTIVE_CRAWL)

    captured_kwargs = {}

    def mock_scan_url(url, output_dir, is_async=True, **kwargs):
        captured_kwargs.update(kwargs)
        return "no-proxy-job"

    monkeypatch.setattr("saq.modules.phishkit.scan_url", mock_scan_url)
    monkeypatch.setattr("saq.modules.phishkit.PhishkitAnalyzer.delay_analysis", lambda *a, **kw: None)
    monkeypatch.setattr("saq.util.filesystem.create_temporary_directory", lambda: "/tmp/no-proxy-test")

    analyzer = PhishkitAnalyzer(
        get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
        context=create_test_context(root=root))
    analyzer.execute_analysis(url_observable)

    assert captured_kwargs.get("proxy") is None


@pytest.mark.integration
def test_phishkit_analyzer_continue_analysis_redacts_proxy_from_stdout(monkeypatch, test_context):
    """Test that proxy credentials are redacted from stdout/stderr in analysis details."""
    from saq.configuration.config import get_config
    from saq.configuration.schema import ProxyConfig

    proxy_config = ProxyConfig(name="testproxy", transport="http", host="gate.proxy.com", port=10001, user="proxyuser", password="s3cr3t+pass")
    get_config().clear_proxy_configs()
    get_config().add_proxy_config("testproxy", proxy_config)
    monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'proxy', 'testproxy')

    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    url_observable = root.add_observable_by_spec(F_URL, "https://example.com/phish")
    analysis = PhishkitAnalysis()
    analysis.job_id = "redact-test-job"
    analysis.output_dir = "/tmp/test-redact"
    url_observable.add_analysis(analysis)

    with tempfile.TemporaryDirectory() as temp_dir:
        exit_code_file = os.path.join(temp_dir, "exit.code")
        stdout_file = os.path.join(temp_dir, "std.out")
        stderr_file = os.path.join(temp_dir, "std.err")

        with open(exit_code_file, "w") as f:
            f.write("0")
        with open(stdout_file, "w") as f:
            f.write("using proxy: proxyuser:s3cr3t+pass@gate.proxy.com:10001\nopening https://example.com\n")
        with open(stderr_file, "w") as f:
            f.write("some error mentioning proxyuser:s3cr3t+pass@gate.proxy.com\n")

        output_files = [exit_code_file, stdout_file, stderr_file]

        def mock_get_async_scan_result(job_id, output_dir, timeout=1):
            return output_files

        monkeypatch.setattr("saq.modules.phishkit.get_async_scan_result", mock_get_async_scan_result)

        analyzer = PhishkitAnalyzer(
            get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
            context=create_test_context(root=root))
        result = analyzer.continue_analysis(url_observable, analysis)

        assert result == AnalysisExecutionResult.COMPLETED
        # Credentials must not appear in stdout or stderr
        assert "s3cr3t+pass" not in analysis.stdout
        assert "proxyuser" not in analysis.stdout
        assert "****:****" in analysis.stdout
        assert "s3cr3t+pass" not in analysis.stderr
        assert "proxyuser" not in analysis.stderr
        assert "****:****" in analysis.stderr
        # Host:port should still be visible
        assert "gate.proxy.com" in analysis.stdout


@pytest.mark.integration
def test_phishkit_analyzer_file_scan_passes_proxy(monkeypatch, test_context):
    """Test that proxy string is passed through to scan_file when configured."""
    from saq.configuration.config import get_config
    from saq.configuration.schema import ProxyConfig

    proxy_config = ProxyConfig(name="testproxy", transport="http", host="proxy.test", port=9090, user="u", password="p")
    get_config().clear_proxy_configs()
    get_config().add_proxy_config("testproxy", proxy_config)

    monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'proxy', 'testproxy')
    monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'valid_file_extensions', ['.html'])
    monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER), 'valid_mime_types', ['text/html'])

    root = create_root_analysis(analysis_mode='correlation')
    root.initialize_storage()

    with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
        f.write('<html><body>Test</body></html>')
        test_file_path = f.name

    try:
        file_observable = root.add_file_observable(test_file_path)
        file_observable.add_directive(DIRECTIVE_RENDER)

        file_type_analysis = FileTypeAnalysis()
        file_type_analysis.details = {'type': 'HTML document', 'mime': 'text/html'}
        file_observable.add_analysis(file_type_analysis)

        captured_kwargs = {}

        def mock_scan_file(file_path, output_dir, is_async=True, **kwargs):
            captured_kwargs.update(kwargs)
            return "proxy-file-job"

        monkeypatch.setattr("saq.modules.phishkit.scan_file", mock_scan_file)
        monkeypatch.setattr("saq.modules.phishkit.PhishkitAnalyzer.delay_analysis", lambda *a, **kw: AnalysisExecutionResult.INCOMPLETE)
        monkeypatch.setattr("saq.util.filesystem.create_temporary_directory", lambda: "/tmp/proxy-file-test")

        analyzer = PhishkitAnalyzer(
            get_analysis_module_config(ANALYSIS_MODULE_PHISHKIT_ANALYZER),
            context=create_test_context(root=root))
        monkeypatch.setattr(analyzer, "wait_for_analysis", lambda obs, at: file_type_analysis)

        analyzer.execute_analysis(file_observable)

        assert captured_kwargs.get("proxy") == "u:p@proxy.test:9090"
    finally:
        if os.path.exists(test_file_path):
            os.unlink(test_file_path)
