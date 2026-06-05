import os
import shutil

import pytest
from unittest.mock import Mock, patch

from saq.constants import ANALYSIS_MODE_CORRELATION, QUEUE_DEFAULT
from saq.engine.analysis_orchestrator import AnalysisOrchestrator
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.execution_context import EngineExecutionContext
from saq.engine.executor import AnalysisExecutor
from saq.environment import get_global_runtime_settings
from tests.saq.helpers import create_root_analysis


@pytest.mark.unit
class TestAnalysisOrchestratorHandleDetectionPoints:
    """Test cases for AnalysisOrchestrator._handle_detection_points method."""

    @pytest.fixture
    def mock_config_manager(self):
        """Create a mock configuration manager."""
        config_manager = Mock(spec=ConfigurationManager)
        config_manager.config = Mock()
        config_manager.config.non_detectable_modes = ["analysis"]
        config_manager.config.alerting_enabled = True
        return config_manager

    @pytest.fixture
    def mock_analysis_executor(self):
        """Create a mock analysis executor."""
        return Mock(spec=AnalysisExecutor)

    @pytest.fixture
    def mock_workload_manager(self):
        """Create a mock workload manager."""
        return Mock()

    @pytest.fixture
    def mock_lock_manager(self):
        """Create a mock lock manager."""
        return Mock()

    @pytest.fixture
    def orchestrator(self, mock_config_manager, mock_analysis_executor, mock_workload_manager, mock_lock_manager):
        """Create an AnalysisOrchestrator instance for testing."""
        return AnalysisOrchestrator(
            configuration_manager=mock_config_manager,
            analysis_executor=mock_analysis_executor,
            workload_manager=mock_workload_manager,
            lock_manager=mock_lock_manager
        )

    @pytest.fixture
    def execution_context(self):
        """Create an execution context with a test root analysis."""
        root = create_root_analysis(analysis_mode="test_mode")
        context = Mock(spec=EngineExecutionContext)
        context.root = root
        return context

    def test_handle_detection_points_non_detectable_mode(self, orchestrator, execution_context):
        """Test that function returns early for non-detectable analysis modes."""
        execution_context.root.analysis_mode = "analysis"
        
        orchestrator._handle_detection_points(execution_context)
        
        assert execution_context.root.analysis_mode == "analysis"

    @pytest.mark.parametrize("forced_alerts,expected_mode", [
        (False, "test_mode"),
        (True, ANALYSIS_MODE_CORRELATION)
    ])
    def test_handle_detection_points_whitelisted_analysis(self, orchestrator, execution_context, monkeypatch, forced_alerts, expected_mode):
        """Test whitelisted analysis behavior with and without forced alerts."""
        execution_context.root.analysis_mode = "test_mode"
        execution_context.root.add_tag("whitelisted")
        
        monkeypatch.setattr(get_global_runtime_settings(), "forced_alerts", forced_alerts)
        
        orchestrator._handle_detection_points(execution_context)
        
        assert execution_context.root.analysis_mode == expected_mode

    @pytest.mark.parametrize("initial_mode,expected_mode", [
        ("test_mode", ANALYSIS_MODE_CORRELATION),
        (ANALYSIS_MODE_CORRELATION, ANALYSIS_MODE_CORRELATION)
    ])
    def test_handle_detection_points_with_detections(self, orchestrator, execution_context, monkeypatch, initial_mode, expected_mode):
        """Test analysis with detections changes to or stays in correlation mode."""
        execution_context.root.analysis_mode = initial_mode
        
        # Mock has_detections to return True and all_detection_points property
        monkeypatch.setattr(execution_context.root, 'has_detections', Mock(return_value=True))
        mock_detection_points = ["detection1", "detection2"]
        monkeypatch.setattr(type(execution_context.root), 'all_detection_points', property(lambda self: mock_detection_points))
        monkeypatch.setattr(get_global_runtime_settings(), "forced_alerts", False)
        
        orchestrator._handle_detection_points(execution_context)
        
        assert execution_context.root.analysis_mode == expected_mode

    @pytest.mark.parametrize("forced_alerts,expected_mode", [
        (False, "test_mode"),
        (True, ANALYSIS_MODE_CORRELATION)
    ])
    def test_handle_detection_points_no_detections_forced_alerts_behavior(self, orchestrator, execution_context, monkeypatch, forced_alerts, expected_mode):
        """Test behavior with no detections and varying forced alerts settings."""
        execution_context.root.analysis_mode = "test_mode"
        
        # Mock has_detections to return False
        monkeypatch.setattr(execution_context.root, 'has_detections', Mock(return_value=False))
        monkeypatch.setattr(get_global_runtime_settings(), "forced_alerts", forced_alerts)
        
        orchestrator._handle_detection_points(execution_context)
        
        assert execution_context.root.analysis_mode == expected_mode

    @pytest.mark.parametrize("has_detections,forced_alerts", [
        (True, False),
        (False, True)
    ])
    def test_handle_detection_points_alerting_disabled_no_change(self, orchestrator, execution_context, monkeypatch, has_detections, forced_alerts):
        """Test that no mode changes occur when alerting is disabled."""
        orchestrator.config.alerting_enabled = False
        execution_context.root.analysis_mode = "test_mode"
        
        # Mock has_detections and forced alerts behavior
        monkeypatch.setattr(execution_context.root, 'has_detections', Mock(return_value=has_detections))
        if has_detections:
            mock_detection_points = ["detection1"]
            monkeypatch.setattr(type(execution_context.root), 'all_detection_points', property(lambda self: mock_detection_points))
        monkeypatch.setattr(get_global_runtime_settings(), "forced_alerts", forced_alerts)
        
        orchestrator._handle_detection_points(execution_context)

        assert execution_context.root.analysis_mode == "test_mode"


@pytest.mark.unit
class TestAnalysisOrchestratorFinallyBlock:
    """Test cases to validate that _handle_post_analysis_logic is called in the finally block."""

    @pytest.fixture
    def mock_config_manager(self):
        """create a mock configuration manager"""
        config_manager = Mock(spec=ConfigurationManager)
        config_manager.config = Mock()
        config_manager.config.non_detectable_modes = ["analysis"]
        config_manager.config.alerting_enabled = True
        return config_manager

    @pytest.fixture
    def mock_analysis_executor(self):
        """create a mock analysis executor"""
        return Mock(spec=AnalysisExecutor)

    @pytest.fixture
    def mock_workload_manager(self):
        """create a mock workload manager"""
        return Mock()

    @pytest.fixture
    def mock_lock_manager(self):
        """create a mock lock manager"""
        return Mock()

    @pytest.fixture
    def orchestrator(self, mock_config_manager, mock_analysis_executor, mock_workload_manager, mock_lock_manager):
        """create an AnalysisOrchestrator instance for testing"""
        return AnalysisOrchestrator(
            configuration_manager=mock_config_manager,
            analysis_executor=mock_analysis_executor,
            workload_manager=mock_workload_manager,
            lock_manager=mock_lock_manager
        )

    @pytest.fixture
    def execution_context(self, tmpdir):
        """create an execution context with a test root analysis"""
        root = create_root_analysis(analysis_mode="test_mode", storage_dir=str(tmpdir))
        root.save()
        context = Mock(spec=EngineExecutionContext)
        context.root = root
        context.work_item = root
        return context

    def test_post_analysis_logic_called_on_success(self, orchestrator, execution_context):
        """test that _handle_post_analysis_logic is called when analysis succeeds"""
        with patch.object(orchestrator, '_process_work_item', return_value=True), \
             patch.object(orchestrator, '_check_disposition', return_value=False), \
             patch.object(orchestrator, '_execute_analysis'), \
             patch.object(orchestrator, '_handle_post_analysis_logic') as mock_post_analysis:

            result = orchestrator.orchestrate_analysis(execution_context)

            assert result is True
            mock_post_analysis.assert_called_once_with(execution_context)

    def test_post_analysis_logic_called_on_execute_analysis_exception(self, orchestrator, execution_context):
        """test that _handle_post_analysis_logic is called even when _execute_analysis raises an exception"""
        with patch.object(orchestrator, '_process_work_item', return_value=True), \
             patch.object(orchestrator, '_check_disposition', return_value=False), \
             patch.object(orchestrator, '_execute_analysis', side_effect=RuntimeError("analysis failed")), \
             patch.object(orchestrator, '_handle_post_analysis_logic') as mock_post_analysis:

            result = orchestrator.orchestrate_analysis(execution_context)

            assert result is False
            mock_post_analysis.assert_called_once_with(execution_context)

    def test_post_analysis_logic_called_on_check_disposition_exception(self, orchestrator, execution_context):
        """test that _handle_post_analysis_logic is called when _check_disposition raises an exception"""
        with patch.object(orchestrator, '_process_work_item', return_value=True), \
             patch.object(orchestrator, '_check_disposition', side_effect=RuntimeError("disposition check failed")), \
             patch.object(orchestrator, '_handle_post_analysis_logic') as mock_post_analysis:

            result = orchestrator.orchestrate_analysis(execution_context)

            assert result is False
            mock_post_analysis.assert_called_once_with(execution_context)

    def test_post_analysis_logic_skipped_when_process_work_item_fails(self, orchestrator, execution_context):
        """test that _handle_post_analysis_logic is skipped when _process_work_item returns False"""
        with patch.object(orchestrator, '_process_work_item', return_value=False), \
             patch.object(orchestrator, '_handle_post_analysis_logic') as mock_post_analysis:

            result = orchestrator.orchestrate_analysis(execution_context)

            assert result is False
            # the work item was never loaded for analysis - there is nothing to clean up
            mock_post_analysis.assert_not_called()

    def test_post_analysis_logic_skipped_when_root_is_none(self, orchestrator, execution_context):
        """test that _handle_post_analysis_logic is skipped when root is None after processing work item"""
        execution_context.root = None

        with patch.object(orchestrator, '_process_work_item', return_value=True), \
             patch.object(orchestrator, '_handle_post_analysis_logic') as mock_post_analysis:

            result = orchestrator.orchestrate_analysis(execution_context)

            assert result is False
            # the root was never loaded - there is nothing to clean up
            mock_post_analysis.assert_not_called()

    def test_post_analysis_logic_skipped_when_storage_dir_missing(self, orchestrator, execution_context):
        """regression: a re-picked-up work item whose storage dir is gone must not run cleanup

        this reproduces the production scenario where an orphaned workload row is
        re-dispatched after its analysis already completed and its storage directory
        was cleaned up - post-analysis logic must not attempt to rmtree a missing dir"""
        # simulate the production scenario: the analysis already completed and its
        # work storage directory was cleaned up before this orphaned workload row
        # was re-dispatched
        shutil.rmtree(execution_context.root.storage_dir)
        assert not os.path.isdir(execution_context.root.storage_dir)

        with patch.object(orchestrator, '_handle_post_analysis_logic') as mock_post_analysis:
            result = orchestrator.orchestrate_analysis(execution_context)

            assert result is False
            mock_post_analysis.assert_not_called()

    def test_post_analysis_logic_called_when_check_disposition_returns_true(self, orchestrator, execution_context):
        """test that _handle_post_analysis_logic is called when _check_disposition returns True (skipping analysis)"""
        with patch.object(orchestrator, '_process_work_item', return_value=True), \
             patch.object(orchestrator, '_check_disposition', return_value=True), \
             patch.object(orchestrator, '_execute_analysis') as mock_execute, \
             patch.object(orchestrator, '_handle_post_analysis_logic') as mock_post_analysis:

            result = orchestrator.orchestrate_analysis(execution_context)

            assert result is True
            mock_execute.assert_not_called()
            mock_post_analysis.assert_called_once_with(execution_context)

    def test_post_analysis_logic_exception_is_caught(self, orchestrator, execution_context):
        """test that exceptions in _handle_post_analysis_logic are caught and logged"""
        with patch.object(orchestrator, '_process_work_item', return_value=True), \
             patch.object(orchestrator, '_check_disposition', return_value=False), \
             patch.object(orchestrator, '_execute_analysis'), \
             patch.object(orchestrator, '_handle_post_analysis_logic', side_effect=RuntimeError("post-analysis failed")), \
             patch('saq.engine.analysis_orchestrator.logging') as mock_logging:

            result = orchestrator.orchestrate_analysis(execution_context)

            # analysis should still return True because the exception was in the finally block
            assert result is True
            # verify error was logged
            mock_logging.error.assert_called()
            error_call_args = str(mock_logging.error.call_args)
            assert "post-analysis logic" in error_call_args

    def test_orchestrate_analysis_exception_before_finally_block(self, orchestrator, execution_context):
        """test that _handle_post_analysis_logic is called even when there's an exception in the try block"""
        with patch.object(orchestrator, '_process_work_item', return_value=True), \
             patch.object(orchestrator, '_check_disposition', side_effect=ValueError("unexpected error")), \
             patch.object(orchestrator, '_handle_post_analysis_logic') as mock_post_analysis, \
             patch('saq.engine.analysis_orchestrator.logging'):

            result = orchestrator.orchestrate_analysis(execution_context)

            assert result is False
            mock_post_analysis.assert_called_once_with(execution_context)

    def test_multiple_exceptions_in_try_and_finally(self, orchestrator, execution_context):
        """test behavior when exceptions occur in both try and finally blocks"""
        with patch.object(orchestrator, '_process_work_item', return_value=True), \
             patch.object(orchestrator, '_check_disposition', return_value=False), \
             patch.object(orchestrator, '_execute_analysis', side_effect=RuntimeError("execute failed")), \
             patch.object(orchestrator, '_handle_post_analysis_logic', side_effect=RuntimeError("post-analysis failed")), \
             patch('saq.engine.analysis_orchestrator.logging') as mock_logging:

            result = orchestrator.orchestrate_analysis(execution_context)

            assert result is False
            # verify both errors were logged
            assert mock_logging.error.call_count >= 2


@pytest.mark.unit
class TestApplyDetectionQueue:
    """Test AnalysisOrchestrator._apply_detection_queue — centralised, order-independent
    resolution of a queue requested by detection meta (e.g. a yara rule's `queue` meta)."""

    @pytest.fixture
    def orchestrator(self):
        config_manager = Mock(spec=ConfigurationManager)
        config_manager.config = Mock()
        return AnalysisOrchestrator(
            configuration_manager=config_manager,
            analysis_executor=Mock(spec=AnalysisExecutor),
            workload_manager=Mock(),
            lock_manager=Mock(),
        )

    def test_single_routed_detection_sets_queue(self, orchestrator):
        root = create_root_analysis()
        assert root.queue == QUEUE_DEFAULT
        root.add_detection_point("yara hit", queue="experimental")

        orchestrator._apply_detection_queue(root)

        assert root.queue == "experimental"

    def test_routed_plus_plain_detection_keeps_default(self, orchestrator):
        """A co-occurring normal detection means it's a real alert -> stay in the default queue."""
        root = create_root_analysis()
        root.add_detection_point("yara hit", queue="experimental")
        root.add_detection_point("real detection")  # no queue

        orchestrator._apply_detection_queue(root)

        assert root.queue == QUEUE_DEFAULT

    def test_explicit_queue_not_clobbered(self, orchestrator):
        root = create_root_analysis(queue="incoming")
        assert root.queue == "incoming"
        root.add_detection_point("yara hit", queue="experimental")

        orchestrator._apply_detection_queue(root)

        assert root.queue == "incoming"

    def test_no_detections_leaves_default(self, orchestrator):
        root = create_root_analysis()
        orchestrator._apply_detection_queue(root)
        assert root.queue == QUEUE_DEFAULT

    def test_conflicting_queues_pick_sorted_first(self, orchestrator):
        root = create_root_analysis()
        root.add_detection_point("hit b", queue="bravo")
        root.add_detection_point("hit a", queue="alpha")

        orchestrator._apply_detection_queue(root)

        assert root.queue == "alpha"

    def test_routed_detection_on_observable(self, orchestrator):
        """Detections attached to observables (the real yara path) are also resolved."""
        root = create_root_analysis()
        root.initialize_storage()
        observable = root.add_observable_by_spec("yara_rule", "routed_rule")
        observable.add_detection_point("yara hit", queue="experimental")

        orchestrator._apply_detection_queue(root)

        assert root.queue == "experimental"

