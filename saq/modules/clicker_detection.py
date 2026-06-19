# vim: sw=4:ts=4:et:cc=120

"""Splunk clicker detection analysis module.

Answers "did anyone click this URL / visit this domain?" by running per-source log searches for an
observable carrying the ``clicker_detection`` directive (added by the "Check for clickers" observable
action). The source-agnostic orchestration lives in ``saq.clicker_detection.analyzer``; this module
is the Splunk concrete implementation. The search definitions live in an analyst-editable config file
(see ``saq.clicker_detection.config``) watched for live reload, so analysts can tune them without a
production release.

Results are published as ``ClickerEvent``s for the alert-level "URL Clicks" view, and on a real click
(e.g. ``ActionType == ClickAllowed``) the module escalates: it adds a detection point and
crawls/Phishkit-analyzes the clicked URL.
"""

from typing import Type

from saq.analysis.presenter.analysis_presenter import register_analysis_presenter
from saq.clicker_detection.analyzer import (
    ClickerConfigMixin,
    ClickerDetectionAnalysisMixin,
    ClickerDetectionMixin,
)
from saq.clicker_detection.config import splunk_value_expansion
from saq.clicker_detection.timeline import register_clicker_event_provider
from saq.modules.api_analysis import BaseAPIAnalysisPresenter
from saq.modules.config import AnalysisModuleConfig
from saq.modules.splunk import SplunkAPIAnalysis, SplunkAPIAnalyzer, SplunkAPIAnalyzerConfig


class SplunkClickerDetectionAnalyzerConfig(ClickerConfigMixin, SplunkAPIAnalyzerConfig):
    pass


class SplunkClickerDetectionAnalysis(ClickerDetectionAnalysisMixin, SplunkAPIAnalysis):
    """Splunk clicker detection results. Publishes ClickerEvents for the URL Clicks view."""


class SplunkClickerDetectionAnalyzer(ClickerDetectionMixin, SplunkAPIAnalyzer):
    """Runs the configured Splunk clicker searches for url/fqdn observables carrying the
    clicker_detection directive (set valid_observable_types + required_directives in saq config).
    Search definitions are loaded from the watched clicker config file."""

    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return SplunkClickerDetectionAnalyzerConfig

    @property
    def generated_analysis_type(self):
        return SplunkClickerDetectionAnalysis

    # ---- source-specific hooks ----

    def _expand_value_clause(self, values) -> str:
        return splunk_value_expansion(values, self._escape_value)

    def _build_search_link(self):
        return self.splunk.encoded_query_link(self.target_query)

    def _reset_job_slot(self, analysis) -> None:
        analysis.search_id = None
        analysis.dispatch_state = None
        analysis.start_time = None
        analysis.running_start_time = None
        analysis.end_time = None


register_analysis_presenter(SplunkClickerDetectionAnalysis, BaseAPIAnalysisPresenter)
register_clicker_event_provider(SplunkClickerDetectionAnalysis)
