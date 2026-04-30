"""Analysis module that flags FQDN observables found in the local NRD database.

Runs on every FQDN observable in every analysis mode. The actual lookup is a
microsecond-cheap SQLite query through ``saq.nrd.util.is_newly_registered``;
the analyzer just decorates a hit with a tag and an analysis record.

Adding a *detection point* is intentionally not done here — promoting an
email to an alert is the job of a separate observable modifier rule (see
``docs/design/newly_registered_domains.md``).
"""

from datetime import datetime, timezone

from saq.analysis import Analysis
from saq.constants import F_FQDN, F_URL, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.nrd.util import is_newly_registered


KEY_IS_NRD = "is_nrd"
KEY_MATCHED_AT = "matched_at"

TAG_NRD = "suspect:nrd"


class NRDAnalysis(Analysis):
    """Marker analysis for FQDNs found in the local newly-registered-domains database."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_IS_NRD: None,
            KEY_MATCHED_AT: None,
        }

    @property
    def is_nrd(self) -> bool:
        return bool(self.details.get(KEY_IS_NRD))

    @is_nrd.setter
    def is_nrd(self, value: bool) -> None:
        self.details[KEY_IS_NRD] = bool(value)

    @property
    def matched_at(self):
        return self.details.get(KEY_MATCHED_AT)

    @matched_at.setter
    def matched_at(self, value) -> None:
        self.details[KEY_MATCHED_AT] = value

    def generate_summary(self):
        if self.is_nrd:
            return "Newly Registered Domain: present in local NRD list"
        return None


class NRDAnalyzer(AnalysisModule):
    """Tag FQDN or URL observables whose host appears in the local NRD database.

    Runs on both FQDN and URL observables. ``is_newly_registered`` auto-detects
    URL inputs and extracts the host, so the analyzer body is the same for
    either type. URL coverage is what makes this work in email mode, where
    ``parse_url`` is not enabled and URL-host FQDN observables therefore don't
    get created as a separate observable for the analyzer to run against.
    """

    @property
    def generated_analysis_type(self):
        return NRDAnalysis

    @property
    def valid_observable_types(self):
        return [F_FQDN, F_URL]

    def execute_analysis(self, observable) -> AnalysisExecutionResult:
        if not is_newly_registered(observable.value):
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(observable)
        analysis.is_nrd = True
        analysis.matched_at = datetime.now(timezone.utc).isoformat()

        observable.add_tag(TAG_NRD)

        return AnalysisExecutionResult.COMPLETED
