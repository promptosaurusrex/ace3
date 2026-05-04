import logging
from typing import Optional

from saq.analysis import Analysis
from saq.constants import F_EMAIL_ADDRESS, F_FQDN, AnalysisExecutionResult
from saq.email import get_email_domain
from saq.modules import AnalysisModule

KEY_DOMAIN = "domain"


class EmailAddressFQDNAnalysis(Analysis):
    """Extracts the domain portion of an email address as an FQDN observable."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {KEY_DOMAIN: None}

    @property
    def domain(self) -> Optional[str]:
        return self.details[KEY_DOMAIN]

    @domain.setter
    def domain(self, value: str):
        self.details[KEY_DOMAIN] = value

    def generate_summary(self):
        if not self.domain:
            return None
        return f"Email Address FQDN: {self.domain}"


class EmailAddressFQDNAnalyzer(AnalysisModule):
    """Adds the domain of an email_address observable as a volatile fqdn observable."""

    @property
    def generated_analysis_type(self):
        return EmailAddressFQDNAnalysis

    @property
    def valid_observable_types(self):
        return F_EMAIL_ADDRESS

    def execute_analysis(self, observable) -> AnalysisExecutionResult:
        domain = get_email_domain(observable.value)
        if not domain:
            logging.debug(f"no domain extractable from email address {observable.value}")
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(observable)
        assert isinstance(analysis, EmailAddressFQDNAnalysis)
        analysis.domain = domain
        analysis.add_observable_by_spec(F_FQDN, domain, volatile=True)
        return AnalysisExecutionResult.COMPLETED
