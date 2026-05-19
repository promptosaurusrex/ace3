"""Module for RDAP analysis of domain names.

RDAP (RFC 7480-7484, RFC 9083) is ICANN's replacement for WHOIS. We
prefer RDAP, falling back to legacy WHOIS only when RDAP cannot
answer — primarily for country-code TLDs (.de, .br, etc.) that have
not yet stood up an RDAP service.

Outcomes to handle:

    - RDAP succeeds: parsed registration data + raw JSON response.
    - RDAP says "domain not found": authoritative negative, no
      fallback to WHOIS (the registry told us the truth).
    - RDAP can't serve this TLD / bootstrap failed / RDAP server
      errored: fall back to ``python-whois``.
    - Both fail: surface a combined error so the analyst sees both
      failure modes.
    - Query succeeds but the registry omits creation / last-changed
      events: record the metadata we did get; ages stay None.

The cacheability contract still applies (no removals, no file
observables), so this module is opted into the 7-day analysis cache
the same way the legacy WhoisAnalyzer was.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional

import whois
import whoisit
from whois.exceptions import PywhoisError
from whoisit.errors import (
    BootstrapError,
    QueryError,
    ResourceDoesNotExist,
    UnsupportedError,
)

from saq.analysis import Analysis
from saq.analysis.presenter.analysis_presenter import (
    AnalysisPresenter,
    register_analysis_presenter,
)
from saq.constants import F_FQDN, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.util.strings import format_item_list_for_summary

KEY_ERROR = "error"
KEY_LOOKUP_PROTOCOL = "lookup_protocol"
KEY_RDAP_ATTEMPT_ERROR = "rdap_attempt_error"

KEY_AGE_CREATED_IN_DAYS = "age_created_in_days"
KEY_AGE_LAST_UPDATED_IN_DAYS = "age_last_updated_in_days"
KEY_DATETIME_CREATED = "datetime_created"
KEY_DATETIME_EXPIRATION = "datetime_expiration"
KEY_DATETIME_OF_ANALYSIS = "datetime_of_analysis"
KEY_DATETIME_OF_LAST_UPDATE = "datetime_of_last_update"

KEY_DOMAIN_NAME = "domain_name"
KEY_REGISTRAR = "registrar"
KEY_RDAP_SERVICE_URL = "rdap_service_url"
KEY_NAME_SERVERS = "name_servers"
KEY_EMAILS = "emails"

KEY_RDAP_DATA = "rdap_data"
KEY_RDAP_RAW_JSON = "rdap_raw_json"
KEY_WHOIS_DATA = "whois_data"
KEY_WHOIS_RAW_TEXT = "whois_raw_text"

# Cap stored email count so a pathological registry response can't
# inflate the cached payload past the blob-spill threshold.
_MAX_EMAILS_STORED = 20


def _age_in_days_as_string(past: datetime, present: datetime) -> str:
    past = (
        past.astimezone(timezone.utc)
        if past.tzinfo is not None
        else past.replace(tzinfo=timezone.utc)
    )
    present = (
        present.astimezone(timezone.utc)
        if present.tzinfo is not None
        else present.replace(tzinfo=timezone.utc)
    )
    delta = present - past
    # Negative deltas usually mean tz weirdness; clamp to zero.
    if delta.days < 0:
        return "0"
    return str(delta.days)


def _extract_rdap_registrar(rdap_dict: dict) -> Optional[str]:
    entities = rdap_dict.get("entities") or {}
    for entity in entities.get("registrar") or []:
        if isinstance(entity, dict):
            name = entity.get("name")
            if name:
                return name
    return None


def _extract_rdap_emails(rdap_dict: dict) -> list[str]:
    emails: set[str] = set()
    entities = rdap_dict.get("entities") or {}
    for entity_list in entities.values():
        for entity in entity_list or []:
            if not isinstance(entity, dict):
                continue
            email = entity.get("email")
            if email:
                emails.add(email)
    return sorted(emails)[:_MAX_EMAILS_STORED]


class RdapAnalysis(Analysis):
    """Registration data for a domain, sourced from RDAP (preferred)
    or WHOIS (fallback)."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_ERROR: None,
            KEY_LOOKUP_PROTOCOL: None,
            KEY_RDAP_ATTEMPT_ERROR: None,

            KEY_AGE_CREATED_IN_DAYS: None,
            KEY_AGE_LAST_UPDATED_IN_DAYS: None,
            KEY_DATETIME_CREATED: None,
            KEY_DATETIME_EXPIRATION: None,
            KEY_DATETIME_OF_ANALYSIS: None,
            KEY_DATETIME_OF_LAST_UPDATE: None,

            KEY_DOMAIN_NAME: None,
            KEY_REGISTRAR: None,
            KEY_RDAP_SERVICE_URL: None,
            KEY_NAME_SERVERS: None,
            KEY_EMAILS: None,

            KEY_RDAP_DATA: None,
            KEY_RDAP_RAW_JSON: None,
            KEY_WHOIS_DATA: None,
            KEY_WHOIS_RAW_TEXT: None,
        }

    @property
    def error(self):
        return self.details[KEY_ERROR]

    @error.setter
    def error(self, value):
        self.details[KEY_ERROR] = value

    @property
    def lookup_protocol(self):
        """``"rdap"`` | ``"whois"`` | ``None`` (both failed)."""
        return self.details[KEY_LOOKUP_PROTOCOL]

    @lookup_protocol.setter
    def lookup_protocol(self, value):
        self.details[KEY_LOOKUP_PROTOCOL] = value

    @property
    def rdap_attempt_error(self):
        """RDAP-side error message when we fell back to WHOIS."""
        return self.details[KEY_RDAP_ATTEMPT_ERROR]

    @rdap_attempt_error.setter
    def rdap_attempt_error(self, value):
        self.details[KEY_RDAP_ATTEMPT_ERROR] = value

    @property
    def rdap_data(self):
        """Parsed RDAP response dict from ``whoisit``."""
        return self.details[KEY_RDAP_DATA]

    @rdap_data.setter
    def rdap_data(self, value):
        self.details[KEY_RDAP_DATA] = value

    @property
    def rdap_raw_json(self):
        """Raw RDAP response (RFC 9083 JSON), serialized as a string."""
        return self.details[KEY_RDAP_RAW_JSON]

    @rdap_raw_json.setter
    def rdap_raw_json(self, value):
        self.details[KEY_RDAP_RAW_JSON] = value

    @property
    def whois_data(self):
        """Parsed WHOIS response (only set on fallback)."""
        return self.details[KEY_WHOIS_DATA]

    @whois_data.setter
    def whois_data(self, value):
        self.details[KEY_WHOIS_DATA] = value

    @property
    def whois_raw_text(self):
        """Raw WHOIS response text (only set on fallback)."""
        return self.details[KEY_WHOIS_RAW_TEXT]

    @whois_raw_text.setter
    def whois_raw_text(self, value):
        self.details[KEY_WHOIS_RAW_TEXT] = value

    @property
    def age_created_in_days(self):
        return self.details[KEY_AGE_CREATED_IN_DAYS]

    @age_created_in_days.setter
    def age_created_in_days(self, value):
        self.details[KEY_AGE_CREATED_IN_DAYS] = value

    @property
    def age_last_updated_in_days(self):
        return self.details[KEY_AGE_LAST_UPDATED_IN_DAYS]

    @age_last_updated_in_days.setter
    def age_last_updated_in_days(self, value):
        self.details[KEY_AGE_LAST_UPDATED_IN_DAYS] = value

    @property
    def datetime_created(self):
        return self.details[KEY_DATETIME_CREATED]

    @datetime_created.setter
    def datetime_created(self, value):
        self.details[KEY_DATETIME_CREATED] = value

    @property
    def datetime_expiration(self):
        return self.details[KEY_DATETIME_EXPIRATION]

    @datetime_expiration.setter
    def datetime_expiration(self, value):
        self.details[KEY_DATETIME_EXPIRATION] = value

    @property
    def datetime_of_analysis(self):
        return self.details[KEY_DATETIME_OF_ANALYSIS]

    @datetime_of_analysis.setter
    def datetime_of_analysis(self, value):
        self.details[KEY_DATETIME_OF_ANALYSIS] = value

    @property
    def datetime_of_last_update(self):
        return self.details[KEY_DATETIME_OF_LAST_UPDATE]

    @datetime_of_last_update.setter
    def datetime_of_last_update(self, value):
        self.details[KEY_DATETIME_OF_LAST_UPDATE] = value

    @property
    def domain_name(self):
        return self.details[KEY_DOMAIN_NAME]

    @domain_name.setter
    def domain_name(self, value):
        self.details[KEY_DOMAIN_NAME] = value

    @property
    def registrar(self):
        return self.details[KEY_REGISTRAR]

    @registrar.setter
    def registrar(self, value):
        self.details[KEY_REGISTRAR] = value

    @property
    def rdap_service_url(self):
        """URL of the upstream RDAP service that answered the query."""
        return self.details[KEY_RDAP_SERVICE_URL]

    @rdap_service_url.setter
    def rdap_service_url(self, value):
        self.details[KEY_RDAP_SERVICE_URL] = value

    @property
    def name_servers(self):
        return self.details[KEY_NAME_SERVERS]

    @name_servers.setter
    def name_servers(self, value):
        self.details[KEY_NAME_SERVERS] = value

    @property
    def emails(self):
        return self.details[KEY_EMAILS]

    @emails.setter
    def emails(self, value):
        self.details[KEY_EMAILS] = value

    def generate_summary(self):
        parts = []
        suffix = ""
        if self.lookup_protocol == "whois":
            suffix = " (whois fallback)"

        if self.error:
            parts.append(f"error: {self.error}")
        else:
            if self.age_created_in_days:
                parts.append(f"created: {self.age_created_in_days} day(s) ago")
            if self.age_last_updated_in_days:
                parts.append(f"last updated: {self.age_last_updated_in_days} day(s) ago")
            if self.name_servers:
                parts.append(
                    f"nameservers: ({format_item_list_for_summary(self.name_servers)})"
                )
            if self.registrar:
                parts.append(f"registrar: {self.registrar}")
            if self.rdap_service_url:
                parts.append(f"rdap service: {self.rdap_service_url}")
            if self.emails:
                parts.append(f"emails: ({format_item_list_for_summary(self.emails)})")

        if not parts:
            return None

        return f"RDAP Analysis{suffix}: " + ", ".join(parts)


class RdapAnalyzer(AnalysisModule):
    """Analysis module performing RDAP (with WHOIS fallback) on FQDN
    observables.
    """

    @property
    def generated_analysis_type(self):
        return RdapAnalysis

    @property
    def valid_observable_types(self):
        return F_FQDN

    def _ensure_rdap_bootstrap(self) -> Optional[str]:
        """Best-effort lazy bootstrap of the IANA RDAP registry. Returns
        ``None`` on success, or an error string on failure (caller
        treats that as a reason to skip RDAP and go straight to WHOIS).
        Repeated bootstrap attempts are cheap because ``whoisit``
        caches state in module-level globals.
        """
        try:
            if not whoisit.is_bootstrapped():
                whoisit.bootstrap()
            return None
        except BootstrapError as e:
            return f"bootstrap failed: {e}".split("\n", 1)[0].strip()

    def execute_analysis(self, observable) -> AnalysisExecutionResult:
        analysis = self.create_analysis(observable)
        now = datetime.now(timezone.utc)
        analysis.datetime_of_analysis = now.isoformat(" ")

        # ---- RDAP attempt --------------------------------------------------
        bootstrap_error = self._ensure_rdap_bootstrap()
        if bootstrap_error is not None:
            rdap_error: Optional[str] = bootstrap_error
        else:
            rdap_error = self._try_rdap(observable, analysis, now)
            if rdap_error is None:
                analysis.lookup_protocol = "rdap"
                return AnalysisExecutionResult.COMPLETED
            if rdap_error == _RDAP_NXDOMAIN_SENTINEL:
                # Authoritative "not found" — don't waste a WHOIS query.
                return AnalysisExecutionResult.COMPLETED

        # ---- WHOIS fallback ------------------------------------------------
        analysis.rdap_attempt_error = rdap_error
        whois_error = self._try_whois(observable, analysis, now)
        if whois_error is None:
            analysis.lookup_protocol = "whois"
            return AnalysisExecutionResult.COMPLETED

        analysis.error = f"rdap: {rdap_error}; whois: {whois_error}"
        return AnalysisExecutionResult.COMPLETED

    def _try_rdap(
        self,
        observable,
        analysis: RdapAnalysis,
        now: datetime,
    ) -> Optional[str]:
        """Populate ``analysis`` from an RDAP query.

        Returns:
            ``None`` on success;
            ``_RDAP_NXDOMAIN_SENTINEL`` for an authoritative "does not
                exist" answer (no fallback needed; the error is also
                stored on the analysis);
            a free-form error string for any other failure (caller
                will fall back to WHOIS).
        """
        try:
            result = whoisit.domain(observable.value, include_raw=True)
        except ResourceDoesNotExist as e:
            analysis.error = f"rdap: domain not found: {e}".split(
                "\n", 1
            )[0].strip()[:200]
            return _RDAP_NXDOMAIN_SENTINEL
        except UnsupportedError as e:
            return f"no RDAP service for TLD: {e}".split("\n", 1)[0].strip()
        except QueryError as e:
            return str(e).split("\n", 1)[0].strip() or "query failed"
        except Exception as e:  # noqa: BLE001 — defensive against lib changes
            return f"rdap client error: {type(e).__name__}: {e}".split(
                "\n", 1
            )[0].strip()

        raw = result.pop("raw", None)
        # Plain-dict copy of the parsed result so the cached payload is
        # JSON-clean (datetime values pass through and serialize via the
        # cache layer's default=str codec).
        analysis.rdap_data = dict(result)
        analysis.rdap_raw_json = json.dumps(raw, default=str) if raw is not None else None

        analysis.domain_name = result.get("name") or observable.value
        analysis.registrar = _extract_rdap_registrar(result)
        nameservers = result.get("nameservers") or []
        analysis.name_servers = list(nameservers)
        analysis.emails = _extract_rdap_emails(result)
        # whoisit surfaces the upstream RDAP service URL under ``url``
        # (the link analysts can click) and the auth registry under
        # ``rir``. ``url`` is the more useful of the two for an analyst.
        analysis.rdap_service_url = result.get("url") or result.get("rir")

        created = result.get("registration_date")
        if isinstance(created, datetime):
            analysis.datetime_created = created.isoformat(" ")
            analysis.age_created_in_days = _age_in_days_as_string(created, now)
        elif created is not None:
            logging.warning(
                f"RDAP result for {observable} has unexpected "
                f"registration_date format: {type(created).__name__}"
            )

        updated = result.get("last_changed_date")
        if isinstance(updated, datetime):
            analysis.datetime_of_last_update = updated.isoformat(" ")
            analysis.age_last_updated_in_days = _age_in_days_as_string(updated, now)
        elif updated is not None:
            logging.warning(
                f"RDAP result for {observable} has unexpected "
                f"last_changed_date format: {type(updated).__name__}"
            )

        expires = result.get("expiration_date")
        if isinstance(expires, datetime):
            analysis.datetime_expiration = expires.isoformat(" ")

        return None

    def _try_whois(
        self,
        observable,
        analysis: RdapAnalysis,
        now: datetime,
    ) -> Optional[str]:
        """Populate ``analysis`` from a legacy WHOIS query. Returns
        ``None`` on success or an error string on failure.
        """
        try:
            whois_result = whois.whois(observable.value)
        except PywhoisError as e:
            return str(e).split("\n", 1)[0].strip()[:200] or "query failed"
        except Exception as e:  # noqa: BLE001
            return f"whois client error: {type(e).__name__}: {e}".split(
                "\n", 1
            )[0].strip()

        # ``python-whois`` returns a ``WhoisEntry`` (dict subclass).
        # Flatten to a plain dict so the cached payload doesn't depend
        # on the library's class survival across versions.
        analysis.whois_data = dict(whois_result) if whois_result else {}
        analysis.whois_raw_text = getattr(whois_result, "text", None)

        # WHOIS responses can pack multi-value fields as either scalar
        # or list — mirror the legacy module's "take the first if list"
        # behaviour.
        def _first(value):
            return value[0] if isinstance(value, list) and value else value

        domain_name = _first(whois_result.get("domain_name"))
        analysis.domain_name = domain_name
        analysis.registrar = whois_result.get("registrar")
        analysis.name_servers = whois_result.get("name_servers") or []
        emails = whois_result.get("emails") or []
        if isinstance(emails, str):
            emails = [emails]
        analysis.emails = sorted(set(emails))[:_MAX_EMAILS_STORED]

        created = _first(whois_result.get("creation_date"))
        if isinstance(created, datetime):
            analysis.datetime_created = created.isoformat(" ")
            analysis.age_created_in_days = _age_in_days_as_string(created, now)
        elif created is not None:
            logging.warning(
                f"whois fallback for {observable} has unexpected "
                f"creation_date format: {type(created).__name__}"
            )

        updated = _first(whois_result.get("updated_date"))
        if isinstance(updated, datetime):
            analysis.datetime_of_last_update = updated.isoformat(" ")
            analysis.age_last_updated_in_days = _age_in_days_as_string(updated, now)
        elif updated is not None:
            logging.warning(
                f"whois fallback for {observable} has unexpected "
                f"updated_date format: {type(updated).__name__}"
            )

        expires = _first(whois_result.get("expiration_date"))
        if isinstance(expires, datetime):
            analysis.datetime_expiration = expires.isoformat(" ")

        return None


# Sentinel returned by ``_try_rdap`` to distinguish "RDAP says no" from
# "RDAP can't answer". Internal; never stored on the analysis.
_RDAP_NXDOMAIN_SENTINEL = "__rdap_nxdomain__"


class RdapAnalysisPresenter(AnalysisPresenter):
    """Presenter for RdapAnalysis."""

    @property
    def template_path(self) -> str:
        return "analysis/rdap.html"


register_analysis_presenter(RdapAnalysis, RdapAnalysisPresenter)
