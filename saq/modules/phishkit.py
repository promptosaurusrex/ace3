import json
import logging
import os
import re
from typing import Optional, List, Type, override
from urlfinderlib.url import URL

import yaml
from fluent import sender
from pydantic import Field
from saq.analysis import Analysis
from saq.analysis.observable import Observable
from saq.constants import ANALYSIS_MODE_CORRELATION, DIRECTIVE_CRAWL, DIRECTIVE_RENDER, F_URL, F_FILE, AnalysisExecutionResult
from saq.environment import get_base_dir
from saq.error.reporting import report_exception
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.observables.file import FileObservable
from saq.phishkit import get_async_scan_result, scan_file, scan_url
from saq.proxy import proxy_string_for_seleniumbase
from saq.util.filesystem import create_temporary_directory
from saq.util.strings import format_item_list_for_summary

FIELD_OUTPUT_DIR = "output_dir"
FIELD_JOB_ID = "job_id"
FIELD_SCAN_TYPE = "scan_type"
FIELD_SCAN_RESULT = "scan_result"
FIELD_OUTPUT_FILES = "output_files"
FIELD_ERROR = "error"
FIELD_EXIT_CODE = "exit_code"
FIELD_STDOUT = "stdout"
FIELD_STDERR = "stderr"
FIELD_METRICS = "metrics"
FIELD_PROXY_STATUS = "proxy_status"

SCAN_TYPE_URL = "url"
SCAN_TYPE_FILE = "file"


class PhishkitAnalysis(Analysis):
    """Analysis results from Phishkit scanning of URLs and files."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            FIELD_EXIT_CODE: None,
            FIELD_STDOUT: None,
            FIELD_STDERR: None,
            FIELD_OUTPUT_DIR: None,  # output directory for the scan
            FIELD_JOB_ID: None, # job ID for the scan
            FIELD_SCAN_TYPE: None,  # SCAN_TYPE_URL or SCAN_TYPE_FILE
            FIELD_SCAN_RESULT: None,  # result from phishkit scan
            FIELD_OUTPUT_FILES: [],  # list of output file paths
            FIELD_ERROR: None,  # error message if scan failed
            FIELD_METRICS: None,  # scan metrics (bytes downloaded, domain breakdown, etc.)
            FIELD_PROXY_STATUS: None,  # proxy usage / fallback info from the scanner worker
        }

    @override
    @property
    def display_name(self) -> str:
        return "Phishkit Analysis"

    @property
    def exit_code(self) -> Optional[int]:
        return self.details.get(FIELD_EXIT_CODE)
    
    @exit_code.setter
    def exit_code(self, value: int):
        self.details[FIELD_EXIT_CODE] = value
    
    @property
    def stdout(self) -> Optional[str]:
        return self.details.get(FIELD_STDOUT)
    
    @stdout.setter
    def stdout(self, value: str):
        self.details[FIELD_STDOUT] = value
    
    @property
    def stderr(self) -> Optional[str]:
        return self.details.get(FIELD_STDERR)
    
    @stderr.setter
    def stderr(self, value: str):
        self.details[FIELD_STDERR] = value

    @property
    def output_dir(self) -> Optional[str]:
        return self.details.get(FIELD_OUTPUT_DIR)

    @output_dir.setter
    def output_dir(self, value: str):
        self.details[FIELD_OUTPUT_DIR] = value

    @property
    def job_id(self) -> Optional[str]:
        return self.details.get(FIELD_JOB_ID)

    @job_id.setter
    def job_id(self, value: str):
        self.details[FIELD_JOB_ID] = value

    @property
    def scan_type(self) -> Optional[str]:
        return self.details.get(FIELD_SCAN_TYPE)

    @scan_type.setter
    def scan_type(self, value: str):
        self.details[FIELD_SCAN_TYPE] = value

    @property
    def scan_result(self) -> Optional[str]:
        return self.details.get(FIELD_SCAN_RESULT)

    @scan_result.setter
    def scan_result(self, value: str):
        self.details[FIELD_SCAN_RESULT] = value

    @property
    def output_files(self) -> List[str]:
        return self.details.get(FIELD_OUTPUT_FILES, [])

    @output_files.setter
    def output_files(self, value: List[str]):
        self.details[FIELD_OUTPUT_FILES] = value

    @property
    def error(self) -> Optional[str]:
        return self.details.get(FIELD_ERROR)

    @error.setter
    def error(self, value: str):
        self.details[FIELD_ERROR] = value

    @property
    def metrics(self) -> Optional[dict]:
        return self.details.get(FIELD_METRICS)

    @metrics.setter
    def metrics(self, value: dict):
        self.details[FIELD_METRICS] = value

    @property
    def proxy_status(self) -> Optional[dict]:
        return self.details.get(FIELD_PROXY_STATUS)

    @proxy_status.setter
    def proxy_status(self, value: dict):
        self.details[FIELD_PROXY_STATUS] = value

    def generate_summary(self):
        if self.error:
            return f"{self.display_name}: failed: {self.error}"

        if self.scan_type == SCAN_TYPE_URL or self.scan_type == SCAN_TYPE_FILE:
            summary = f"{self.display_name}: output files created (" + format_item_list_for_summary(self.output_files) + ")"
            if self.metrics and self.metrics.get("total_bytes_downloaded"):
                mb = self.metrics["total_bytes_downloaded"] / (1024 * 1024)
                summary += f" - {mb:.2f} MB downloaded"
            if self.proxy_status:
                route = self.proxy_status.get("final_route")
                if route == "proxy":
                    summary += " - fetched via proxy"
                elif route == "direct" and self.proxy_status.get("configured"):
                    reason = self.proxy_status.get("fallback_reason") or "unknown"
                    summary += f" - proxy failed ({reason}), fetched direct"
            return summary
        else:
            return f"{self.display_name}: completed"


class PhishkitAnalyzerConfig(AnalysisModuleConfig):
    valid_file_extensions: list[str] = Field(..., description="List of file extensions to enable for scanning.")
    valid_mime_types: list[str] = Field(..., description="List of mime types to enable for scanning.")
    fluent_bit_metrics_enabled: bool = Field(default=False, description="Whether to forward scan metrics to fluent-bit.")
    fluent_bit_hostname: str = Field(default="fluent-bit", description="Hostname of the fluent-bit server.")
    fluent_bit_port: int = Field(default=24224, description="Port of the fluent-bit forward input.")
    fluent_bit_metrics_tag: str = Field(default="phishkit-metrics", description="Tag for phishkit metrics events.")
    scanner_timeout: int = Field(default=15, description="Timeout in seconds for the phishkit scanner process.")
    proxy: Optional[str] = Field(default=None, description="Named proxy config to route scanner traffic through.")
    proxy_fallback_to_direct: bool = Field(default=True, description="If true, retry scan without proxy on proxy-related failures.")
    config_path: str = Field(default="etc/phishkit_config.yaml", description="Path to phishkit YAML config file, relative to SAQ_HOME.")

class PhishkitAnalyzer(AnalysisModule):
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return PhishkitAnalyzerConfig

    """Analyzes URLs and files using Phishkit for phishing detection."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fluent_bit_metrics_sender: Optional[sender.FluentSender] = None
        if self.config.fluent_bit_metrics_enabled:
            self.fluent_bit_metrics_sender = sender.FluentSender(
                self.config.fluent_bit_metrics_tag,
                host=self.config.fluent_bit_hostname,
                port=self.config.fluent_bit_port,
            )

        # resolve named proxy config to a SeleniumBase-compatible proxy string
        self._proxy_string: Optional[str] = None
        if self.config.proxy:
            self._proxy_string = proxy_string_for_seleniumbase(self.config.proxy)
            if self._proxy_string:
                logging.info(f"phishkit analyzer using proxy: {self.config.proxy}")

        self._deny_crawl_patterns: list[str] = []
        self._yaml_config_path = os.path.join(get_base_dir(), self.config.config_path)
        self._load_deny_patterns()
        self.watch_file(self._yaml_config_path, self._load_deny_patterns)

    def _load_deny_patterns(self):
        """Load deny_crawl_url_patterns from the phishkit YAML config."""
        try:
            with open(self._yaml_config_path, "r") as fp:
                data = yaml.safe_load(fp) or {}
        except Exception as e:
            logging.warning(
                f"failed to load phishkit YAML config {self._yaml_config_path}: {e}"
            )
            self._deny_crawl_patterns = []
            return

        raw = data.get("deny_crawl_url_patterns", []) or []
        if not isinstance(raw, list):
            logging.error(
                f"invalid deny_crawl_url_patterns type in {self._yaml_config_path}: "
                f"expected list, got {type(raw).__name__}"
            )
            raw = []
        self._deny_crawl_patterns = [p.lower() for p in raw if isinstance(p, str) and p]
        logging.debug(
            f"loaded {len(self._deny_crawl_patterns)} phishkit deny_crawl_url_patterns"
        )

    @property
    def generated_analysis_type(self):
        return PhishkitAnalysis

    @property
    def valid_observable_types(self):
        return [F_URL, F_FILE]

    def custom_requirement(self, observable: Observable) -> bool:
        """Custom requirement for phishkit analysis."""
        if observable.type == F_URL:
            url_lc = observable.value.lower()
            for pattern in self._deny_crawl_patterns:
                if pattern in url_lc:
                    logging.info(
                        f"phishkit refusing to scan {observable.value} - "
                        f"matched deny pattern {pattern!r}"
                    )
                    return False
            return True
        elif observable.type == F_FILE:
            # phishkit file rendering only meaningful in correlation mode
            return self.get_root().analysis_mode == ANALYSIS_MODE_CORRELATION
        else:
            return False

    def _redact_proxy_credentials(self, text: str) -> str:
        """Remove proxy credentials from text to prevent storage in analysis details."""
        if not text or not self._proxy_string or '@' not in self._proxy_string:
            return text
        before_at = self._proxy_string.rsplit('@', 1)[0]
        # strip scheme prefix (e.g. socks5://) to get raw user:pass
        if '://' in before_at:
            creds = before_at.split('://', 1)[1]
        else:
            creds = before_at
        if creds:
            return text.replace(creds, "****:****")
        return text

    def continue_analysis(self, observable: Observable, analysis: PhishkitAnalysis) -> AnalysisExecutionResult:
        """Completes an existing analysis."""
        if not analysis.job_id:
            logging.error(f"no job ID for analysis {analysis}")
            return AnalysisExecutionResult.COMPLETED
        
        # wait for the job to complete
        logging.info(f"checking for phishkit scan results for {observable} job ID {analysis.job_id}")
        try:
            scan_results = get_async_scan_result(analysis.job_id, analysis.output_dir, timeout=1)
        except TimeoutError as e:
            error_msg = f"phishkit scan timed out for {observable} job ID {analysis.job_id}: {e}"
            logging.warning(error_msg)
            analysis.error = error_msg
            return AnalysisExecutionResult.COMPLETED
        except Exception as e:
            error_msg = f"phishkit scan failed for {observable} job ID {analysis.job_id}: {e}"
            logging.error(error_msg)
            report_exception()
            analysis.error = error_msg
            return AnalysisExecutionResult.COMPLETED

        if scan_results is None:
            logging.info(f"scan results not ready yet for {observable} job ID {analysis.job_id}")
            return self.delay_analysis(observable, analysis, seconds=3, timeout_seconds=max(self.config.scanner_timeout, 60))

        # if we get this far then the scan results are ready
        analysis.scan_result = f"successfully scanned {observable}"
        analysis.error = None

        for file_path in scan_results:
            if not os.path.exists(file_path):
                logging.error(f"file {file_path} does not exist for {observable} job ID {analysis.job_id}")
                continue

            if os.path.basename(file_path) == "exit.code":
                with open(file_path, "r") as fp:
                    analysis.exit_code = int(fp.read())
            elif os.path.basename(file_path) == "std.out":
                with open(file_path, "r") as fp:
                    analysis.stdout = self._redact_proxy_credentials(fp.read())
            elif os.path.basename(file_path) == "std.err":
                with open(file_path, "r") as fp:
                    analysis.stderr = self._redact_proxy_credentials(fp.read())
            elif os.path.basename(file_path) == "metrics.json":
                try:
                    with open(file_path, "r") as fp:
                        analysis.metrics = json.load(fp)
                    logging.info(f"loaded scan metrics for {observable} job ID {analysis.job_id}: "
                                 f"{analysis.metrics.get('total_bytes_downloaded', 0)} bytes downloaded")
                    if self.fluent_bit_metrics_sender:
                        try:
                            # send one message per domain with all stats
                            for domain, stats in analysis.metrics.get("domain_stats", {}).items():
                                self.fluent_bit_metrics_sender.emit(None, {
                                    "timestamp": analysis.metrics.get("timestamp"),
                                    "job_id": analysis.job_id,
                                    "url_scanned": analysis.metrics.get("url_scanned"),
                                    "total_bytes_downloaded": analysis.metrics.get("total_bytes_downloaded"),
                                    "scan_duration_seconds": analysis.metrics.get("scan_duration_seconds"),
                                    "domain": domain,
                                    **stats,
                                })
                        except Exception as e:
                            logging.error(f"failed to send metrics to fluent-bit for {observable}: {e}")
                except Exception as e:
                    logging.error(f"failed to read metrics.json for {observable}: {e}")
            elif os.path.basename(file_path) == "proxy.json":
                try:
                    with open(file_path, "r") as fp:
                        proxy_status = json.load(fp)
                    # defense in depth — worker already sanitizes host, but redact again
                    # in case an older worker version slipped credentials through
                    host = proxy_status.get("host")
                    if isinstance(host, str):
                        proxy_status["host"] = self._redact_proxy_credentials(host)
                    analysis.proxy_status = proxy_status
                except Exception as e:
                    logging.error(f"failed to read proxy.json for {observable}: {e}")
            else:
                relative_path = os.path.join("phishkit", analysis.job_id, os.path.relpath(file_path, analysis.output_dir))
                file_observable = analysis.add_file_observable(file_path, relative_path)
                if file_observable:
                    from saq.modules.file_analysis.pdf import PDFAnalyzer
                    # do not send phishkit output to phishkit
                    file_observable.add_yara_meta("type", "document.html.phishkit")
                    file_observable.exclude_analysis(self)
                    file_observable.exclude_analysis(PDFAnalyzer)
                    #file_observable.add_directive(DIRECTIVE_EXCLUDE_ALL)
                    analysis.output_files.append(file_observable.file_path)


                # TODO follow the logic of the existing crawlphish module here

        # extract URL observables from MARKER URL entries in dom.html
        dom_path = os.path.join(analysis.output_dir, "dom.html")
        if os.path.exists(dom_path):
            try:
                with open(dom_path, "r", errors="ignore") as fp:
                    for line in fp:
                        match = re.match(r"MARKER URL: (.+)$", line.strip())
                        if match:
                            url = URL(match.group(1).strip())
                            if url.value and not url.value.startswith("file:///"):
                                obs = analysis.add_observable_by_spec(F_URL, url.value)
                                if obs:
                                    obs.display_type = "Phishkit Request URL"
            except Exception as e:
                logging.error(f"failed to extract MARKER URLs from dom.html for {observable}: {e}")

        # extract URL observables from every request entry in requests.json.
        # The MARKER URL pass above only covers URLs whose response bodies
        # were captured into dom.html, which skips anything filtered by
        # skip_body_ext / skip_body_url_patterns and anything that failed
        # outright. Parsing requests.json catches those too — including
        # errored URLs like the second-stage challenge endpoints that get
        # blocked by upstream origin checks. add_observable_by_spec dedupes
        # by value, so overlap with the MARKER URL pass is a no-op.
        requests_path = os.path.join(analysis.output_dir, "requests.json")
        if os.path.exists(requests_path):
            try:
                with open(requests_path, "r", errors="ignore") as fp:
                    entries = json.load(fp)
                for entry in entries:
                    if entry.get("type") != "request":
                        continue
                    raw_url = entry.get("url")
                    if not raw_url:
                        continue
                    if raw_url.startswith(("file:///", "data:", "blob:")):
                        continue
                    url = URL(raw_url)
                    if not url.value:
                        continue
                    obs = analysis.add_observable_by_spec(F_URL, url.value)
                    if obs:
                        obs.display_type = "Phishkit Request URL"
            except Exception as e:
                logging.error(f"failed to extract URLs from requests.json for {observable}: {e}")

        return AnalysisExecutionResult.COMPLETED

    def execute_analysis(self, observable) -> AnalysisExecutionResult:
        # if the observable is a file, we need to check if the file type is enabled for scanning
        if observable.type == F_FILE:
            if not observable.has_directive(DIRECTIVE_RENDER):
                logging.debug(f"skipping file {observable} - render directive not found")
                return AnalysisExecutionResult.COMPLETED

            # by default we do not accept files for phishkit analysis
            file_accepted = False

            # first check the file extension
            assert isinstance(observable, FileObservable)
            file_extension = os.path.splitext(observable.file_name)[1].lower()
            if file_extension in self.config.valid_file_extensions:
                logging.debug(f"file {observable} extension {file_extension} enabled for phishkit analysis")
                file_accepted = True

            # then check the mime type
            from saq.modules.file_analysis import FileTypeAnalysis
            file_type_analysis = self.wait_for_analysis(observable, FileTypeAnalysis)

            if file_type_analysis is not None and file_type_analysis.mime_type in self.config.valid_mime_types:
                file_accepted = True
                logging.debug(f"file {observable} mime type {file_type_analysis.mime_type} enabled for phishkit analysis")

            if not file_accepted:
                logging.debug(f"file {observable} not accepted for phishkit analysis")
                return AnalysisExecutionResult.COMPLETED

        if observable.type == F_URL:
            # urls require crawl directives
            if not observable.has_directive(DIRECTIVE_CRAWL):
                logging.debug(f"skipping URL {observable} - crawl directive not found")
                return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(observable)
        assert isinstance(analysis, PhishkitAnalysis)

        # create a temporary directory to store the output files
        analysis.output_dir = create_temporary_directory()

        if observable.type == F_URL:
            logging.info(f"executing phishkit URL scan for {observable}")
            analysis.scan_type = SCAN_TYPE_URL
            
            try:
                analysis.job_id = scan_url(observable.value, analysis.output_dir, is_async=True, scanner_timeout=self.config.scanner_timeout, proxy=self._proxy_string, proxy_fallback_to_direct=self.config.proxy_fallback_to_direct, config_path=self.config.config_path)
                self.delay_analysis(observable, analysis, seconds=5, timeout_seconds=max(self.config.scanner_timeout, 60))
                
            except Exception as e:
                error_msg = f"failed to scan URL {observable.value}: {str(e)}"
                logging.error(error_msg)
                analysis.error = error_msg
                return AnalysisExecutionResult.COMPLETED

        elif observable.type == F_FILE:
            logging.info(f"executing phishkit file scan for {observable.value}")
            analysis.scan_type = SCAN_TYPE_FILE
            
            try:
                analysis.job_id = scan_file(observable.full_path, analysis.output_dir, is_async=True, scanner_timeout=self.config.scanner_timeout, proxy=self._proxy_string, proxy_fallback_to_direct=self.config.proxy_fallback_to_direct, config_path=self.config.config_path)
                return self.delay_analysis(observable, analysis, seconds=5, timeout_seconds=max(self.config.scanner_timeout, 60))
                
            except Exception as e:
                error_msg = f"Failed to scan file {observable.value}: {str(e)}"
                logging.error(error_msg)
                report_exception()
                analysis.error = error_msg
                return AnalysisExecutionResult.COMPLETED

        return AnalysisExecutionResult.COMPLETED
