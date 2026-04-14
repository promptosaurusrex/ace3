import json
import logging
import os
import shutil
from typing import Type

from pydantic import Field

from saq.analysis.analysis import Analysis
from saq.constants import (
    AnalysisExecutionResult,
    DIRECTIVE_CRAWL_EXTRACTED_URLS,
    DIRECTIVE_EXTRACT_URLS,
    F_FILE,
    R_EXTRACTED_FROM,
)
from saq.js_deobfuscator import deobfuscate_file
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.modules.file_analysis.is_file_type import is_javascript_file
from saq.observables.file import FileObservable
from saq.util.filesystem import create_temporary_directory
from saq.util.strings import format_item_list_for_summary

DEOBFUSCATED_PREFIX = "deobfuscated-"


class JavaScriptDeobfuscationAnalysis(Analysis):

    KEY_EXTRACTED_FILES = "extracted_files"
    KEY_STDOUT = "stdout"
    KEY_STDERR = "stderr"
    KEY_EXIT_CODE = "exit_code"
    KEY_EVENT_COUNT = "event_count"
    KEY_SECONDARY_SCRIPT_COUNT = "secondary_script_count"
    KEY_ERROR = "error"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            JavaScriptDeobfuscationAnalysis.KEY_EXTRACTED_FILES: [],
            JavaScriptDeobfuscationAnalysis.KEY_STDOUT: None,
            JavaScriptDeobfuscationAnalysis.KEY_STDERR: None,
            JavaScriptDeobfuscationAnalysis.KEY_EXIT_CODE: None,
            JavaScriptDeobfuscationAnalysis.KEY_EVENT_COUNT: 0,
            JavaScriptDeobfuscationAnalysis.KEY_SECONDARY_SCRIPT_COUNT: 0,
            JavaScriptDeobfuscationAnalysis.KEY_ERROR: None,
        }

    @property
    def extracted_files(self):
        if self.details is None:
            return []
        return self.details.get(JavaScriptDeobfuscationAnalysis.KEY_EXTRACTED_FILES, [])

    @property
    def stdout(self):
        return None if self.details is None else self.details.get(JavaScriptDeobfuscationAnalysis.KEY_STDOUT)

    @stdout.setter
    def stdout(self, value):
        self.details[JavaScriptDeobfuscationAnalysis.KEY_STDOUT] = value

    @property
    def stderr(self):
        return None if self.details is None else self.details.get(JavaScriptDeobfuscationAnalysis.KEY_STDERR)

    @stderr.setter
    def stderr(self, value):
        self.details[JavaScriptDeobfuscationAnalysis.KEY_STDERR] = value

    @property
    def exit_code(self):
        return None if self.details is None else self.details.get(JavaScriptDeobfuscationAnalysis.KEY_EXIT_CODE)

    @exit_code.setter
    def exit_code(self, value):
        self.details[JavaScriptDeobfuscationAnalysis.KEY_EXIT_CODE] = value

    @property
    def event_count(self):
        return 0 if self.details is None else self.details.get(JavaScriptDeobfuscationAnalysis.KEY_EVENT_COUNT, 0)

    @event_count.setter
    def event_count(self, value):
        self.details[JavaScriptDeobfuscationAnalysis.KEY_EVENT_COUNT] = value

    @property
    def secondary_script_count(self):
        return 0 if self.details is None else self.details.get(JavaScriptDeobfuscationAnalysis.KEY_SECONDARY_SCRIPT_COUNT, 0)

    @secondary_script_count.setter
    def secondary_script_count(self, value):
        self.details[JavaScriptDeobfuscationAnalysis.KEY_SECONDARY_SCRIPT_COUNT] = value

    @property
    def error(self):
        return None if self.details is None else self.details.get(JavaScriptDeobfuscationAnalysis.KEY_ERROR)

    @error.setter
    def error(self, value):
        self.details[JavaScriptDeobfuscationAnalysis.KEY_ERROR] = value

    def generate_summary(self) -> str:
        if not self.details:
            return None
        if self.error:
            return f"JavaScript Deobfuscation: failed: {self.error}"
        if self.exit_code != 0 or not self.extracted_files:
            return None
        return (
            "JavaScript Deobfuscation: extracted "
            + format_item_list_for_summary(self.extracted_files)
            + f" ({self.event_count} events, {self.secondary_script_count} secondary scripts)"
        )


class JavaScriptDeobfuscationAnalyzerConfig(AnalysisModuleConfig):
    scanner_timeout: int = Field(
        default=30,
        description="Wall-clock limit (seconds) for a single scanner container invocation.",
    )
    celery_timeout: int = Field(
        default=60,
        description="Wall-clock limit (seconds) to wait on the celery manager for a result.",
    )


class JavaScriptDeobfuscationAnalyzer(AnalysisModule):
    """Runs obfuscated JavaScript in a throwaway scanner container whose
    sandbox harness traces every write to a browser global, and emits a
    reconstructed file observable marked for URL extraction and crawling.

    The actual execution happens in the ``js-deobfuscator`` service, which
    spawns a sibling ``js-deobfuscator`` image per scan via
    ``docker run --rm --network none``. This module is just a client.
    """

    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return JavaScriptDeobfuscationAnalyzerConfig

    @property
    def generated_analysis_type(self):
        return JavaScriptDeobfuscationAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        from saq.modules.file_analysis.file_type import FileTypeAnalysis

        local_file_path = _file.full_path

        # don't re-analyze our own output
        if _file.file_name.startswith(DEOBFUSCATED_PREFIX):
            return AnalysisExecutionResult.COMPLETED

        if not os.path.exists(local_file_path):
            logging.debug(f"local file {local_file_path} does not exist")
            return AnalysisExecutionResult.COMPLETED

        if os.path.getsize(local_file_path) == 0:
            logging.debug(f"local file {local_file_path} is empty")
            return AnalysisExecutionResult.COMPLETED

        if _file.file_name.endswith(".json"):
            return AnalysisExecutionResult.COMPLETED

        file_type_analysis = self.wait_for_analysis(_file, FileTypeAnalysis)
        if file_type_analysis is not None and file_type_analysis.mime_type == "application/json":
            return AnalysisExecutionResult.COMPLETED

        if _file.file_name == "exiftool.out":
            return AnalysisExecutionResult.COMPLETED

        if not is_javascript_file(local_file_path):
            logging.debug(f"local file {local_file_path} is not a javascript file")
            return AnalysisExecutionResult.COMPLETED

        _file.add_tag("js")

        analysis = self.create_analysis(_file)
        assert isinstance(analysis, JavaScriptDeobfuscationAnalysis)

        # temp directory on the ACE side where result files will be copied
        # back from the shared ace-js-deobfuscator volume
        scratch_dir = create_temporary_directory()

        try:
            result_files = deobfuscate_file(
                local_file_path,
                scratch_dir,
                is_async=False,
                timeout=self.config.celery_timeout,
                scanner_timeout=self.config.scanner_timeout,
            )
        except Exception as e:
            analysis.error = f"js deobfuscator call failed: {e}"
            logging.warning(f"js deobfuscator failed for {local_file_path}: {e}")
            return AnalysisExecutionResult.COMPLETED

        # parse std.out / std.err / exit.code / report.json and pick out
        # the deobfuscated.js file
        deobfuscated_src = None
        for result_file in result_files:
            basename = os.path.basename(result_file)
            if basename == "std.out":
                with open(result_file, "r", errors="replace") as fp:
                    analysis.stdout = fp.read()
            elif basename == "std.err":
                with open(result_file, "r", errors="replace") as fp:
                    analysis.stderr = fp.read()
            elif basename == "exit.code":
                try:
                    with open(result_file, "r") as fp:
                        analysis.exit_code = int(fp.read().strip() or "0")
                except ValueError:
                    analysis.exit_code = None
            elif basename == "report.json":
                try:
                    with open(result_file, "r") as fp:
                        report = json.load(fp)
                    analysis.event_count = int(report.get("event_count", 0) or 0)
                    analysis.secondary_script_count = int(report.get("secondary_script_count", 0) or 0)
                    if report.get("error"):
                        analysis.error = report["error"]
                except (OSError, json.JSONDecodeError) as e:
                    logging.debug(f"failed to read report.json from deobfuscator: {e}")
            elif basename == "deobfuscated.js":
                deobfuscated_src = result_file

        if analysis.exit_code != 0:
            logging.warning(
                f"js deobfuscator exit {analysis.exit_code} for {local_file_path}; stderr={analysis.stderr!r}"
            )
            return AnalysisExecutionResult.COMPLETED

        if not deobfuscated_src or not os.path.exists(deobfuscated_src):
            logging.debug(f"js deobfuscator produced no output file for {local_file_path}")
            return AnalysisExecutionResult.COMPLETED

        if os.path.getsize(deobfuscated_src) == 0 or analysis.event_count == 0:
            logging.debug(f"js deobfuscator produced no events for {local_file_path}")
            return AnalysisExecutionResult.COMPLETED

        # rename into place next to the source file so the ACE file manager
        # picks up the new observable with a meaningful name
        target_dir = os.path.dirname(local_file_path)
        target_path = os.path.join(target_dir, f"{DEOBFUSCATED_PREFIX}{_file.file_name}")
        if os.path.exists(target_path):
            logging.warning(f"target file {target_path} already exists")
            return AnalysisExecutionResult.COMPLETED

        shutil.move(deobfuscated_src, target_path)

        o_file = analysis.add_file_observable(target_path, volatile=True)
        if o_file:
            o_file.add_relationship(R_EXTRACTED_FROM, _file)
            o_file.exclude_analysis(self)
            o_file.add_yara_meta("type", "script.javascript")
            o_file.add_directive(DIRECTIVE_EXTRACT_URLS)
            o_file.add_directive(DIRECTIVE_CRAWL_EXTRACTED_URLS)
            analysis.extracted_files.append(o_file.file_path)

        return AnalysisExecutionResult.COMPLETED
