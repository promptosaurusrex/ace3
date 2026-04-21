"""Unit tests for the JavaScript deobfuscation analyzer.

The production path dispatches through celery to a docker-in-docker
manager that spawns scanner containers. None of that is available in the
unit test environment, so we monkeypatch
``saq.modules.file_analysis.js.deobfuscate_file`` with a local shim that
runs the harness directly via ``node``. This keeps the tests fast and
faithful to the real harness output while skipping the container plumbing.
"""

import json
import os
import subprocess

import pytest

from saq.configuration.config import get_analysis_module_config
from saq.constants import (
    ANALYSIS_MODULE_JAVASCRIPT_DEOBFUSCATION,
    AnalysisExecutionResult,
    DIRECTIVE_CRAWL_EXTRACTED_URLS,
    DIRECTIVE_EXTRACT_URLS,
    DIRECTIVE_YARA_META_PREFIX,
    F_FILE,
    R_EXTRACTED_FROM,
)
from saq.modules.adapter import AnalysisModuleAdapter
from saq.modules.file_analysis.js import (
    DEOBFUSCATED_PREFIX,
    JavaScriptDeobfuscationAnalysis,
    JavaScriptDeobfuscationAnalyzer,
)
from tests.saq.helpers import create_root_analysis
from tests.saq.test_util import create_test_context

YARA_META_JS = f"{DIRECTIVE_YARA_META_PREFIX}type=script.javascript"

HARNESS_PATH = os.path.normpath(
    os.path.join(
        os.path.dirname(__file__),
        "..", "..", "..", "..",
        "js_deobfuscator", "harness.js",
    )
)


def _local_deobfuscate_file(file_path, output_dir, is_async=False, timeout=60, scanner_timeout=30):
    """Stand-in for saq.js_deobfuscator.deobfuscate_file that runs the
    harness directly via node."""
    os.makedirs(output_dir, exist_ok=True)
    out_js = os.path.join(output_dir, "deobfuscated.js")
    proc = subprocess.run(
        ["node", HARNESS_PATH, file_path, out_js],
        capture_output=True,
        text=True,
        timeout=scanner_timeout,
    )
    stdout, stderr = proc.stdout or "", proc.stderr or ""

    with open(os.path.join(output_dir, "std.out"), "w") as fp:
        fp.write(stdout)
    with open(os.path.join(output_dir, "std.err"), "w") as fp:
        fp.write(stderr)
    with open(os.path.join(output_dir, "exit.code"), "w") as fp:
        fp.write(str(proc.returncode))
    try:
        report = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        report = {"status": "parse_error", "raw_stdout": stdout}
    with open(os.path.join(output_dir, "report.json"), "w") as fp:
        json.dump(report, fp)

    return [
        os.path.join(output_dir, name)
        for name in ("deobfuscated.js", "std.out", "std.err", "exit.code", "report.json")
        if os.path.exists(os.path.join(output_dir, name))
    ]


@pytest.fixture
def patched_deobfuscate(monkeypatch):
    """Replace the celery client with the local node shim for every test."""
    monkeypatch.setattr(
        "saq.modules.file_analysis.js.deobfuscate_file",
        _local_deobfuscate_file,
    )


def _build_analyzer(root):
    """Build the analyzer wired to a root."""
    raw_analyzer = JavaScriptDeobfuscationAnalyzer(
        context=create_test_context(root=root),
        config=get_analysis_module_config(ANALYSIS_MODULE_JAVASCRIPT_DEOBFUSCATION),
    )
    return AnalysisModuleAdapter(raw_analyzer)


@pytest.mark.unit
def test_obfuscated_sample_is_deobfuscated(datadir, monkeypatch, patched_deobfuscate):
    """Feeding the canonical obfuscator.io sample should produce a
    deobfuscated sibling file marked for URL extraction and crawling."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_file_observable(datadir / "sample_obsfucated_javascript.js")
    observable.add_directive(YARA_META_JS)

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    assert isinstance(analysis, JavaScriptDeobfuscationAnalysis)
    assert analysis.exit_code == 0
    assert analysis.event_count > 0
    assert len(analysis.extracted_files) == 1
    assert os.path.basename(analysis.extracted_files[0]).startswith(DEOBFUSCATED_PREFIX)

    file_observables = [o for o in analysis.observables if o.type == F_FILE]
    assert len(file_observables) == 1
    emitted_obs = file_observables[0]
    assert emitted_obs.has_directive(DIRECTIVE_EXTRACT_URLS)
    assert emitted_obs.has_directive(DIRECTIVE_CRAWL_EXTRACTED_URLS)
    assert emitted_obs.has_relationship(R_EXTRACTED_FROM)
    assert observable.has_tag("js")

    with open(emitted_obs.full_path, "r", encoding="utf-8") as fp:
        body = fp.read()
    assert "in loop" in body


@pytest.mark.unit
def test_plain_js_emits_url_to_extracted_file(datadir, monkeypatch, patched_deobfuscate):
    """A trivial but real JS file should still produce a deobfuscated
    file containing the assigned URL in clear text."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_file_observable(datadir / "plain.js")
    observable.add_directive(YARA_META_JS)

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    assert analysis is not None
    assert analysis.exit_code == 0

    file_observables = [o for o in analysis.observables if o.type == F_FILE]
    assert len(file_observables) == 1
    emitted_obs = file_observables[0]
    assert emitted_obs.has_directive(DIRECTIVE_EXTRACT_URLS)
    assert emitted_obs.has_directive(DIRECTIVE_CRAWL_EXTRACTED_URLS)
    with open(emitted_obs.full_path, "r", encoding="utf-8") as fp:
        body = fp.read()
    assert "https://example.com/plain-target" in body


@pytest.mark.unit
def test_acrobat_pdf_bracket_notation_js(datadir, monkeypatch, patched_deobfuscate):
    """A PDF-extracted sample that uses only bracket-notation calls on
    Acrobat globals (app, util, SOAP, getField)."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_file_observable(datadir / "acrobat_pdf.js")
    observable.add_directive(YARA_META_JS)

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    assert analysis is not None
    assert analysis.exit_code == 0
    assert analysis.event_count > 0

    file_observables = [o for o in analysis.observables if o.type == F_FILE]
    assert len(file_observables) == 1
    emitted_obs = file_observables[0]
    with open(emitted_obs.full_path, "r", encoding="utf-8") as fp:
        body = fp.read()
    assert "getField" in body
    assert "SOAP" in body or "streamDecode" in body


@pytest.mark.unit
def test_window_property_is_resolved_in_url(datadir, monkeypatch, patched_deobfuscate):
    """Values written to `window.<prop>` must be resolved when read back and
    concatenated into a later redirect URL — otherwise the sandbox emits a
    bogus URL like `https://host/[window.prop]` from Proxy stringification."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_file_observable(datadir / "window_property_substitution.js")
    observable.add_directive(YARA_META_JS)

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    assert analysis is not None
    assert analysis.exit_code == 0

    file_observables = [o for o in analysis.observables if o.type == F_FILE]
    assert len(file_observables) == 1
    emitted_obs = file_observables[0]
    with open(emitted_obs.full_path, "r", encoding="utf-8") as fp:
        body = fp.read()
    assert "https://evil.com/?e=user@example.com" in body
    assert "[window.abcd]" not in body


@pytest.mark.unit
def test_harness_crash_still_emits_observable(tmpdir, monkeypatch):
    """When the sandbox harness crashes partway through, the analyzer should
    still emit the deobfuscated-<name> observable carrying analysis.error."""
    import json as _json

    def _crashing_shim(file_path, output_dir, is_async=False, timeout=60, scanner_timeout=30):
        os.makedirs(output_dir, exist_ok=True)
        out_js = os.path.join(output_dir, "deobfuscated.js")
        with open(out_js, "w") as fp:
            fp.write(
                "// ACE3 javascript deobfuscator -- reconstructed from sandbox trace\n"
                "// partial capture before crash\n"
                "// run error: TypeError: this[<obfuscated>] is not a function\n"
            )
        with open(os.path.join(output_dir, "std.out"), "w") as fp:
            fp.write("")
        with open(os.path.join(output_dir, "std.err"), "w") as fp:
            fp.write("")
        with open(os.path.join(output_dir, "exit.code"), "w") as fp:
            fp.write("0")
        with open(os.path.join(output_dir, "report.json"), "w") as fp:
            _json.dump({
                "status": "error_during_run",
                "event_count": 0,
                "secondary_script_count": 0,
                "error": "TypeError: this[<obfuscated>] is not a function at evalmachine.<anonymous>:1:639",
            }, fp)
        return [
            os.path.join(output_dir, name)
            for name in ("deobfuscated.js", "std.out", "std.err", "exit.code", "report.json")
        ]

    monkeypatch.setattr(
        "saq.modules.file_analysis.js.deobfuscate_file",
        _crashing_shim,
    )

    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    crash_src = tmpdir / "harness_crash_sample.js"
    crash_src.write('var x = 1; app.unknown_method();')
    observable = root.add_file_observable(str(crash_src))
    observable.add_directive(YARA_META_JS)

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    assert analysis is not None
    assert analysis.error and "not a function" in analysis.error
    file_observables = [o for o in analysis.observables if o.type == F_FILE]
    assert len(file_observables) == 1
    emitted_obs = file_observables[0]
    assert emitted_obs.has_directive(DIRECTIVE_EXTRACT_URLS)


@pytest.mark.unit
def test_deobfuscator_error_does_not_crash(datadir, monkeypatch):
    """If the celery client raises, the analyzer should record the error
    and return COMPLETED without a derived file observable."""
    def _exploding(*args, **kwargs):
        raise RuntimeError("simulated manager unavailable")
    monkeypatch.setattr("saq.modules.file_analysis.js.deobfuscate_file", _exploding)

    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_file_observable(datadir / "plain.js")
    observable.add_directive(YARA_META_JS)

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    assert analysis is not None
    assert analysis.error and "simulated manager unavailable" in analysis.error
    assert [o for o in analysis.observables if o.type == F_FILE] == []


@pytest.mark.unit
def test_js_extension_triggers_without_yara_tag(tmpdir, monkeypatch, patched_deobfuscate):
    """A .js file without the yara meta tag (e.g. manually uploaded) should
    still be deobfuscated, and the tag should be added to the source
    observable on success."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    manual_upload = tmpdir / "uploaded_sample.js"
    manual_upload.write('window.location.href = "https://example.com/manual";')
    observable = root.add_file_observable(str(manual_upload))
    # deliberately NOT adding the yara meta directive — .js extension is enough

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis)
    assert analysis is not None
    assert analysis.exit_code == 0
    # the source observable should now have the yara meta tag applied
    assert observable.has_directive(YARA_META_JS)


@pytest.mark.unit
def test_skipped_without_tag_or_js_extension(tmpdir, monkeypatch, patched_deobfuscate):
    """Files without the yara meta tag AND without a .js extension should be
    skipped entirely — no analysis created."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    txt_path = tmpdir / "notes.txt"
    txt_path.write("just some plain text")
    observable = root.add_file_observable(str(txt_path))

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    assert observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis) is None


@pytest.mark.unit
def test_empty_file_is_skipped(tmpdir, monkeypatch, patched_deobfuscate):
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    empty_path = tmpdir / "empty.js"
    empty_path.write("")
    observable = root.add_file_observable(str(empty_path))
    observable.add_directive(YARA_META_JS)

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    assert observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis) is None


@pytest.mark.unit
def test_own_output_is_not_reanalyzed(tmpdir, monkeypatch, patched_deobfuscate):
    """Files whose name already starts with the deobfuscated- prefix
    (i.e. our own output) must not recurse."""
    root = create_root_analysis(analysis_mode="test_single")
    root.initialize_storage()
    out_path = tmpdir / f"{DEOBFUSCATED_PREFIX}already.js"
    out_path.write("const x = 1;")
    observable = root.add_file_observable(str(out_path))
    observable.add_directive(YARA_META_JS)

    analyzer = _build_analyzer(root)
    result = analyzer.execute_analysis(observable)

    assert result == AnalysisExecutionResult.COMPLETED
    assert observable.get_and_load_analysis(JavaScriptDeobfuscationAnalysis) is None
