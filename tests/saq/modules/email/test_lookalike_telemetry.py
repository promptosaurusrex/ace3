import uuid

import pytest

from fluent import sender as fluent_sender

from saq.analysis.root import RootAnalysis
from saq.constants import DIRECTIVE_ORIGINAL_EMAIL
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.util.uuid import storage_dir_from_uuid

# cyrillic small letter a (U+0430) - visually identical to latin 'a'
CYRILLIC_A = "а"
LOOKALIKE_DOMAIN = "ex" + CYRILLIC_A + "mple.com"  # look-a-like of example.com

LOOKALIKE_TAG = "phishfinder-lookalike"


def _email(message_id, mail_from, mail_to, subject, in_reply_to=None, references=None):
    headers = [
        "From: " + mail_from,
        "To: " + mail_to,
        "Subject: " + subject,
        "Message-ID: " + message_id,
    ]
    if references:
        headers.append("References: " + references)
    if in_reply_to:
        headers.append("In-Reply-To: " + in_reply_to)
    headers += [
        "Date: Fri, 23 Feb 2018 18:22:20 +0000",
        "MIME-Version: 1.0",
        "Content-Type: text/plain",
    ]
    return ("\n".join(headers) + "\n\nbody text\n").encode("utf-8")


def _run_email(raw_email, tmpdir, name, captured):
    """Run a single email through the engine and return the lookalike telemetry records emitted."""
    captured.clear()

    email_path = str(tmpdir / (name + ".email.rfc822"))
    with open(email_path, "wb") as fp:
        fp.write(raw_email)

    root_uuid = str(uuid.uuid4())
    root = RootAnalysis(
        uuid=root_uuid,
        tool="tool",
        tool_instance="tool_instance",
        alert_type="mailbox",
        desc="lookalike test",
        storage_dir=storage_dir_from_uuid(root_uuid),
        analysis_mode="test_groups")
    root.initialize_storage()
    file_observable = root.add_file_observable(email_path)
    file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('file_type', 'test_groups')
    engine.configuration_manager.enable_module('email_analyzer', 'test_groups')
    engine.configuration_manager.enable_module('email_logger', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # return only the records emitted to the dedicated lookalike source
    return [data for tag, data in captured if tag == LOOKALIKE_TAG]


@pytest.mark.integration
def test_lookalike_telemetry_scoped_to_conversation(tmpdir, monkeypatch):
    captured = []

    def fake_emit(self, label, data):
        captured.append((self.tag, data))
        return True

    monkeypatch.setattr(fluent_sender.FluentSender, "emit", fake_emit)

    # email A: legitimate, starts a thread between example.com and company.com
    records = _run_email(
        _email("<a@example.com>", "John Davison <ceo@example.com>", "cfo@company.com", "invoice question"),
        tmpdir, "a", captured)
    assert len(records) == 1
    record_a = records[0]
    assert record_a["thread_id"] == "<a@example.com>"
    # no prior domains in the thread yet -> nothing to compare against
    assert record_a["comparisons"] == []
    assert record_a["any_similar"] is False

    # email B: a reply from a look-a-like of example.com, threaded to A via References/In-Reply-To
    records = _run_email(
        _email("<b@evil.test>", "John Davison <ceo@" + LOOKALIKE_DOMAIN + ">", "cfo@company.com",
               "Re: invoice question", in_reply_to="<a@example.com>", references="<a@example.com>"),
        tmpdir, "b", captured)
    assert len(records) == 1
    record_b = records[0]
    # B is grouped into A's thread
    assert record_b["thread_id"] == "<a@example.com>"
    # the look-a-like sender domain is compared against example.com established by A
    example_comparisons = [c for c in record_b["comparisons"] if c["reference_domain"] == "example.com"]
    assert len(example_comparisons) == 1
    comparison = example_comparisons[0]
    assert comparison["is_identical"] is False
    assert comparison["skeleton_equal"] is True
    assert comparison["is_similar"] is True
    assert record_b["any_similar"] is True
    assert record_b["any_mixed_script"] is True

    # email C: same look-a-like sender, but an UNRELATED email (no threading headers, different subject)
    records = _run_email(
        _email("<c@evil.test>", "John Davison <ceo@" + LOOKALIKE_DOMAIN + ">", "someone@company.com",
               "lunch plans"),
        tmpdir, "c", captured)
    assert len(records) == 1
    record_c = records[0]
    # different conversation -> example.com is NOT in its reference set, so no comparison against it
    assert record_c["thread_id"] == "<c@evil.test>"
    assert all(c["reference_domain"] != "example.com" for c in record_c["comparisons"])
    assert record_c["any_similar"] is False
