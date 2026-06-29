import pytest

from saq.modules.email.conversation import (
    Participant,
    ThreadContext,
    derive_thread_id,
    get_established_domains,
    get_thread_message_count,
    normalize_subject,
    parse_message_id_list,
    record_thread,
)


def _context(thread_id, method, message_id, normalized_subject, participants, **kwargs):
    senders = [p for p in participants if p.role in ("from", "reply_to", "return_path")]
    from_participant = next((p for p in participants if p.role == "from"), None)
    return ThreadContext(
        thread_id=thread_id,
        thread_method=method,
        message_id=message_id,
        in_reply_to=kwargs.get("in_reply_to"),
        references=kwargs.get("references"),
        normalized_subject=normalized_subject,
        message_date=None,
        from_address=from_participant.address if from_participant else None,
        from_domain=from_participant.domain if from_participant else None,
        direction=0,
        participants=participants,
        senders=senders,
    )


@pytest.mark.unit
@pytest.mark.parametrize("subject,expected", [
    ("Re: Hello", "hello"),
    ("RE: FW: Re: Hello World", "hello world"),
    ("Fwd: project update", "project update"),
    ("Re[2]: counter", "counter"),
    ("   spaced    out   subject ", "spaced out subject"),
    ("no prefix here", "no prefix here"),
    ("", ""),
    (None, ""),
])
def test_normalize_subject(subject, expected):
    assert normalize_subject(subject) == expected


@pytest.mark.unit
def test_parse_message_id_list():
    assert parse_message_id_list("<a@x> <b@x> <c@x>") == ["<a@x>", "<b@x>", "<c@x>"]
    # commas / whitespace between tokens are tolerated
    assert parse_message_id_list("<a@x>,\n <b@x>") == ["<a@x>", "<b@x>"]
    assert parse_message_id_list("") == []
    assert parse_message_id_list(None) == []


@pytest.mark.unit
def test_derive_thread_id_uses_references_root():
    # References is oldest-first; the first token is the JWZ root
    thread_id, method = derive_thread_id("<c@x>", "<b@x>", "<a@x> <b@x>")
    assert thread_id == "<a@x>"
    assert method == "references"


@pytest.mark.unit
def test_derive_thread_id_falls_back_to_in_reply_to():
    thread_id, method = derive_thread_id("<c@x>", "<b@x>", None)
    assert thread_id == "<b@x>"
    assert method == "in_reply_to"


@pytest.mark.unit
def test_derive_thread_id_self_when_no_linkage():
    thread_id, method = derive_thread_id("<c@x>", None, None)
    assert thread_id == "<c@x>"
    assert method == "self"


@pytest.mark.unit
def test_derive_thread_id_normalizes_bare_message_id():
    # a message-id missing angle brackets is normalized when it becomes the thread root
    thread_id, method = derive_thread_id("c@x", None, None)
    assert thread_id == "<c@x>"
    assert method == "self"


@pytest.mark.unit
def test_derive_thread_id_none_when_nothing_available():
    thread_id, method = derive_thread_id(None, None, None)
    assert thread_id == ""
    assert method == "none"


@pytest.mark.unit
def test_derive_thread_id_replies_converge_on_same_root():
    # two different replies in the same thread must map to the same thread_id regardless of arrival order
    a, _ = derive_thread_id("<b@x>", "<a@x>", "<a@x>")
    b, _ = derive_thread_id("<c@x>", "<b@x>", "<a@x> <b@x>")
    assert a == b == "<a@x>"


@pytest.mark.integration
def test_thread_store_round_trip():
    root = _context(
        "<root@example.com>", "self", "<root@example.com>", "invoice question",
        [Participant("ceo@example.com", "example.com", "from"),
         Participant("cfo@company.com", "company.com", "to")])
    record_thread(root)
    assert get_thread_message_count("<root@example.com>") == 1

    # a reply (References the root) sees the root's participant domains as established
    reply = _context(
        "<root@example.com>", "references", "<reply@examp1e.com>", "invoice question",
        [Participant("ceo@examp1e.com", "examp1e.com", "from")],
        in_reply_to="<root@example.com>", references="<root@example.com>")
    established = {d.domain for d in get_established_domains(reply)}
    assert "example.com" in established
    assert "company.com" in established
    # the reply's own look-a-like domain is not yet recorded (recording happens after scoring)
    assert "examp1e.com" not in established


@pytest.mark.integration
def test_subject_fallback_requires_shared_domain():
    root = _context(
        "<root2@example.com>", "self", "<root2@example.com>", "wire transfer",
        [Participant("ceo@example.com", "example.com", "from"),
         Participant("cfo@company.com", "company.com", "to")])
    record_thread(root)

    # no threading headers (method 'self'), same subject, shares company.com -> root domains established
    shared = _context(
        "<isolated@evil.com>", "self", "<isolated@evil.com>", "wire transfer",
        [Participant("cfo@company.com", "company.com", "from")])
    assert "example.com" in {d.domain for d in get_established_domains(shared)}

    # same subject but no shared participant domain -> not merged, nothing established
    unrelated = _context(
        "<other@unrelated.org>", "self", "<other@unrelated.org>", "wire transfer",
        [Participant("bob@unrelated.org", "unrelated.org", "from")])
    assert get_established_domains(unrelated) == []
