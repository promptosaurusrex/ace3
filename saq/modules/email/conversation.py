# vim: sw=4:ts=4:et:cc=120
#
# email conversation (thread) reconstruction and the brocess-backed thread store
#
# threads are reconstructed JWZ-style: primarily from the RFC threading headers (Message-ID / In-Reply-To /
# References), falling back to normalized-subject + participant-domain overlap when those headers are missing.
# per-message metadata and per-thread participant domains are persisted in the brocess database so that a
# later message in the same thread can be compared against the domains already established in that thread.

import email.utils
import logging
import re

from collections import namedtuple
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from saq.database import execute_with_retry, get_db_connection
from saq.domain_similarity import registrable_domain
from saq.email import get_email_domain, is_local_email_domain, normalize_message_id

# matches an addr-spec wrapped in angle brackets (a single message-id token)
RE_MESSAGE_ID_TOKEN = re.compile(r"<[^<>]+>")

# leading reply/forward prefixes to strip when normalizing a subject (re:, fwd:, fw:, aw:, sv:, tr:),
# optionally followed by a bracketed counter such as "[2]"
RE_SUBJECT_PREFIX = re.compile(r"^\s*(re|fwd?|aw|sv|tr)\s*(\[\d+\])?\s*:\s*", re.IGNORECASE)
RE_WHITESPACE = re.compile(r"\s+")

# roles whose domains we score a new sender against; and the full set we record as thread participants
SENDER_ROLES = ("from", "reply_to", "return_path")

# direction values stored in email_thread_message.direction
DIRECTION_INBOUND = 0
DIRECTION_OUTBOUND = 1

# a participant domain observed in a thread (one role of one address)
Participant = namedtuple("Participant", ["address", "domain", "role"])

# a row returned from the thread domain store
ThreadDomain = namedtuple("ThreadDomain", ["domain", "address", "role", "firstseendate"])


def normalize_subject(subject: Optional[str]) -> str:
    """Strip reply/forward prefixes and collapse whitespace so subjects can be matched across a thread."""
    if not subject:
        return ""

    result = subject
    # repeatedly strip prefixes - real-world subjects stack them ("Re: Fwd: Re: ...")
    for _ in range(100):
        stripped = RE_SUBJECT_PREFIX.sub("", result, count=1)
        if stripped == result:
            break
        result = stripped
    else:
        logging.error("normalize_subject: subject prefix stripping exhausted maximum iterations for subject %s", subject)
   
    return RE_WHITESPACE.sub(" ", result).strip().lower()


def parse_message_id_list(value: Optional[str]) -> list:
    """Extract all <...> message-id tokens from a header value (e.g. a References chain), in order."""
    if not value:
        return []

    return RE_MESSAGE_ID_TOKEN.findall(value)


def derive_thread_id(message_id: Optional[str], in_reply_to: Optional[str],
                     references: Optional[str]) -> tuple:
    """Derive a stable thread id from the threading headers, returning (thread_id, method).

    References is oldest-first, so References[0] is the JWZ root and groups every reply consistently
    regardless of arrival order. Falls back to In-Reply-To, then to the message's own id (a new thread).
    """
    references_list = parse_message_id_list(references)
    if references_list:
        return references_list[0], "references"

    in_reply_to_token = (parse_message_id_list(in_reply_to) or [None])[0]
    if in_reply_to_token:
        return in_reply_to_token, "in_reply_to"

    if message_id:
        return normalize_message_id(message_id), "self"

    return "", "none"


def _header_value(email_analysis, name: str) -> Optional[str]:
    """Return the first matching header value (case-insensitive) from an EmailAnalysis, or None.

    headers are read directly off the parsed header list - this is the workaround for In-Reply-To not
    being individually keyed and References being stored under a misspelled log_entry key.
    """
    for header in email_analysis.headers or []:
        if header and header[0] and header[0].lower() == name.lower():
            return header[1]

    return None


@dataclass
class ThreadContext:
    """Everything needed to record a message into the thread store and to score its sender domains."""

    thread_id: str
    thread_method: str
    message_id: Optional[str]
    in_reply_to: Optional[str]
    references: Optional[str]
    normalized_subject: str
    message_date: Optional[datetime]
    from_address: Optional[str]
    from_domain: Optional[str]
    direction: Optional[int]
    # all participant domains (from/reply_to/return_path/to/cc) recorded for the thread
    participants: list = field(default_factory=list)
    # the subset of participants we treat as suspect senders to score against established domains
    senders: list = field(default_factory=list)

    @property
    def participant_domains(self) -> set:
        return {p.domain for p in self.participants if p.domain}


def _participant(address: Optional[str], role: str) -> Optional[Participant]:
    if not address:
        return None

    domain = registrable_domain(get_email_domain(address) or "")
    if not domain:
        return None

    return Participant(address=address, domain=domain, role=role)


def derive_thread_context(email_analysis) -> ThreadContext:
    """Build a ThreadContext from a parsed EmailAnalysis (used identically by the recorder and the scorer)."""
    log_entry = (email_analysis.email or {}).get("log_entry") or {}

    message_id = log_entry.get("message_id") or email_analysis.message_id
    in_reply_to = log_entry.get("in_reply_to")
    # NOTE (pulling from headers due to the typo in the log_entry key name)
    references = _header_value(email_analysis, "references")

    thread_id, thread_method = derive_thread_id(message_id, in_reply_to, references)

    normalized = normalize_subject(email_analysis.decoded_subject or email_analysis.subject)

    # message date from the Date header (falls back to None - ordering then uses insert_date)
    message_date = None
    date_header = _header_value(email_analysis, "date")
    if date_header:
        try:
            message_date = email.utils.parsedate_to_datetime(date_header)
        except (TypeError, ValueError):
            message_date = None

    # collect participants: senders we will score, plus all recipients for the reference set
    participants = []
    senders = []

    from_participant = _participant(email_analysis.mail_from_address, "from")
    reply_participant = _participant(email_analysis.reply_to_address, "reply_to")
    return_participant = _participant(
        email.utils.parseaddr(email_analysis.return_path)[1] if email_analysis.return_path else None,
        "return_path")

    for participant in (from_participant, reply_participant, return_participant):
        if participant:
            senders.append(participant)
            participants.append(participant)

    for address in (email_analysis.mail_to_addresses or []):
        participant = _participant(address, "to")
        if participant:
            participants.append(participant)

    for address in (email_analysis.cc or []):
        # cc is a list of raw header values - extract the address portion
        cc_address = email.utils.parseaddr(address)[1] if isinstance(address, str) else None
        participant = _participant(cc_address, "cc")
        if participant:
            participants.append(participant)

    from_address = from_participant.address if from_participant else None
    from_domain = from_participant.domain if from_participant else None

    direction = None
    if from_address is not None:
        direction = DIRECTION_OUTBOUND if is_local_email_domain(from_address) else DIRECTION_INBOUND

    return ThreadContext(
        thread_id=thread_id,
        thread_method=thread_method,
        message_id=normalize_message_id(message_id) if message_id else None,
        in_reply_to=in_reply_to,
        references=references,
        normalized_subject=normalized,
        message_date=message_date,
        from_address=from_address,
        from_domain=from_domain,
        direction=direction,
        participants=participants,
        senders=senders,
    )


def record_thread(context: ThreadContext) -> None:
    """Persist a message and its participant domains into the brocess thread store.

    must be called AFTER the look-a-like scoring for the same message, so that the message's own domains
    are not yet present when its sender is compared against the thread's established domains.
    """
    if not context.thread_id or not context.message_id:
        logging.debug("skipping thread store - missing thread_id or message_id")
        return

    with get_db_connection(name="brocess") as db:
        cursor = db.cursor()

        # record the message. on a duplicate (the same message reprocessed) leave the row unchanged.
        execute_with_retry(db, cursor, """
INSERT INTO email_thread_message (
    thread_id, thread_id_hash, message_id, message_id_hash, in_reply_to,
    normalized_subject, normalized_subject_hash, from_address, from_domain, direction, message_date )
VALUES (
    %s, UNHEX(SHA2(%s, 256)), %s, UNHEX(SHA2(%s, 256)), %s,
    %s, UNHEX(SHA2(%s, 256)), %s, %s, %s, %s )
ON DUPLICATE KEY UPDATE id = id""", (
            context.thread_id, context.thread_id,
            context.message_id, context.message_id,
            context.in_reply_to,
            context.normalized_subject or None, context.normalized_subject or None,
            context.from_address, context.from_domain,
            context.direction, context.message_date))

        # record each participant domain, incrementing numseen on repeats
        for participant in context.participants:
            execute_with_retry(db, cursor, """
INSERT INTO email_thread_domain (
    thread_id, thread_id_hash, domain, address, role, entry_hash, numseen, firstseendate )
VALUES (
    %s, UNHEX(SHA2(%s, 256)), %s, %s, %s, UNHEX(SHA2(CONCAT_WS(0x1f, %s, %s, %s), 256)), 1, NOW() )
ON DUPLICATE KEY UPDATE numseen = numseen + 1""", (
                context.thread_id, context.thread_id,
                participant.domain, participant.address, participant.role,
                participant.domain, participant.address, participant.role))

        db.commit()


def get_established_thread_domains(thread_id: str) -> list:
    """Return the participant domains already recorded for a thread (header-threaded path)."""
    if not thread_id:
        return []

    with get_db_connection(name="brocess") as db:
        cursor = db.cursor()
        cursor.execute("""
SELECT domain, address, role, firstseendate FROM email_thread_domain
WHERE thread_id_hash = UNHEX(SHA2(%s, 256))""", (thread_id,))
        return [ThreadDomain(*row) for row in cursor]


def get_subject_fallback_domains(normalized_subject: str, current_domains: set) -> list:
    """Return participant domains from prior same-subject threads that share a domain with this message.

    this is the fallback when threading headers are absent. requiring a shared participant domain prevents
    unrelated messages that merely share a subject line from being merged into one conversation.
    """
    if not normalized_subject:
        return []

    with get_db_connection(name="brocess") as db:
        cursor = db.cursor()
        cursor.execute("""
SELECT HEX(d.thread_id_hash), d.domain, d.address, d.role, d.firstseendate
FROM email_thread_domain d
WHERE d.thread_id_hash IN (
    SELECT m.thread_id_hash FROM email_thread_message m
    WHERE m.normalized_subject_hash = UNHEX(SHA2(%s, 256)) )""", (normalized_subject,))
        rows = cursor.fetchall()

    # group candidate domains by thread, then keep only threads that overlap the current participants
    by_thread = {}
    for thread_hex, domain, address, role, firstseendate in rows:
        by_thread.setdefault(thread_hex, []).append(ThreadDomain(domain, address, role, firstseendate))

    result = []
    for domains in by_thread.values():
        if current_domains.intersection({d.domain for d in domains}):
            result.extend(domains)

    return result


def get_established_domains(context: ThreadContext) -> list:
    """Return the established domains to score this message's senders against, scoped to its conversation.

    uses the header-threaded set when the message links to a thread; otherwise falls back to same-subject
    threads that share a participant domain. never compares across unrelated conversations.
    """
    if context.thread_method in ("references", "in_reply_to"):
        return get_established_thread_domains(context.thread_id)

    return get_subject_fallback_domains(context.normalized_subject, context.participant_domains)


def get_thread_messages(thread_id: str) -> list:
    """Return the messages recorded for a thread, ordered chronologically (for the thread view)."""
    if not thread_id:
        return []

    with get_db_connection(name="brocess") as db:
        cursor = db.cursor()
        cursor.execute("""
SELECT message_id, in_reply_to, normalized_subject, from_address, from_domain, direction,
       message_date, insert_date
FROM email_thread_message
WHERE thread_id_hash = UNHEX(SHA2(%s, 256))
ORDER BY message_date IS NULL, message_date, insert_date""", (thread_id,))
        return cursor.fetchall()


def get_thread_message_count(thread_id: str) -> int:
    """Return how many messages have been recorded for a thread."""
    if not thread_id:
        return 0

    with get_db_connection(name="brocess") as db:
        cursor = db.cursor()
        cursor.execute("""
SELECT COUNT(*) FROM email_thread_message WHERE thread_id_hash = UNHEX(SHA2(%s, 256))""", (thread_id,))
        for row in cursor:
            return int(row[0]) if row[0] is not None else 0

        return 0
