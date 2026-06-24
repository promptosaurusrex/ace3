"""Analysis module that flags FQDN observables which look like another FQDN in the same alert.

Runs on every FQDN observable. For each one, the analyzer walks the alert's
other FQDN observables, reduces both to their registrable domain (eTLD+1) via
``tldextract``, and computes the Levenshtein distance between the two
registrable forms. A pair is a "lookalike" when the distance is within
``DISTANCE_THRESHOLD`` (but not zero — identical registrables aren't lookalikes)
AND the shorter registrable's label (the part before the public suffix) is at
least ``MIN_LABEL_LENGTH`` characters, which kills `a.io` vs `b.io`-style noise.

Adding a *detection point* is intentionally not done here — promoting the
observable to alerting is the job of a downstream observable modifier rule
that matches on the tag this analyzer adds. Same split as
``saq.modules.nrd``.

Author: jpetrucci
"""

import logging
from typing import Optional

import idna
import tldextract

from saq.analysis import Analysis
from saq.constants import F_FQDN, AnalysisExecutionResult
from saq.modules import AnalysisModule


KEY_MATCHES = "matches"

TAG_LOOKALIKE = "suspect:fqdn_lookalike"

# Edit-distance window for "extremely similar but not identical". 1 catches
# single-character typos (paypal/paypa1), 2 catches the common transposition +
# vowel-swap cases (microsoft/microsfot, google/googel). Beyond 2 the false-
# positive rate climbs sharply.
DISTANCE_THRESHOLD = 2

# Skip pairs whose shorter registrable label is below this length. The label is
# the part before the public suffix — e.g. "paypal" in "paypal.com". Short
# labels generate too many spurious near-matches (`a.io` vs `b.io`).
MIN_LABEL_LENGTH = 5


def _levenshtein(a: str, b: str) -> int:
    """Plain iterative Levenshtein. Pure-Python, no deps.

    Two-row DP; O(len(a) * len(b)) time, O(min(len(a), len(b))) space. Inputs
    here are registrable domains capped at a few dozen characters, so per-pair
    cost is microseconds — adding rapidfuzz just to shave that wasn't worth a
    new dep.
    """
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)

    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            current[j] = min(
                current[j - 1] + 1,        # insertion
                previous[j] + 1,           # deletion
                previous[j - 1] + cost,    # substitution
            )
        previous = current
    return previous[-1]


def _registrable(value: str) -> Optional[tuple[str, str]]:
    """Return ``(registrable_domain, label)`` for ``value``, or None.

    ``label`` is the eTLD+1's first component — e.g. ``("paypal.com", "paypal")``.
    Returns None when tldextract can't identify a public suffix (bare hostnames,
    IPs, garbage); such values can't be meaningfully compared.

    Inputs are normalized: stripped, lower-cased, trailing-dot removed, and
    IDN-encoded to punycode so a unicode lookalike (e.g. ``раypal.com`` with
    Cyrillic ``а``) compares against ASCII forms in the same alphabet.
    """
    if not isinstance(value, str):
        return None
    domain = value.strip().lower().rstrip(".")
    if not domain:
        return None
    try:
        domain = idna.encode(domain).decode("ascii")
    except (idna.IDNAError, UnicodeError):
        return None

    extracted = tldextract.extract(domain)
    registrable = extracted.top_domain_under_public_suffix
    if not registrable or not extracted.domain:
        return None
    return registrable, extracted.domain


class FQDNLookalikeAnalysis(Analysis):
    """Records the lookalike pair(s) found for an FQDN observable."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {KEY_MATCHES: []}

    @property
    def matches(self) -> list[dict]:
        return self.details.get(KEY_MATCHES) or []

    def add_match(self, other_value: str, registrable_self: str, registrable_other: str, distance: int) -> None:
        self.details.setdefault(KEY_MATCHES, []).append({
            "other": other_value,
            "registrable_self": registrable_self,
            "registrable_other": registrable_other,
            "distance": distance,
        })

    def generate_summary(self):
        if not self.matches:
            return None
        first = self.matches[0]
        extra = ""
        if len(self.matches) > 1:
            extra = f" (+{len(self.matches) - 1} more)"
        return f"Lookalike FQDN: similar to {first['other']} (distance {first['distance']}){extra}"


class FQDNLookalikeAnalyzer(AnalysisModule):
    """Tag FQDN observables that have a lookalike sibling FQDN in the same alert."""

    @property
    def generated_analysis_type(self):
        return FQDNLookalikeAnalysis

    @property
    def valid_observable_types(self):
        return F_FQDN

    def execute_analysis(self, observable) -> AnalysisExecutionResult:
        self_parts = _registrable(observable.value)
        if self_parts is None:
            return AnalysisExecutionResult.COMPLETED
        self_registrable, self_label = self_parts

        try:
            others = self.get_root().get_observables_by_type(F_FQDN)
        except RuntimeError:
            # No root context wired (shouldn't happen in production; defensive
            # for any caller that constructs the module without a context).
            logging.debug("FQDNLookalikeAnalyzer: no root available")
            return AnalysisExecutionResult.COMPLETED

        analysis: Optional[FQDNLookalikeAnalysis] = None

        for other in others:
            if other is observable:
                continue
            other_parts = _registrable(other.value)
            if other_parts is None:
                continue
            other_registrable, other_label = other_parts

            if other_registrable == self_registrable:
                # Same site (e.g. mail.example.com vs www.example.com) — not a lookalike.
                continue
            if min(len(self_label), len(other_label)) < MIN_LABEL_LENGTH:
                continue

            distance = _levenshtein(self_registrable, other_registrable)
            if 1 <= distance <= DISTANCE_THRESHOLD:
                if analysis is None:
                    analysis = self.create_analysis(observable)
                    observable.add_tag(TAG_LOOKALIKE)
                analysis.add_match(
                    other_value=other.value,
                    registrable_self=self_registrable,
                    registrable_other=other_registrable,
                    distance=distance,
                )

        return AnalysisExecutionResult.COMPLETED
