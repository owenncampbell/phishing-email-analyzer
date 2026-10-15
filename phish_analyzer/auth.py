"""SPF / DKIM / DMARC results from the Authentication-Results header.

Quick refresher:

* **SPF**   - Is the sending server's IP allowed to send for the
              Return-Path (envelope) domain? Checked against a DNS TXT record.
* **DKIM**  - Does the message carry a valid cryptographic signature from
              the domain in ``d=``? Proves the content wasn't altered.
* **DMARC** - Does the domain in the visible ``From:`` *align* with a
              domain that passed SPF or DKIM? This is the check that
              actually ties authentication to what the user sees.

Important: authentication proves *where* mail came from, not that the sender
is honest. A scammer using a real Gmail account passes all three.

Which header to trust: every server along the path can add an
Authentication-Results header, and an attacker can include fake ones in the
message they send. New headers are added at the *top*, so the first one was
written by the final receiving server (your provider). Only that one is used
here. In production you would also check that its authserv-id is your own
mail system.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email.message import EmailMessage

_RESULT_RE = re.compile(r"\b(spf|dkim|dmarc|compauth)\s*=\s*([a-z]+)", re.IGNORECASE)

# What each result means, for the report.
RESULT_MEANINGS = {
    "pass": "verified",
    "fail": "FAILED verification",
    "softfail": "weak fail: the domain discourages this sender (~all)",
    "neutral": "the domain makes no assertion",
    "none": "no record / no signature, so nothing could be verified",
    "temperror": "temporary DNS error, so nothing could be verified",
    "permerror": "broken record at the domain, so nothing could be verified",
}


@dataclass
class AuthResults:
    spf: str = "missing"
    dkim: str = "missing"
    dmarc: str = "missing"
    source: str = ""  # which header the results came from
    raw: str = ""
    extra: dict[str, str] = field(default_factory=dict)


def parse_auth_results(msg: EmailMessage) -> AuthResults:
    results = AuthResults()

    headers = msg.get_all("Authentication-Results") or []
    if headers:
        raw = " ".join(str(headers[0]).split())  # collapse folded lines
        results.source = "Authentication-Results"
        results.raw = raw
        for mechanism, value in _RESULT_RE.findall(raw):
            mechanism, value = mechanism.lower(), value.lower()
            if mechanism in ("spf", "dkim", "dmarc"):
                # Keep the first result for each mechanism.
                if getattr(results, mechanism) == "missing":
                    setattr(results, mechanism, value)
            else:
                results.extra[mechanism] = value  # e.g. Microsoft's compauth
        return results

    # Fallback: some servers only add Received-SPF, e.g. "Pass (google.com: ...)".
    spf_headers = msg.get_all("Received-SPF") or []
    if spf_headers:
        raw = " ".join(str(spf_headers[0]).split())
        results.source = "Received-SPF"
        results.raw = raw
        results.spf = raw.split()[0].lower() if raw else "missing"
    return results
