"""Loading an .eml file and pulling out the sender-identity headers.

An email has *two* senders, and phishers abuse the gap between them:

* ``From:``        - what the victim sees in their mail client. Trivial to fake.
* ``Return-Path:`` - the "envelope sender" used by mail servers for bounces.
                     It is what SPF actually checks, and often reveals the
                     real sending infrastructure.

``Reply-To:`` is a third address: where replies go. Scams that want a
conversation (419 / BEC) set it to an inbox the attacker controls.
"""

from __future__ import annotations

import email
from dataclasses import dataclass
from email import policy
from email.message import EmailMessage
from email.utils import parseaddr

# Free webmail providers. A "bank" or "IT department" sending from one of
# these is a red flag, because real organizations send from their own domain.
FREEMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "msn.com", "yahoo.com", "aol.com", "icloud.com", "me.com", "proton.me",
    "protonmail.com", "gmx.com", "gmx.net", "mail.com", "yandex.com",
    "yandex.ru", "mail.ru", "zoho.com",
}

# Second-level labels used under country-code TLDs (example.com.br, example.co.uk).
_CCTLD_SECOND_LEVEL = {"co", "com", "net", "org", "gov", "edu", "ac"}


def load_email(path: str) -> EmailMessage:
    """Parse an .eml file into an EmailMessage object.

    The file is opened in binary mode ("rb") because email can contain bytes in
    any character set; the email parser does the decoding, not open().
    ``policy.default`` enables modern behaviour, e.g. decoding RFC 2047 encoded
    headers like ``=?UTF-8?B?...?=`` into readable text.
    """
    with open(path, "rb") as f:
        return email.message_from_binary_file(f, policy=policy.default)


@dataclass
class Address:
    """One parsed address header, e.g. ``"PayPal" <alerts@evil.example>``."""

    raw: str
    display_name: str
    address: str
    domain: str

    @property
    def base_domain(self) -> str:
        return base_domain(self.domain)


@dataclass
class SenderHeaders:
    subject: str
    date: str
    to: str
    from_: Address | None
    reply_to: Address | None
    return_path: Address | None
    message_id: str
    message_id_domain: str


def domain_of(address: str) -> str:
    """Return the lower-cased part after the *last* @.

    rpartition is used rather than split("@") because bounce addresses
    often contain several @ signs, e.g. bounce+abc-user@pot=hotmail.com@mg.example.
    """
    if "@" not in address:
        return ""
    return address.rpartition("@")[2].strip(" <>").lower()


def base_domain(domain: str) -> str:
    """Rough "organizational domain": mail.paypal.com -> paypal.com.

    Used so legitimate setups like From: example.com / Return-Path:
    bounces.example.com are not flagged as mismatches.

    This is a heuristic. Real tools use the Public Suffix List (for example
    the ``tldextract`` package) to handle every TLD correctly.
    """
    labels = [label for label in domain.lower().split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    if len(labels[-1]) == 2 and labels[-2] in _CCTLD_SECOND_LEVEL:
        return ".".join(labels[-3:])  # example.com.br, example.co.uk
    return ".".join(labels[-2:])


def parse_address(raw: str | None) -> Address | None:
    if raw is None:
        return None
    raw = str(raw)
    name, addr = parseaddr(raw)
    if not addr:
        # parseaddr gives up on some malformed addresses; keep the raw text.
        addr = raw.strip(" <>")
    return Address(raw=raw, display_name=name, address=addr.lower(), domain=domain_of(addr))


def is_freemail(domain: str) -> bool:
    return domain.lower() in FREEMAIL_DOMAINS


def extract_sender_headers(msg: EmailMessage) -> SenderHeaders:
    message_id = str(msg.get("Message-ID", "") or "").strip()
    return SenderHeaders(
        subject=str(msg.get("Subject", "") or ""),
        date=str(msg.get("Date", "") or ""),
        to=str(msg.get("To", "") or ""),
        from_=parse_address(msg.get("From")),
        reply_to=parse_address(msg.get("Reply-To")),
        return_path=parse_address(msg.get("Return-Path")),
        message_id=message_id,
        message_id_domain=domain_of(message_id),
    )
