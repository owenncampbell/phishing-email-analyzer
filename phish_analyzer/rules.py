"""Red-flag rules: turning analyst judgment into code.

Each rule looks at the parsed email and may return a Finding worth some
points. Points add up to a 0-100 risk score. The weights are judgment calls,
roughly "how often is this seen in legitimate mail?":

* Strong signals (DMARC fail, deceptive link text, risky attachment) - 20-30
* Medium signals (Reply-To diversion, redirector links)              - 10-20
* Weak signals (free webmail, urgency words)                         - 5-10

No single weak signal makes an email malicious. It's the combination that
matters, the same way an analyst builds a case.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

from .body import anchor_text_domain
from .headers import base_domain, is_freemail

if TYPE_CHECKING:
    from .analysis import Analysis


@dataclass
class Finding:
    category: str  # auth | sender | content | links | attachments | routing
    points: int
    title: str
    detail: str


# Organizations and roles phishers like to claim in the display name.
IMPERSONATION_KEYWORDS = [
    "bank", "banco", "paypal", "microsoft", "office 365", "outlook", "apple",
    "icloud", "amazon", "netflix", "dhl", "fedex", "usps", "docusign", "chase",
    "wells fargo", "irs", "security", "support", "helpdesk", "help desk",
    "alert", "admin", "administrator", "billing", "payroll",
]
URGENCY_KEYWORDS = [
    "urgent", "immediately", "within 24 hours", "suspended", "blocked",
    "unusual activit", "expire", "expiring", "final notice", "action required",
    "account will be", "limited time", "last chance",
]
CREDENTIAL_KEYWORDS = [
    "verify your", "confirm your", "update your", "password", "log in", "login",
    "sign in", "validate your", "unlock your",
]
ADVANCE_FEE_KEYWORDS = [
    "next of kin", "beneficiary", "inheritance", "inherited", "fund transfer",
    "transfer the fund", "million", "barrister", "deceased", "investor",
    "confidential", "business proposal", "consignment", "lottery",
]
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "rebrand.ly",
    "cutt.ly", "rb.gy", "tiny.cc", "shorturl.at",
}


def _matches(keywords: list[str], text: str) -> list[str]:
    text = text.lower()
    return [k for k in keywords if re.search(rf"\b{re.escape(k)}", text)]


# ---------------------------------------------------------------- auth rules

def check_spf(a: Analysis) -> Finding | None:
    points = {"fail": 20, "softfail": 10, "none": 5, "neutral": 5,
              "temperror": 5, "permerror": 5}.get(a.auth.spf)
    if points:
        return Finding("auth", points, f"SPF {a.auth.spf}",
                       "The sending server is not confirmed as allowed to send for the envelope domain.")
    return None


def check_dkim(a: Analysis) -> Finding | None:
    points = {"fail": 15, "none": 5, "temperror": 5, "permerror": 5}.get(a.auth.dkim)
    if points:
        return Finding("auth", points, f"DKIM {a.auth.dkim}",
                       "No valid signature, so the message could have been forged or altered.")
    return None


def check_dmarc(a: Analysis) -> Finding | None:
    points = {"fail": 25, "none": 5, "temperror": 5, "permerror": 5}.get(a.auth.dmarc)
    if points:
        return Finding("auth", points, f"DMARC {a.auth.dmarc}",
                       "The visible From: domain is not backed by a passing, aligned SPF or DKIM result.")
    return None


# -------------------------------------------------------------- sender rules

def check_display_name_spoof(a: Analysis) -> Finding | None:
    """Display name contains an address, e.g. "support@paypal.com" <x@evil.ru>."""
    sender = a.headers.from_
    if not sender or "@" not in sender.display_name:
        return None
    shown = sender.display_name.rpartition("@")[2].strip(" <>\"'").lower()
    if shown and base_domain(shown) != sender.base_domain:
        return Finding("sender", 25, "Display name shows a different email address",
                       f"Name claims '{sender.display_name}' but the real address is {sender.address}.")
    return None


def check_impersonation(a: Analysis) -> Finding | None:
    sender = a.headers.from_
    if not sender or not sender.display_name:
        return None
    domain = sender.domain.replace("-", "")
    claimed = [k for k in _matches(IMPERSONATION_KEYWORDS, sender.display_name)
               if k.replace(" ", "") not in domain]
    if claimed:
        return Finding("sender", 15, "Display name claims an organization the sender domain doesn't match",
                       f"Display name '{sender.display_name}' mentions {', '.join(claimed)}, "
                       f"but the mail came from {sender.domain or '(no domain)'}.")
    return None


def check_freemail(a: Analysis) -> Finding | None:
    sender = a.headers.from_
    if sender and is_freemail(sender.domain):
        return Finding("sender", 5, "Sent from free webmail",
                       f"{sender.domain}: real companies send from their own domain.")
    return None


def check_reply_to(a: Analysis) -> Finding | None:
    sender, reply = a.headers.from_, a.headers.reply_to
    if not sender or not reply or reply.address == sender.address:
        return None
    if reply.base_domain != sender.base_domain:
        return Finding("sender", 20, "Reply-To goes to a different domain",
                       f"Replies go to {reply.address}, not {sender.address}.")
    if is_freemail(reply.domain):
        return Finding("sender", 15, "Reply-To is a different free webmail inbox",
                       f"Replies go to {reply.address}, not {sender.address}.")
    return None


def check_return_path(a: Analysis) -> Finding | None:
    sender, envelope = a.headers.from_, a.headers.return_path
    if not sender or not envelope:
        return None
    if envelope.domain and "." not in envelope.domain:
        return Finding("sender", 15, "Envelope sender is not a real domain",
                       f"Return-Path is {envelope.address}: a bare server hostname, "
                       "typical of a throwaway or misconfigured mail server.")
    if envelope.base_domain and envelope.base_domain != sender.base_domain:
        return Finding("sender", 10, "Return-Path domain differs from From domain",
                       f"Envelope sender {envelope.domain} vs. visible sender {sender.domain}.")
    if is_freemail(sender.domain) and envelope.address != sender.address:
        return Finding("sender", 15, "Return-Path is a different webmail account than From",
                       f"Sent by {envelope.address} while displaying {sender.address}. A personal "
                       "webmail message should have the same address in both.")
    return None


def check_message_id(a: Analysis) -> Finding | None:
    sender, mid_domain = a.headers.from_, a.headers.message_id_domain
    if sender and mid_domain and base_domain(mid_domain) != sender.base_domain:
        return Finding("sender", 5, "Message-ID created by a different domain",
                       f"Message-ID domain {mid_domain} vs. From domain {sender.domain}.")
    return None


def check_recipients(a: Analysis) -> Finding | None:
    to = a.headers.to.strip().lower()
    if not to or "undisclosed" in to:
        return Finding("sender", 5, "No visible recipients",
                       "Undisclosed or empty To: suggests the victim was Bcc'd on a mass mailing.")
    return None


# ------------------------------------------------------------- content rules

def _content(a: Analysis) -> str:
    return f"{a.headers.subject} {a.body_text}"


def check_urgency(a: Analysis) -> Finding | None:
    hits = _matches(URGENCY_KEYWORDS, _content(a))
    if hits:
        return Finding("content", 10, "Urgency / threat language", f"Matched: {', '.join(hits)}")
    return None


def check_credential_lure(a: Analysis) -> Finding | None:
    hits = _matches(CREDENTIAL_KEYWORDS, _content(a))
    if hits and a.links:
        return Finding("content", 10, "Asks the reader to log in or verify details, and includes links",
                       f"Matched: {', '.join(hits)}")
    return None


def check_advance_fee(a: Analysis) -> Finding | None:
    hits = _matches(ADVANCE_FEE_KEYWORDS, _content(a))
    if len(hits) >= 2:  # one alone ("confidential") is too common
        return Finding("content", 15, "Advance-fee / 419 scam language", f"Matched: {', '.join(hits)}")
    return None


# ---------------------------------------------------------------- link rules

def check_deceptive_links(a: Analysis) -> Finding | None:
    bad = []
    for link in a.links:
        shown = anchor_text_domain(link.text)
        if shown and link.domain and base_domain(shown) != base_domain(link.domain):
            bad.append(f"text '{link.text}' -> {link.domain}")
    if bad:
        return Finding("links", 25, "Link text shows a different domain than the real destination",
                       "; ".join(bad[:3]))
    return None


def check_ip_links(a: Analysis) -> Finding | None:
    hosts = []
    for link in a.links:
        try:
            ipaddress.ip_address(link.domain)
            hosts.append(link.domain)
        except ValueError:
            pass
    if hosts:
        return Finding("links", 20, "Links point to a raw IP address", ", ".join(sorted(set(hosts))))
    return None


def check_redirectors(a: Analysis) -> Finding | None:
    wrapped = [link for link in a.links if link.redirect_target]
    if wrapped:
        targets = sorted({link.redirect_target for link in wrapped})
        return Finding("links", 15, "Links hidden behind a trusted redirector",
                       f"{wrapped[0].domain} redirects to: {', '.join(targets[:3])}")
    return None


def check_shorteners(a: Analysis) -> Finding | None:
    hits = sorted({link.domain for link in a.links if link.domain in URL_SHORTENERS})
    if hits:
        return Finding("links", 10, "URL shortener hides the destination", ", ".join(hits))
    return None


def check_punycode(a: Analysis) -> Finding | None:
    hits = sorted({link.domain for link in a.links if "xn--" in link.domain})
    if hits:
        return Finding("links", 15, "Punycode domain (possible look-alike characters)", ", ".join(hits))
    return None


def check_plain_http(a: Analysis) -> Finding | None:
    hits = sorted({link.domain for link in a.links if link.url.lower().startswith("http://")})
    if hits:
        return Finding("links", 5, "Unencrypted http:// links", ", ".join(hits[:5]))
    return None


# ---------------------------------------------------------- attachment rules

def check_attachments(a: Analysis) -> Finding | None:
    double = [att.filename for att in a.attachments if att.has_double_extension]
    if double:
        return Finding("attachments", 30, "Attachment with a double extension", ", ".join(double))
    risky = [att.filename for att in a.attachments if att.is_risky]
    if risky:
        return Finding("attachments", 25, "Risky attachment type", ", ".join(risky))
    return None


# ------------------------------------------------------------- routing rules

def check_root_sender(a: Analysis) -> Finding | None:
    if any("from userid 0" in hop.raw.lower() for hop in a.hops):
        return Finding("routing", 10, "Sent from a server's root account",
                       "A Received header shows 'from userid 0': a script running as root on a "
                       "server, typical of throwaway VPS spam setups.")
    return None


RULES: list[Callable[[Analysis], Finding | None]] = [
    check_spf, check_dkim, check_dmarc,
    check_display_name_spoof, check_impersonation, check_freemail,
    check_reply_to, check_return_path, check_message_id, check_recipients,
    check_urgency, check_credential_lure, check_advance_fee,
    check_deceptive_links, check_ip_links, check_redirectors, check_shorteners,
    check_punycode, check_plain_http,
    check_attachments,
    check_root_sender,
]


def run_rules(a: Analysis) -> list[Finding]:
    findings = [f for rule in RULES if (f := rule(a))]
    return sorted(findings, key=lambda f: f.points, reverse=True)


def score(findings: list[Finding]) -> tuple[int, str]:
    total = min(100, sum(f.points for f in findings))
    if total >= 50:
        verdict = "LIKELY PHISHING"
    elif total >= 25:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LOW RISK"
    return total, verdict
