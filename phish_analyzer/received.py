"""Reconstruct the relay path from the Received: headers.

Every mail server that handles a message adds a Received: line at the top,
so the headers read newest-first. Reversing them gives the route in the
order the email actually travelled, starting at its origin.

    Received: from mx.victim.com ... by inbox.victim.com ...   <- last hop (top)
    Received: from evil-vps (203.0.113.9) by mx.victim.com ... <- handoff to victim
    Received: by evil-vps (Postfix) ...                        <- origin (bottom)

Caveat for interviews: only hops added by servers *you* trust are reliable.
An attacker controls everything before the handoff to your server and can
add fake Received lines at the bottom to mislead an analyst.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime
from email.message import EmailMessage
from email.utils import parsedate_to_datetime

_FROM_RE = re.compile(r"^from\s+([^\s;]+)", re.IGNORECASE)
_BY_RE = re.compile(r"\bby\s+([^\s;]+)", re.IGNORECASE)
# IPs usually appear inside () or [] next to the hostname.
_BRACKETED_RE = re.compile(r"[\[(]\s*(?:IPv6:)?([0-9a-fA-F:.%]+)\s*[\])]")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class Hop:
    number: int  # 1 = origin
    from_host: str
    by_host: str
    ips: list[str]
    timestamp: datetime | None
    delay_seconds: float | None  # time since the previous hop
    raw: str


def _extract_ips(text: str) -> list[str]:
    candidates = _BRACKETED_RE.findall(text) + _IPV4_RE.findall(text)
    ips: list[str] = []
    for candidate in candidates:
        candidate = candidate.split("%")[0]  # drop IPv6 zone index (fe80::1%4)
        try:
            ip = str(ipaddress.ip_address(candidate))
        except ValueError:
            continue  # not an IP, e.g. "(Postfix" or a version number
        if ip not in ips:
            ips.append(ip)
    return ips


def _parse_timestamp(text: str) -> datetime | None:
    # The date is everything after the last semicolon.
    if ";" not in text:
        return None
    try:
        return parsedate_to_datetime(text.rpartition(";")[2].strip())
    except (TypeError, ValueError, IndexError):
        return None


def parse_received_chain(msg: EmailMessage) -> list[Hop]:
    raw_headers = [" ".join(str(h).split()) for h in (msg.get_all("Received") or [])]
    hops: list[Hop] = []
    previous_time: datetime | None = None

    for number, raw in enumerate(reversed(raw_headers), start=1):
        from_match = _FROM_RE.search(raw)
        by_match = _BY_RE.search(raw)
        timestamp = _parse_timestamp(raw)

        delay = None
        if timestamp and previous_time:
            try:
                delay = (timestamp - previous_time).total_seconds()
            except TypeError:  # one timestamp has a timezone, the other doesn't
                delay = None
        if timestamp:
            previous_time = timestamp

        hops.append(Hop(
            number=number,
            from_host=from_match.group(1) if from_match else "",
            by_host=by_match.group(1) if by_match else "",
            ips=_extract_ips(raw),
            timestamp=timestamp,
            delay_seconds=delay,
            raw=raw,
        ))
    return hops


def origin_ip(hops: list[Hop]) -> str | None:
    """The first *public* IP on the route: the likely sending server.

    Private (10.x, 192.168.x), loopback and link-local addresses are skipped
    because they're internal to some organization's network and can't be
    looked up in threat intel.
    """
    for hop in hops:
        for ip in hop.ips:
            if ipaddress.ip_address(ip).is_global:
                return ip
    return None
