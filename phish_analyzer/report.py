"""Format an Analysis as a human-readable report or as JSON.

All URLs and IPs are defanged in the text report so it can be pasted into a
ticket or chat without creating clickable malicious links.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from .analysis import Analysis
from .auth import RESULT_MEANINGS
from .body import defang


def _defang_ip(ip: str) -> str:
    return ip.replace(".", "[.]") if "." in ip else ip


def _addr(a) -> str:
    return a.raw if a else "(not present)"


def _section(title: str) -> str:
    return f"\n{title}\n{'-' * len(title)}"


def to_text(a: Analysis) -> str:
    h = a.headers
    lines = [
        "=" * 72,
        f"PHISHING TRIAGE REPORT: {a.file}",
        "=" * 72,
        f"Verdict: {a.verdict}   (risk score {a.score}/100)",
        _section("Sender headers"),
        f"  {'Subject':<12} {h.subject}",
        f"  {'From':<12} {_addr(h.from_)}",
        f"  {'Reply-To':<12} {_addr(h.reply_to)}",
        f"  {'Return-Path':<12} {_addr(h.return_path)}",
        f"  {'To':<12} {h.to or '(not present)'}",
        f"  {'Date':<12} {h.date}",
        f"  {'Message-ID':<12} {h.message_id or '(not present)'}",
        _section(f"Authentication (from {a.auth.source or 'no auth headers'})"),
    ]
    for name in ("spf", "dkim", "dmarc"):
        value = getattr(a.auth, name)
        meaning = RESULT_MEANINGS.get(value, "")
        lines.append(f"  {name.upper():<6} {value:<10} {meaning}")

    lines.append(_section(f"Relay path ({len(a.hops)} hops, origin first)"))
    for hop in a.hops:
        ips = ", ".join(_defang_ip(ip) for ip in hop.ips) or "-"
        delay = f"+{hop.delay_seconds:.0f}s" if hop.delay_seconds is not None else ""
        lines.append(f"  {hop.number:>2}. from {hop.from_host or '?'} [{ips}] -> by {hop.by_host or '?'} {delay}")
    lines.append(f"  Likely origin IP: {_defang_ip(a.origin_ip) if a.origin_ip else 'unknown'}")

    lines.append(_section(f"Links ({len(a.links)})"))
    for link in a.links:
        lines.append(f"  - {defang(link.url)[:150]}")
        if link.text:
            lines.append(f"      text: {link.text[:80]}")
        if link.redirect_target:
            lines.append(f"      REAL DESTINATION: {defang(link.redirect_target)}")
    if not a.links:
        lines.append("  (none)")

    lines.append(_section(f"Attachments ({len(a.attachments)})"))
    for att in a.attachments:
        lines.append(f"  - {att.filename} ({att.content_type}, {att.size} bytes)")
        lines.append(f"      sha256: {att.sha256}")
    if not a.attachments:
        lines.append("  (none)")

    lines.append(_section("Findings"))
    for f in a.findings:
        lines.append(f"  [+{f.points:>2}] {f.title}")
        lines.append(f"        {f.detail}")
    if not a.findings:
        lines.append("  (no red flags found)")
    return "\n".join(lines) + "\n"


def to_json(a: Analysis) -> str:
    data = asdict(a)
    data.pop("body_text")  # bulky; the findings already summarize it
    for hop in data["hops"]:
        hop.pop("raw")
    return json.dumps(data, indent=2, default=str, ensure_ascii=False)
