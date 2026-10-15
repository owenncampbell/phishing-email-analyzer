"""Runs every analysis step and collects the results in one object."""

from __future__ import annotations

from dataclasses import dataclass, field
from email.message import EmailMessage

from .attachments import Attachment, extract_attachments
from .auth import AuthResults, parse_auth_results
from .body import Link, extract_body
from .headers import SenderHeaders, extract_sender_headers, load_email
from .received import Hop, origin_ip, parse_received_chain
from .rules import Finding, run_rules, score


@dataclass
class Analysis:
    file: str
    headers: SenderHeaders
    auth: AuthResults
    hops: list[Hop]
    origin_ip: str | None
    links: list[Link]
    body_text: str
    attachments: list[Attachment]
    findings: list[Finding] = field(default_factory=list)
    score: int = 0
    verdict: str = ""


def analyze_message(msg: EmailMessage, file: str = "") -> Analysis:
    hops = parse_received_chain(msg)
    links, body_text = extract_body(msg)
    result = Analysis(
        file=file,
        headers=extract_sender_headers(msg),
        auth=parse_auth_results(msg),
        hops=hops,
        origin_ip=origin_ip(hops),
        links=links,
        body_text=body_text,
        attachments=extract_attachments(msg),
    )
    # Rules run last because they read everything collected above.
    result.findings = run_rules(result)
    result.score, result.verdict = score(result.findings)
    return result


def analyze_file(path: str) -> Analysis:
    return analyze_message(load_email(path), file=path)
