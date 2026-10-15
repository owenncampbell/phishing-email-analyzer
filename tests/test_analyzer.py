"""Tests use small synthetic emails built in code, so they need no real phishing samples."""

from __future__ import annotations

import email
import hashlib
from email import policy
from pathlib import Path

import pytest

from phish_analyzer.analysis import analyze_message
from phish_analyzer.auth import parse_auth_results
from phish_analyzer.body import decode_redirect, defang, extract_body
from phish_analyzer.cli import main
from phish_analyzer.headers import base_domain, domain_of, parse_address
from phish_analyzer.received import origin_ip, parse_received_chain
from phish_analyzer.rules import score

SAMPLES = Path(__file__).parent.parent / "samples"


def make_email(headers: str, body: str = "Hello", content_type: str = "text/plain") -> email.message.EmailMessage:
    raw = f"{headers.strip()}\nContent-Type: {content_type}; charset=utf-8\n\n{body}\n"
    return email.message_from_bytes(raw.encode(), policy=policy.default)


def titles(msg) -> list[str]:
    return [f.title for f in analyze_message(msg).findings]


# ------------------------------------------------------------------ headers

def test_domain_of_uses_last_at_sign():
    assert domain_of("bounce+abc-user@pot=hotmail.com@mg.example.com") == "mg.example.com"
    assert domain_of("no-at-sign") == ""


@pytest.mark.parametrize("domain, expected", [
    ("mail.paypal.com", "paypal.com"),
    ("paypal.com", "paypal.com"),
    ("secure.bradesco.com.br", "bradesco.com.br"),
    ("news.bbc.co.uk", "bbc.co.uk"),
])
def test_base_domain(domain, expected):
    assert base_domain(domain) == expected


def test_parse_address_splits_display_name():
    addr = parse_address('"PayPal Support" <Alerts@Evil.Example>')
    assert addr.display_name == "PayPal Support"
    assert addr.address == "alerts@evil.example"
    assert addr.domain == "evil.example"


# --------------------------------------------------------------------- auth

def test_auth_uses_topmost_header_only():
    # The lower header is "attacker supplied" and claims everything passed.
    msg = make_email("""
Authentication-Results: mx.victim.com; spf=fail smtp.mailfrom=evil.example; dkim=none; dmarc=fail
Authentication-Results: fake.evil.example; spf=pass; dkim=pass; dmarc=pass
From: a@b.com
""")
    auth = parse_auth_results(msg)
    assert (auth.spf, auth.dkim, auth.dmarc) == ("fail", "none", "fail")


def test_auth_falls_back_to_received_spf():
    msg = make_email("Received-SPF: Pass (google.com: domain of a@b.com designates 1.2.3.4)\nFrom: a@b.com")
    assert parse_auth_results(msg).spf == "pass"


# ----------------------------------------------------------------- received

RECEIVED = """
Received: from mx.internal (10.0.0.5) by inbox.victim.com; Tue, 19 Sep 2023 18:36:00 +0000
Received: from evil-vps (45.33.32.156) by mx.victim.com; Tue, 19 Sep 2023 18:35:55 +0000
Received: by evil-vps (Postfix, from userid 0); Tue, 19 Sep 2023 18:35:49 +0000
From: "Bank Security" <security@bank-alerts.example>
To: victim@victim.com
"""


def test_received_chain_is_reversed_to_origin_first():
    hops = parse_received_chain(make_email(RECEIVED))
    assert [h.by_host for h in hops] == ["evil-vps", "mx.victim.com", "inbox.victim.com"]
    assert hops[1].delay_seconds == 6


def test_origin_ip_skips_private_addresses():
    hops = parse_received_chain(make_email(RECEIVED))
    assert origin_ip(hops) == "45.33.32.156"
    hops[1].ips = ["10.0.0.1", "8.8.8.8"]
    assert origin_ip(hops) == "8.8.8.8"


def test_root_sender_flagged():
    assert "Sent from a server's root account" in titles(make_email(RECEIVED))


# --------------------------------------------------------------------- body

def test_deceptive_link_text_is_flagged():
    html = '<p>Log in at <a href="https://evil.example/login">https://www.paypal.com</a></p>'
    msg = make_email("From: service@paypal.com\nTo: v@v.com", html, "text/html")
    links, _ = extract_body(msg)
    assert links[0].text == "https://www.paypal.com"
    assert "Link text shows a different domain than the real destination" in titles(msg)


def test_matching_link_text_is_not_flagged():
    html = '<a href="https://www.paypal.com/signin">paypal.com</a>'
    msg = make_email("From: service@paypal.com\nTo: v@v.com", html, "text/html")
    assert "Link text shows a different domain than the real destination" not in titles(msg)


def test_bing_redirect_is_decoded():
    # "a1" + base64("http://evil.example/x"), as used in a real sample.
    url = "https://www.bing.com/ck/a?!&&p=abc&u=a1aHR0cDovL2V2aWwuZXhhbXBsZS94&ntb=1"
    assert decode_redirect(url) == "http://evil.example/x"


def test_defang():
    assert defang("https://evil.example.com/a.b") == "hxxps://evil[.]example[.]com/a.b"


# --------------------------------------------------------------- attachments

def test_attachment_hashed_and_double_extension_flagged():
    msg = email.message.EmailMessage(policy=policy.default)
    msg["From"] = "a@b.com"
    msg["To"] = "v@v.com"
    msg.set_content("see attached")
    payload = b"MZ fake executable"
    msg.add_attachment(payload, maintype="application", subtype="octet-stream", filename="invoice.pdf.exe")

    result = analyze_message(msg)
    assert result.attachments[0].sha256 == hashlib.sha256(payload).hexdigest()
    assert "Attachment with a double extension" in [f.title for f in result.findings]


# ------------------------------------------------------------------- sender

def test_reply_to_diversion():
    msg = make_email('From: "Edward Collins" <a@gmail.com>\nReply-To: b@gmail.com\nTo: v@v.com')
    assert "Reply-To is a different free webmail inbox" in titles(msg)


def test_display_name_with_fake_address():
    msg = make_email('From: "support@paypal.com" <x@evil.example>\nTo: v@v.com')
    assert "Display name shows a different email address" in titles(msg)


def test_clean_email_is_low_risk():
    msg = make_email("""
Authentication-Results: mx.example.com; spf=pass; dkim=pass header.d=example.com; dmarc=pass
From: Alice <alice@example.com>
To: bob@example.com
Message-ID: <123@example.com>
Return-Path: <alice@example.com>
""", "Lunch tomorrow?")
    result = analyze_message(msg)
    assert result.findings == []
    assert result.verdict == "LOW RISK"


# -------------------------------------------------------------------- score

def test_score_is_capped_and_bucketed():
    from phish_analyzer.rules import Finding
    assert score([Finding("x", 80, "", ""), Finding("x", 80, "", "")]) == (100, "LIKELY PHISHING")
    assert score([Finding("x", 30, "", "")])[1] == "SUSPICIOUS"
    assert score([])[1] == "LOW RISK"


# ---------------------------------------------------------------------- cli

def test_cli_missing_file_returns_error(capsys):
    assert main(["does-not-exist.eml"]) == 1
    assert "error" in capsys.readouterr().err


@pytest.mark.skipif(not (SAMPLES / "sample-1.eml").exists(), reason="run ./get_samples.sh first")
def test_real_samples_regression(capsys):
    assert main([str(SAMPLES / "sample-1.eml"), str(SAMPLES / "sample-2.eml"), "--summary"]) == 0
    out = capsys.readouterr().out
    assert out.count("LIKELY PHISHING") == 2
