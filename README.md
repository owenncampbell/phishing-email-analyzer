# Phishing Email Analyzer

> Part of my [IT & Cybersecurity Portfolio](https://github.com/owenncampbell/it-cybersecurity-portfolio)

A Python command-line tool that triages a raw `.eml` file the way a SOC analyst would. It parses the headers, checks SPF/DKIM/DMARC, rebuilds the relay path, extracts and defangs links, hashes attachments, and scores the email against a set of phishing red-flag rules.

It uses only the Python standard library, so the analyzer itself has no dependencies.

## Example

Run against a real credential-phishing email impersonating Mashreq Bank:

```
$ python analyzer.py samples/sample-2.eml
========================================================================
PHISHING TRIAGE REPORT: samples/sample-2.eml
========================================================================
Verdict: LIKELY PHISHING   (risk score 70/100)

Sender headers
--------------
  Subject      Confirm Your Mashreq Email Now For Your Security (MOVE TO INBOX)
  From         MashreqAlerts <postmaster@digitalmashreq.mg.tdi.tc>
  Return-Path  bounce+a57fa4.cba7bc-phishing@pot=hotmail.com@mg.tdi.tc
  ...

Authentication (from Authentication-Results)
--------------------------------------------
  SPF    none       no record / no signature, so nothing could be verified
  DKIM   fail       FAILED verification
  DMARC  fail       FAILED verification

Relay path (5 hops, origin first)
---------------------------------
   1. from <unknown> [-] -> by 27533be87c53
   2. from pc232-5.mailgun.net [143[.]55[.]232[.]5, ...] -> by DB3EUR04FT006.mail.protection.outlook.com +1s
  ...
  Likely origin IP: 143[.]55[.]232[.]5

Links (6)
---------
  - hxxps://www[.]bing[.]com/ck/a?!&&p=b03d93...
      text: Sign in To verify your email
      REAL DESTINATION: hxxp://marhaba-travel[.]com/fr/formules
  ...

Findings
--------
  [+25] DMARC fail
  [+15] DKIM fail
  [+15] Links hidden behind a trusted redirector
        www.bing.com redirects to: http://marhaba-travel.com/fr/formules
  [+10] Asks the reader to log in or verify details, and includes links
  [+ 5] SPF none
```

The "Sign in" button points to `bing.com`, so a link scanner would see a trusted domain. The analyzer decodes Bing's redirect parameter to show where it really goes.

Summary mode for triaging a batch:

```
$ python analyzer.py samples/*.eml --summary
 70/100  LIKELY PHISHING  samples/sample-1.eml  |  CLIENTE PRIME - BRADESCO LIVELO: Seu cartão tem 92.990 ponto
 70/100  LIKELY PHISHING  samples/sample-2.eml  |  Confirm Your Mashreq Email Now For Your Security (MOVE TO IN
 25/100  SUSPICIOUS       samples/sample-3.eml  |  Dia Bom
 15/100  LOW RISK         samples/sample-4.eml  |  Ditt abonnement er avsluttet
 35/100  SUSPICIOUS       samples/sample-5.eml  |  Fw: Your Bank Account has been blocked due to unusual activi
```

## Usage

```bash
git clone https://github.com/owenncampbell/phishing-email-analyzer.git
cd phishing-email-analyzer
python3 -m venv .venv && source .venv/bin/activate

./get_samples.sh                              # download test samples (see Safety)
python analyzer.py samples/sample-1.eml       # full report
python analyzer.py samples/*.eml --summary    # one line per email
python analyzer.py samples/sample-1.eml --json > report.json   # for SIEM/SOAR ingestion

pip install -r requirements-dev.txt && pytest # run the tests
```

To analyze your own email, save the original message as `.eml`. In Gmail use ⋮ → *Download message*; in Outlook use *Save As*.

## What it checks

| Category | Check | Points | Why it matters |
|---|---|---|---|
| Authentication | SPF fail / softfail / none | 20 / 10 / 5 | Sending server not authorized for the envelope domain |
| | DKIM fail / none | 15 / 5 | No valid signature, so the content could be forged |
| | DMARC fail / none | 25 / 5 | Visible From: domain isn't backed by aligned SPF/DKIM |
| Sender | Display name contains a different address | 25 | `"support@paypal.com" <x@evil.ru>` |
| | Display name claims an org the domain doesn't match | 15 | "BANCO DO BRADESCO" sending from `atendimento.com.br` |
| | Reply-To diverted to another domain / webmail inbox | 20 / 15 | Replies go to the attacker (419, BEC) |
| | Return-Path is a bare hostname / different domain / different webmail account | 15 / 10 / 15 | Shows the real sending infrastructure |
| | Message-ID from a different domain | 5 | Shows which server actually built the message |
| | Free webmail sender, no visible recipients | 5 each | Weak signals that add up in combination |
| Content | Urgency, credential-lure and advance-fee (419) language | 10–15 | Social-engineering pressure |
| Links | Link text shows a different domain than the href | 25 | Classic deceptive link |
| | Raw-IP links, trusted-redirector wrapping, shorteners, punycode, http:// | 5–20 | Hiding or disguising the destination |
| Attachments | Double extension (`invoice.pdf.exe`) / risky type (`.html`, `.iso`, `.js`…) | 30 / 25 | Malware and credential-harvesting delivery |
| Routing | Sent from a server's root account (`from userid 0`) | 10 | Typical of throwaway VPS spam scripts |

Score: **50+** likely phishing, **25–49** suspicious, **under 25** low risk. No single weak signal decides the verdict; the combination does.

## How it works

```
analyzer.py                 entry point
phish_analyzer/
├── headers.py      load .eml, parse From / Reply-To / Return-Path / Message-ID
├── auth.py         SPF / DKIM / DMARC from Authentication-Results
├── received.py     rebuild the relay path, find the origin IP
├── body.py         walk MIME parts, extract links + anchor text, decode redirectors, defang
├── attachments.py  list attachments, SHA-256 in memory (never written to disk)
├── rules.py        red-flag rules + scoring
├── analysis.py     runs every step, builds one Analysis object
├── report.py       text report (defanged) and JSON output
└── cli.py          argparse command line
tests/              pytest suite using synthetic emails
```

Design decisions:
- **Only the top Authentication-Results header is trusted.** Attackers can include fake "all pass" headers further down; only the receiving server's own header is reliable.
- **Received headers are read bottom-up** to rebuild the route from the origin. Hops before the handoff to the victim's provider are attacker-controlled and could be forged.
- **Attachments are hashed in memory**, so a malicious file never touches disk.
- **Reports are defanged** (`hxxps://evil[.]com`) so they can be pasted into tickets or chat safely. JSON output keeps the original values for tooling.

## Limitations

- **Content keywords are English only.** Sample 3 is a Portuguese 419 scam that passes SPF, DKIM and DMARC (it really was sent from Gmail). It's caught only as *suspicious*, mostly because its Return-Path Gmail account differs from its From account.
- **Forwarded emails are analyzed as the forward.** Sample 5 is a phish someone forwarded, so the headers describe the forwarder rather than the attacker.
- **The organizational-domain logic is a heuristic.** Production code should use the Public Suffix List (for example `tldextract`).
- **No threat-intel lookups.** IPs, domains and hashes are extracted but not checked for reputation.

## Roadmap

- [ ] Enrich IOCs with VirusTotal, AbuseIPDB and URLhaus (API keys via environment variables)
- [ ] Look-alike domain detection (`paypa1.com`, `rnicrosoft.com`)
- [ ] Multi-language keyword lists
- [ ] Parse HTML forms and `<img>` tracking pixels

## Safety

Samples come from [phishing_pot](https://github.com/rf-peixoto/phishing_pot) and are **live phishing emails**. They aren't committed to this repo; `get_samples.sh` downloads them. Open them only as text or with this tool, never in a mail client, and never visit the extracted links.
