"""Extract links and readable text from the message body.

Email bodies are MIME: a tree of parts. A typical phish is
``multipart/alternative`` containing a text/plain and a text/html version.
``msg.walk()`` visits every part so nothing is missed.

For HTML, the analyzer records the *visible link text* as well as the real
href. "Display text says paypal.com, href goes somewhere else" is one of the
strongest phishing signals there is.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from email.message import EmailMessage
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit

_URL_RE = re.compile(r"""https?://[^\s<>"'\])]+""", re.IGNORECASE)
_DOMAINISH_RE = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.IGNORECASE)


@dataclass
class Link:
    url: str
    text: str = ""  # visible anchor text (HTML only)
    source: str = "text"  # "html-href" or "text"
    redirect_target: str = ""  # decoded destination if the URL is a known redirector

    @property
    def domain(self) -> str:
        return (urlsplit(self.url).hostname or "").lower()


class _AnchorParser(HTMLParser):
    """Collects (href, visible text) for every <a> tag."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)  # turns &amp; back into &
        self.anchors: list[tuple[str, str]] = []
        self.text_chunks: list[str] = []
        self._href: str | None = None
        self._anchor_text: list[str] = []
        self._skip = 0  # inside <style> or <script>

    def handle_starttag(self, tag, attrs):
        if tag in ("style", "script"):
            self._skip += 1
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._anchor_text = []

    def handle_endtag(self, tag):
        if tag in ("style", "script") and self._skip:
            self._skip -= 1
        if tag == "a" and self._href is not None:
            self.anchors.append((self._href.strip(), " ".join("".join(self._anchor_text).split())))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text_chunks.append(data)
        if self._href is not None:
            self._anchor_text.append(data)


def _part_text(part: EmailMessage) -> str:
    """Decode a text part, surviving the broken charsets phishers often send."""
    try:
        return part.get_content()
    except (LookupError, UnicodeDecodeError, AssertionError):
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")


def decode_redirect(url: str) -> str:
    """If ``url`` is a known redirector, return the real destination.

    Attackers wrap malicious links in trusted domains (Bing, Google) so link
    scanners see a reputable domain. Bing's /ck/a links carry the destination
    in the ``u`` parameter as "a1" + URL-safe base64.
    """
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    query = parse_qs(parts.query)

    if host.endswith("bing.com") and parts.path.startswith("/ck/a"):
        encoded = (query.get("u") or [""])[0]
        if encoded.startswith("a1"):
            encoded = encoded[2:]
            try:
                padded = encoded + "=" * (-len(encoded) % 4)
                return base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")
            except (binascii.Error, ValueError):
                return ""

    if host.endswith("google.com") and parts.path == "/url":
        return (query.get("q") or query.get("url") or [""])[0]

    return ""


def extract_body(msg: EmailMessage) -> tuple[list[Link], str]:
    """Return (unique links, readable text) from every text part."""
    links: list[Link] = []
    text_chunks: list[str] = []

    for part in msg.walk():
        if part.get_content_maintype() != "text" or part.get_filename():
            continue  # skip containers and attached files
        content = _part_text(part)

        if part.get_content_subtype() == "html":
            parser = _AnchorParser()
            parser.feed(content)
            text_chunks.append(" ".join(parser.text_chunks))
            for href, anchor_text in parser.anchors:
                if href.lower().startswith(("http://", "https://")):
                    links.append(Link(url=href, text=anchor_text, source="html-href"))
            # URLs outside <a> tags (images, plain text inside the HTML).
            visible = " ".join(parser.text_chunks)
            links.extend(Link(url=u) for u in _URL_RE.findall(visible))
        else:
            text_chunks.append(content)
            links.extend(Link(url=u) for u in _URL_RE.findall(content))

    unique: dict[str, Link] = {}
    for link in links:
        link.url = link.url.rstrip(".,;")
        # Prefer the HTML version of a URL because it carries anchor text.
        if link.url not in unique or (link.text and not unique[link.url].text):
            unique[link.url] = link
    for link in unique.values():
        link.redirect_target = decode_redirect(link.url)

    return list(unique.values()), " ".join(" ".join(text_chunks).split())


def anchor_text_domain(text: str) -> str:
    """If the anchor text *looks like* a domain or URL, return that domain."""
    match = _DOMAINISH_RE.search(text)
    return match.group(1).lower() if match else ""


def defang(url: str) -> str:
    """Make a URL non-clickable for safe sharing: hxxps://evil[.]com/path."""
    parts = urlsplit(url)
    scheme = parts.scheme.replace("http", "hxxp") if parts.scheme else ""
    host = parts.netloc.replace(".", "[.]")
    rest = url.split(parts.netloc, 1)[1] if parts.netloc else url
    return f"{scheme}://{host}{rest}" if scheme else url.replace(".", "[.]")
