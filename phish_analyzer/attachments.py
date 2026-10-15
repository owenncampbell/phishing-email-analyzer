"""List attachments and hash them without ever writing them to disk.

The SHA-256 hash is the indicator analysts search for in VirusTotal or
MalwareBazaar. Hashing in memory means the potentially malicious file is never
saved, so it can't be opened by accident or picked up by an antivirus scan
mid-analysis.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from email.message import EmailMessage

# File types commonly used to deliver malware or credential-harvesting pages.
RISKY_EXTENSIONS = {
    ".exe", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse",
    ".wsf", ".hta", ".lnk", ".msi", ".dll", ".jar", ".iso", ".img", ".vhd",
    ".one", ".docm", ".xlsm", ".pptm", ".html", ".htm", ".shtml", ".svg",
    ".zip", ".rar", ".7z", ".gz",
}
# Extensions an attacker might put *before* the real one: invoice.pdf.exe
DECOY_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt"}


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str

    @property
    def extension(self) -> str:
        name = self.filename.lower()
        return name[name.rfind("."):] if "." in name else ""

    @property
    def is_risky(self) -> bool:
        return self.extension in RISKY_EXTENSIONS

    @property
    def has_double_extension(self) -> bool:
        parts = self.filename.lower().split(".")
        return len(parts) >= 3 and f".{parts[-2]}" in DECOY_EXTENSIONS


def extract_attachments(msg: EmailMessage) -> list[Attachment]:
    attachments = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if not filename and part.get_content_disposition() != "attachment":
            continue
        payload = part.get_payload(decode=True) or b""
        attachments.append(Attachment(
            filename=filename or "(unnamed)",
            content_type=part.get_content_type(),
            size=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
        ))
    return attachments
