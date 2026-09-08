from __future__ import annotations

import email
import re
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from typing import Optional


@dataclass
class ParsedEmail:
    message_id: str = ""
    subject: str = ""
    from_addr: str = ""
    to_addr: str = ""
    reply_to: str = ""
    return_path: str = ""
    date: str = ""
    x_mailer: str = ""
    received_headers: list[str] = field(default_factory=list)
    body: str = ""
    raw_headers: str = ""
    attachments: list[dict] = field(default_factory=list)
    content_type: str = ""
    mime_version: str = ""
    dkim_signature: str = ""
    authentication_results: str = ""
    arc_seal: str = ""
    arc_message_signature: str = ""


class EmailParser:
    """Parse raw .eml content or raw email string into structured data."""

    @staticmethod
    def parse(raw: bytes | str) -> ParsedEmail:
        if isinstance(raw, str):
            raw = raw.encode("utf-8", errors="replace")

        msg = BytesParser(policy=policy.default).parsebytes(raw)
        parsed = ParsedEmail()

        parsed.message_id = msg.get("Message-ID", "")
        parsed.subject = msg.get("Subject", "")
        parsed.from_addr = msg.get("From", "")
        parsed.to_addr = msg.get("To", "")
        parsed.reply_to = msg.get("Reply-To", "")
        parsed.return_path = msg.get("Return-Path", "")
        parsed.date = msg.get("Date", "")
        parsed.x_mailer = msg.get("X-Mailer", "")
        parsed.content_type = msg.get("Content-Type", "")
        parsed.mime_version = msg.get("MIME-Version", "")
        parsed.dkim_signature = msg.get("DKIM-Signature", "")
        parsed.authentication_results = msg.get("Authentication-Results", "")
        parsed.arc_seal = msg.get("ARC-Seal", "")
        parsed.arc_message_signature = msg.get("ARC-Message-Signature", "")

        parsed.received_headers = EmailParser._extract_received(msg)
        parsed.raw_headers = EmailParser._extract_raw_headers(raw)
        parsed.body = EmailParser._extract_body(msg)

        return parsed

    @staticmethod
    def _extract_received(msg) -> list[str]:
        return msg.get_all("Received", [])

    @staticmethod
    def _extract_raw_headers(raw: bytes) -> str:
        try:
            split = raw.split(b"\r\n\r\n", 1)
            if len(split) == 2:
                return split[0].decode("utf-8", errors="replace")
            split = raw.split(b"\n\n", 1)
            if len(split) == 2:
                return split[0].decode("utf-8", errors="replace")
        except Exception:
            pass
        return ""

    @staticmethod
    def _extract_body(msg) -> str:
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                if ct == "text/plain":
                    payload = part.get_content()
                    if isinstance(payload, str):
                        body += payload
                elif ct == "text/html" and not body:
                    payload = part.get_content()
                    if isinstance(payload, str):
                        body += EmailParser._strip_html(payload)
        else:
            payload = msg.get_content()
            if isinstance(payload, str):
                if msg.get_content_type() == "text/html":
                    body = EmailParser._strip_html(payload)
                else:
                    body = payload
        return body.strip()

    @staticmethod
    def _strip_html(html: str) -> str:
        # Extract href URLs before stripping tags
        hrefs = re.findall(r'href=["\']([^"\']+)["\']', html)
        clean = re.sub(r"<[^>]+>", " ", html)
        clean = re.sub(r"\s+", " ", clean)
        result = clean.strip()
        # Append extracted URLs so they're available for analysis
        if hrefs:
            result += " URLs: " + " ".join(hrefs)
        return result
