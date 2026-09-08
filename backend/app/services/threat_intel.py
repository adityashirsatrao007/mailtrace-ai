"""
MailTrace AI — Advanced Threat Intelligence Services
Lookalike domain detection, display-name spoofing, URL redirect tracing, IoC extraction.
"""

from __future__ import annotations

import re
import Levenshtein
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import Optional

import httpx


# Known brand domains for lookalike detection
KNOWN_BRANDS = {
    "google.com": ["Google", "Gmail"],
    "microsoft.com": ["Microsoft", "Outlook", "Hotmail", "Office365"],
    "apple.com": ["Apple", "iCloud"],
    "amazon.com": ["Amazon", "AWS"],
    "facebook.com": ["Facebook", "Meta"],
    "instagram.com": ["Instagram"],
    "linkedin.com": ["LinkedIn"],
    "netflix.com": ["Netflix"],
    "paypal.com": ["PayPal"],
    "twitter.com": ["Twitter", "X"],
    "github.com": ["GitHub"],
    "dropbox.com": ["Dropbox"],
    "yahoo.com": ["Yahoo"],
    "icloud.com": ["iCloud"],
    "outlook.com": ["Outlook"],
    "live.com": ["Live", "Microsoft"],
    "protonmail.com": ["ProtonMail"],
    "proton.me": ["Proton"],
    "sbi.co.in": ["SBI", "State Bank of India"],
    "hdfcbank.com": ["HDFC"],
    "icicibank.com": ["ICICI"],
    "bankofamerica.com": ["Bank of America"],
    "wellsfargo.com": ["Wells Fargo"],
    "chase.com": ["Chase", "JPMorgan"],
}

# Common typosquatting patterns
HOMOGLYPH_MAP = {
    "a": ["а", "ạ", "à", "á", "â"],  # Cyrillic a
    "e": ["е", "ё", "ε", "ē"],  # Cyrillic e
    "o": ["ο", "о", "ö", "0"],  # Cyrillic o, zero
    "i": ["і", "1", "l", "!"],  # Cyrillic i, one, l
    "l": ["1", "i", "|"],
    "c": ["с", "ϲ"],  # Cyrillic c
    "p": ["р", "ρ"],  # Cyrillic p
    "x": ["х", "×"],
    "y": ["у", "ý"],
    "s": ["ѕ", "5"],
    "n": ["ñ", "ń"],
}


@dataclass
class LookalikeResult:
    is_lookalike: bool = False
    target_brand: str = ""
    target_domain: str = ""
    edit_distance: int = 0
    technique: str = ""  # homoglyph, typosquat, subdomain, tld_swap, combo
    confidence: float = 0.0
    details: str = ""


@dataclass
class DisplaySpoofResult:
    is_spoofed: bool = False
    display_name: str = ""
    envelope_sender: str = ""
    display_domain: str = ""
    mismatch_type: str = ""  # display_vs_envelope, reply_to_mismatch, return_path_mismatch
    confidence: float = 0.0
    details: str = ""


@dataclass
class URLTraceResult:
    original_url: str = ""
    final_url: str = ""
    redirect_chain: list[str] = field(default_factory=list)
    total_redirects: int = 0
    is_suspicious: bool = False
    suspicion_reasons: list[str] = field(default_factory=list)
    url_shortener: bool = False
    ip_url: bool = False
    https_downgrade: bool = False


@dataclass
class IoCItem:
    type: str = ""  # ip, domain, url, hash, email
    value: str = ""
    context: str = ""
    confidence: float = 0.0


class ThreatIntelligence:
    """Advanced threat intelligence: lookalike domains, display spoofing, URL tracing, IoCs."""

    @staticmethod
    def check_lookalike_domain(domain: str) -> LookalikeResult:
        """Check if a domain is a lookalike of a known brand."""
        result = LookalikeResult()
        domain_lower = domain.lower().strip(".")

        for brand_domain, brand_names in KNOWN_BRANDS.items():
            # Check exact match first
            if domain_lower == brand_domain:
                return result  # Not a lookalike, it IS the brand

            # 1. Subdomain abuse: paypal.evil.com
            if domain_lower.endswith("." + brand_domain):
                result.is_lookalike = True
                result.target_brand = brand_names[0]
                result.target_domain = brand_domain
                result.technique = "subdomain_abuse"
                result.confidence = 0.95
                result.details = f"Domain uses {brand_domain} as subdomain: {domain}"
                return result

            # 2. TLD swap: google.ru, paypal.xyz
            base = domain_lower.rsplit(".", 1)[0] if "." in domain_lower else domain_lower
            brand_base = brand_domain.rsplit(".", 1)[0]
            if base == brand_base and domain_lower != brand_domain:
                result.is_lookalike = True
                result.target_brand = brand_names[0]
                result.target_domain = brand_domain
                result.technique = "tld_swap"
                result.confidence = 0.90
                result.details = f"Same name, different TLD: {domain} vs {brand_domain}"
                return result

            # 3. Homoglyph detection (Cyrillic, etc.)
            for char in domain_lower:
                for latin, homoglyphs in HOMOGLYPH_MAP.items():
                    if char in homoglyphs:
                        # Check if replacing this char would match a brand
                        fixed = domain_lower.replace(char, latin)
                        dist = Levenshtein.distance(fixed, brand_domain)
                        if dist <= 2:
                            result.is_lookalike = True
                            result.target_brand = brand_names[0]
                            result.target_domain = brand_domain
                            result.edit_distance = dist
                            result.technique = "homoglyph"
                            result.confidence = 0.85
                            result.details = f"Uses homoglyph '{char}' (resembles '{latin}'), distance={dist}"
                            return result

            # 4. Typosquatting (edit distance)
            dist = Levenshtein.distance(domain_lower, brand_domain)
            if 0 < dist <= 2 and len(domain_lower) > 3:
                result.is_lookalike = True
                result.target_brand = brand_names[0]
                result.target_domain = brand_domain
                result.edit_distance = dist
                result.technique = "typosquat"
                result.confidence = max(0.6, 0.95 - dist * 0.15)
                result.details = f"Edit distance {dist} from {brand_domain}"
                return result

            # 5. Combo domains: google-verify.com, paypal-secure.xyz
            for separator in ["-", "_", "."]:
                parts = domain_lower.split(separator)
                if len(parts) > 1:
                    for part in parts:
                        if Levenshtein.distance(part, brand_base) <= 1 and part != brand_base:
                            result.is_lookalike = True
                            result.target_brand = brand_names[0]
                            result.target_domain = brand_domain
                            result.edit_distance = Levenshtein.distance(part, brand_base)
                            result.technique = "combo_domain"
                            result.confidence = 0.75
                            result.details = f"Contains brand name '{part}' with separator in {domain}"
                            return result

            # 6. Brand name as prefix/suffix: paypal-secure.com, microsoft-login.xyz
            if brand_base in domain_lower and domain_lower != brand_domain:
                suffix_after_brand = domain_lower.split(brand_base, 1)[-1]
                if suffix_after_brand and suffix_after_brand[0] in "-_":
                    result.is_lookalike = True
                    result.target_brand = brand_names[0]
                    result.target_domain = brand_domain
                    result.technique = "combo_domain"
                    result.confidence = 0.85
                    result.details = f"Domain contains brand '{brand_base}' with appended text: {domain}"
                    return result

        return result

    @staticmethod
    def check_display_spoofing(from_header: str, reply_to: str = "", return_path: str = "") -> DisplaySpoofResult:
        """Check for display-name vs envelope-sender mismatch."""
        result = DisplaySpoofResult()

        # Parse display name and email from From header
        # Format: "Display Name <email@domain.com>" or just "email@domain.com"
        display_match = re.match(r'^"?([^"<]+)"?\s*<([^>]+)>', from_header)
        if display_match:
            result.display_name = display_match.group(1).strip()
            result.envelope_sender = display_match.group(2).strip()
        else:
            result.envelope_sender = from_header.strip()
            return result  # No display name to compare

        # Extract domain from display name (if it looks like an email)
        display_email_match = re.search(r'[\w.-]+@[\w.-]+\.\w+', result.display_name)
        if display_email_match:
            result.display_domain = display_email_match.group(0).split("@")[-1]
            envelope_domain = result.envelope_sender.split("@")[-1] if "@" in result.envelope_sender else ""

            if result.display_domain.lower() != envelope_domain.lower():
                result.is_spoofed = True
                result.mismatch_type = "display_vs_envelope"
                result.confidence = 0.90
                result.details = f"Display email domain ({result.display_domain}) differs from envelope ({envelope_domain})"
                return result

        # Check if display name contains a brand but sender domain differs
        display_lower = result.display_name.lower()
        for brand_domain, brand_names in KNOWN_BRANDS.items():
            brand_base = brand_domain.split(".")[0].lower()
            for name in brand_names + [brand_base]:
                if name.lower() in display_lower:
                    envelope_domain = result.envelope_sender.split("@")[-1].lower() if "@" in result.envelope_sender else ""
                    if brand_base not in envelope_domain and brand_domain != envelope_domain:
                        result.is_spoofed = True
                        result.mismatch_type = "display_vs_envelope"
                        result.confidence = 0.85
                        result.details = f"Display name mentions '{name}' but sender is from {envelope_domain}"
                        return result

        # Check Reply-To mismatch
        if reply_to:
            reply_domain = reply_to.split("@")[-1].lower() if "@" in reply_to else ""
            sender_domain = result.envelope_sender.split("@")[-1].lower() if "@" in result.envelope_sender else ""
            if reply_domain and sender_domain and reply_domain != sender_domain:
                result.is_spoofed = True
                result.mismatch_type = "reply_to_mismatch"
                result.confidence = 0.70
                result.details = f"Reply-To domain ({reply_domain}) differs from sender ({sender_domain})"
                return result

        # Check Return-Path mismatch
        if return_path:
            rp_domain = return_path.strip("<>").split("@")[-1].lower() if "@" in return_path else ""
            sender_domain = result.envelope_sender.split("@")[-1].lower() if "@" in result.envelope_sender else ""
            if rp_domain and sender_domain and rp_domain != sender_domain:
                result.is_spoofed = True
                result.mismatch_type = "return_path_mismatch"
                result.confidence = 0.65
                result.details = f"Return-Path domain ({rp_domain}) differs from sender ({sender_domain})"
                return result

        return result

    @staticmethod
    async def trace_url_redirects(url: str, max_redirects: int = 5) -> URLTraceResult:
        """Follow URL redirect chain and detect suspicious patterns."""
        result = URLTraceResult(original_url=url)
        parsed = urlparse(url)

        # Check if URL is an IP address
        ip_match = re.match(r'^https?://(\d{1,3}\.){3}\d{1,3}', url)
        if ip_match:
            result.ip_url = True
            result.is_suspicious = True
            result.suspicion_reasons.append("URL uses raw IP address instead of domain")

        # Check for URL shorteners
        shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
                      "buff.ly", "adf.ly", "bit.do", "rb.gy", "cutt.ly", "shorturl.at"]
        if any(s in parsed.netloc.lower() for s in shorteners):
            result.url_shortener = True
            result.is_suspicious = True
            result.suspicion_reasons.append("Uses URL shortener (common in phishing)")

        # Check for HTTP downgrade
        if url.startswith("http://") and not url.startswith("https://"):
            result.https_downgrade = True
            result.is_suspicious = True
            result.suspicion_reasons.append("Uses HTTP instead of HTTPS")

        # Follow redirects
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                max_redirects=max_redirects,
                timeout=10.0,
                verify=False,
            ) as client:
                resp = await client.get(url)
                result.final_url = str(resp.url)

                # Build redirect chain
                if resp.history:
                    result.redirect_chain = [str(r.url) for r in resp.history]
                    result.total_redirects = len(resp.history)

                # Check for redirect to different domain
                orig_domain = parsed.netloc.lower()
                final_domain = urlparse(result.final_url).netloc.lower()
                if orig_domain != final_domain and result.total_redirects > 0:
                    result.is_suspicious = True
                    result.suspicion_reasons.append(
                        f"Redirects from {orig_domain} to {final_domain}"
                    )

                # Check for data: URI or javascript: URI
                if result.final_url.startswith("data:") or result.final_url.startswith("javascript:"):
                    result.is_suspicious = True
                    result.suspicion_reasons.append("Final URL is a data: or javascript: URI")

        except (httpx.RequestError, httpx.TooManyRedirects, Exception) as e:
            result.is_suspicious = True
            result.suspicion_reasons.append(f"URL request failed: {type(e).__name__}")

        return result

    @staticmethod
    def extract_iocs(
        parsed_email, headers, geo_result=None, domain_intel=None, relay_path=None
    ) -> list[IoCItem]:
        """Extract all Indicators of Compromise from the email analysis."""
        iocs = []

        # Sender email
        if parsed_email.from_addr:
            iocs.append(IoCItem(
                type="email",
                value=parsed_email.from_addr,
                context="Sender address",
                confidence=1.0,
            ))

        # Sender domain
        if parsed_email.from_addr and "@" in parsed_email.from_addr:
            domain = parsed_email.from_addr.split("@")[-1]
            iocs.append(IoCItem(
                type="domain",
                value=domain,
                context="Sender domain",
                confidence=1.0,
            ))

        # IPs from relay path
        if relay_path:
            for hop in relay_path:
                ip = hop.get("ip")
                if ip:
                    iocs.append(IoCItem(
                        type="ip",
                        value=ip,
                        context=f"Relay hop: {hop.get('from_host', '?')} → {hop.get('by_host', '?')}",
                        confidence=0.9,
                    ))

        # URLs in email body
        if hasattr(parsed_email, 'body') and parsed_email.body:
            url_pattern = re.compile(r'https?://[^\s<>"\']+')
            urls = url_pattern.findall(parsed_email.body)
            for url in set(urls):
                iocs.append(IoCItem(
                    type="url",
                    value=url,
                    context="URL found in email body",
                    confidence=0.8,
                ))

        # URLs in headers (e.g., Message-ID, X-URI)
        raw = parsed_email.raw_headers or ""
        if isinstance(raw, str):
            urls = re.findall(r'https?://[^\s<>"]+', raw)
            for url in set(urls):
                iocs.append(IoCItem(
                    type="url",
                    value=url,
                    context="URL found in email headers",
                    confidence=0.6,
                ))

        # Attachment filenames (if any)
        if hasattr(parsed_email, 'attachments') and parsed_email.attachments:
            for att in parsed_email.attachments:
                iocs.append(IoCItem(
                    type="file",
                    value=att.get("filename", "unknown"),
                    context=f"Attachment ({att.get('content_type', 'unknown')})",
                    confidence=0.7,
                ))

        # Geo IP
        if geo_result and geo_result.ip:
            iocs.append(IoCItem(
                type="ip",
                value=geo_result.ip,
                context=f"Origin IP ({geo_result.country}, {geo_result.isp})",
                confidence=0.85,
            ))

        # Suspicious domain from domain intel
        if domain_intel and domain_intel.is_suspicious:
            for reason in (domain_intel.suspicion_reasons or []):
                iocs.append(IoCItem(
                    type="domain",
                    value=parsed_email.from_addr.split("@")[-1] if "@" in parsed_email.from_addr else "",
                    context=f"Suspicious: {reason}",
                    confidence=0.8,
                ))

        return iocs
