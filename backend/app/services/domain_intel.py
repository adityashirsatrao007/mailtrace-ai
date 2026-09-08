from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import whois


@dataclass
class DomainIntel:
    domain: str = ""
    registrar: str = ""
    creation_date: str = ""
    expiration_date: str = ""
    domain_age_days: int = 0
    name_servers: list[str] = field(default_factory=list)
    registrant_org: str = ""
    registrant_country: str = ""
    dnssec: str = ""
    mx_records: list[str] = field(default_factory=list)
    a_records: list[str] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    is_suspicious: bool = False
    suspicion_reasons: list[str] = field(default_factory=list)


class DomainAnalyzer:
    """Analyze sender domain for registration intel and suspicious indicators."""

    SUSPICIOUS_TLDS = [".xyz", ".top", ".club", ".work", ".buzz", ".tk", ".ml",
                       ".ga", ".cf", ".gq", ".icu", ".vip", ".loan"]

    @staticmethod
    async def analyze(domain: str) -> DomainIntel:
        intel = DomainIntel(domain=domain)

        try:
            w = whois.whois(domain)
            intel.registrar = w.registrar or ""
            if w.creation_date:
                cd = w.creation_date
                if isinstance(cd, list):
                    cd = cd[0]
                if isinstance(cd, datetime):
                    intel.creation_date = cd.strftime("%Y-%m-%d")
                    intel.domain_age_days = (datetime.now() - cd).days
            if w.expiration_date:
                ed = w.expiration_date
                if isinstance(ed, list):
                    ed = ed[0]
                if isinstance(ed, datetime):
                    intel.expiration_date = ed.strftime("%Y-%m-%d")
            intel.name_servers = w.name_servers or []
            if isinstance(intel.name_servers, str):
                intel.name_servers = [intel.name_servers]
            intel.registrant_org = w.org or ""
            intel.registrant_country = w.country or ""
        except Exception:
            pass

        try:
            import dns.resolver
            try:
                answers = dns.resolver.resolve(domain, "MX")
                intel.mx_records = [str(r.exchange).rstrip(".") for r in answers]
            except Exception:
                pass
            try:
                answers = dns.resolver.resolve(domain, "A")
                intel.a_records = [str(r) for r in answers]
            except Exception:
                pass
            try:
                answers = dns.resolver.resolve(domain, "TXT")
                intel.txt_records = [str(r).strip('"') for r in answers]
            except Exception:
                pass
        except Exception:
            pass

        intel.is_suspicious, intel.suspicion_reasons = DomainAnalyzer._check_suspicion(intel)
        return intel

    @staticmethod
    def _check_suspicion(intel: DomainIntel) -> tuple[bool, list[str]]:
        reasons = []

        if intel.domain_age_days > 0 and intel.domain_age_days < 30:
            reasons.append(f"Domain registered only {intel.domain_age_days} days ago")

        tld = "." + intel.domain.split(".")[-1] if "." in intel.domain else ""
        if tld in DomainAnalyzer.SUSPICIOUS_TLDS:
            reasons.append(f"Suspicious TLD: {tld}")

        if not intel.mx_records:
            reasons.append("No MX records found")

        if not intel.registrar:
            reasons.append("WHOIS data hidden or unavailable")

        suspicious_registrars = ["whoisguard", "privacy", "redacted", "proxy"]
        if any(s in intel.registrar.lower() for s in suspicious_registrars):
            reasons.append("Privacy-protected registration")

        if intel.domain.count("-") > 2:
            reasons.append(f"Multiple hyphens in domain: {intel.domain}")

        if len(intel.domain) > 30:
            reasons.append("Unusually long domain name")

        return len(reasons) > 0, reasons

    @staticmethod
    def domain_count_hyphens(domain: str) -> int:
        return domain.count("-")
