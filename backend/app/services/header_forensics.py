from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

import dns.resolver


@dataclass
class HeaderAnalysis:
    spf_result: str = "none"
    spf_detail: str = ""
    dkim_result: str = "none"
    dkim_detail: str = ""
    dmarc_result: str = "none"
    dmarc_detail: str = ""
    relay_path: list[dict] = field(default_factory=list)
    earliest_reliable_ip: str = ""
    sender_domain: str = ""
    reply_to_mismatch: bool = False
    return_path_mismatch: bool = False
    anomalies: list[str] = field(default_factory=list)
    risk_score: float = 0.0


class HeaderForensics:
    """Analyze email headers for authentication results, relay path, and anomalies."""

    @staticmethod
    def analyze(parsed_email) -> HeaderAnalysis:
        analysis = HeaderAnalysis()
        headers = parsed_email.raw_headers

        analysis.sender_domain = HeaderForensics._extract_domain(parsed_email.from_addr)
        analysis.spf_result, analysis.spf_detail = HeaderForensics._check_spf(headers)
        analysis.dkim_result, analysis.dkim_detail = HeaderForensics._check_dkim(headers)
        analysis.dmarc_result, analysis.dmarc_detail = HeaderForensics._check_dmarc(headers)
        analysis.relay_path = HeaderForensics._trace_relay(parsed_email.received_headers)
        analysis.earliest_reliable_ip = HeaderForensics._find_earliest_ip(analysis.relay_path)

        analysis.reply_to_mismatch = HeaderForensics._check_reply_to_mismatch(
            parsed_email.from_addr, parsed_email.reply_to
        )
        analysis.return_path_mismatch = HeaderForensics._check_return_path_mismatch(
            parsed_email.from_addr, parsed_email.return_path
        )

        analysis.anomalies = HeaderForensics._detect_anomalies(
            parsed_email, analysis
        )
        analysis.risk_score = HeaderForensics._compute_risk_score(analysis)

        return analysis

    @staticmethod
    def _extract_domain(addr: str) -> str:
        match = re.search(r"@([\w.-]+)", addr)
        return match.group(1) if match else ""

    @staticmethod
    def _check_spf(headers: str) -> tuple[str, str]:
        match = re.search(
            r"spf=(\w+).*?([^\s;]+(?:\s+[^\s;]+)*)", headers, re.IGNORECASE
        )
        if match:
            return match.group(1).lower(), match.group(0).strip()
        for line in headers.split("\n"):
            if "spf=" in line.lower():
                val = re.search(r"spf=(\w+)", line, re.IGNORECASE)
                if val:
                    return val.group(1).lower(), line.strip()
        return "none", "SPF record not found in headers"

    @staticmethod
    def _check_dkim(headers: str) -> tuple[str, str]:
        match = re.search(r"dkim=(\w+)\s+.*?header\.i=([^\s;]+)", headers, re.IGNORECASE)
        if match:
            return match.group(1).lower(), match.group(0).strip()
        for line in headers.split("\n"):
            if "dkim=" in line.lower():
                val = re.search(r"dkim=(\w+)", line, re.IGNORECASE)
                if val:
                    return val.group(1).lower(), line.strip()
        return "none", "DKIM signature not found"

    @staticmethod
    def _check_dmarc(headers: str) -> tuple[str, str]:
        match = re.search(r"dmarc=(\w+)", headers, re.IGNORECASE)
        if match:
            return match.group(1).lower(), match.group(0).strip()
        return "none", "DMARC result not found in headers"

    @staticmethod
    def _trace_relay(received_headers: list[str]) -> list[dict]:
        relay_path = []
        for header in reversed(received_headers):
            entry = {"raw": header}
            ip_match = re.search(r"\[(\d+\.\d+\.\d+\.\d+)\]", header)
            if ip_match:
                entry["ip"] = ip_match.group(1)
            from_match = re.search(r"from\s+([\w.-]+)", header)
            if from_match:
                entry["from_host"] = from_match.group(1)
            by_match = re.search(r"by\s+([\w.-]+)", header)
            if by_match:
                entry["by_host"] = by_match.group(1)
            with_match = re.search(r"with\s+(\w+)", header)
            if with_match:
                entry["protocol"] = with_match.group(1)
            date_match = re.search(
                r";\s*(\w{3},?\s+\d{1,2}\s+\w{3}\s+\d{4}\s+[\d:]+\s+[^\s]+)", header
            )
            if date_match:
                entry["timestamp"] = date_match.group(1)
            relay_path.append(entry)
        return relay_path

    @staticmethod
    def _find_earliest_ip(relay_path: list[dict]) -> str:
        for entry in relay_path:
            if "ip" in entry:
                return entry["ip"]
        return ""

    @staticmethod
    def _check_reply_to_mismatch(from_addr: str, reply_to: str) -> bool:
        if not reply_to:
            return False
        from_domain = HeaderForensics._extract_domain(from_addr)
        reply_domain = HeaderForensics._extract_domain(reply_to)
        return from_domain != reply_domain and from_domain != "" and reply_domain != ""

    @staticmethod
    def _check_return_path_mismatch(from_addr: str, return_path: str) -> bool:
        if not return_path or return_path == "<>":
            return True
        from_domain = HeaderForensics._extract_domain(from_addr)
        rp_domain = HeaderForensics._extract_domain(return_path)
        return from_domain != rp_domain and from_domain != "" and rp_domain != ""

    @staticmethod
    def _detect_anomalies(parsed_email, analysis: HeaderAnalysis) -> list[str]:
        anomalies = []

        if analysis.spf_result in ("fail", "softfail"):
            anomalies.append(f"SPF check failed: {analysis.spf_detail}")
        if analysis.dkim_result in ("fail", "none"):
            anomalies.append(f"DKIM check failed: {analysis.dkim_detail}")
        if analysis.dmarc_result in ("fail", "reject", "none"):
            anomalies.append(f"DMARC check failed or missing: {analysis.dmarc_detail}")
        if analysis.reply_to_mismatch:
            anomalies.append(
                f"Reply-To domain differs from From domain (possible spoofing)"
            )
        if analysis.return_path_mismatch:
            anomalies.append("Return-Path mismatches From address")
        if len(parsed_email.received_headers) > 8:
            anomalies.append(
                f"Unusual relay chain length: {len(parsed_email.received_headers)} hops"
            )
        if parsed_email.x_mailer and any(
            s in parsed_email.x_mailer.lower()
            for s in ["php", "python", "perl", "ruby", "bulk"]
        ):
            anomalies.append(f"Suspicious X-Mailer: {parsed_email.x_mailer}")

        subject = parsed_email.subject.lower()
        urgent_words = ["urgent", "immediate", "verify", "account", "suspended",
                        "locked", "security alert", "unauthorized", "act now",
                        "confirm your", "update your"]
        if any(w in subject for w in urgent_words):
            anomalies.append("Subject contains urgency/social engineering cues")

        body = parsed_email.body.lower()
        if any(w in body for w in ["click here", "verify your account", "confirm identity",
                                    "update payment", "unusual activity"]):
            anomalies.append("Body contains phishing indicators")

        url_count = len(re.findall(r"https?://[^\s<>\"']+", parsed_email.body))
        if url_count > 5:
            anomalies.append(f"High URL count in body: {url_count}")

        return anomalies

    @staticmethod
    def _compute_risk_score(analysis: HeaderAnalysis) -> float:
        score = 0.0
        if analysis.spf_result == "fail":
            score += 25
        elif analysis.spf_result == "softfail":
            score += 10
        if analysis.dkim_result == "fail":
            score += 25
        elif analysis.dkim_result == "none":
            score += 15
        if analysis.dmarc_result == "fail":
            score += 20
        elif analysis.dmarc_result == "none":
            score += 10
        if analysis.reply_to_mismatch:
            score += 10
        if analysis.return_path_mismatch:
            score += 10
        score += min(len(analysis.anomalies) * 3, 30)
        return min(score, 100.0)
