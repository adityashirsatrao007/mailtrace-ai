from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ForensicReport:
    report_id: str = ""
    email_subject: str = ""
    email_from: str = ""
    email_to: str = ""
    date_analyzed: str = ""
    threat_level: str = "LOW"
    threat_score: float = 0.0
    classification: str = "legitimate"
    classification_confidence: float = 0.0
    spf_result: str = ""
    dkim_result: str = ""
    dmarc_result: str = ""
    anomalies: list[str] = field(default_factory=list)
    relay_path: list[dict] = field(default_factory=list)
    origin_ip: str = ""
    origin_country: str = ""
    origin_city: str = ""
    origin_isp: str = ""
    is_vpn: bool = False
    is_tor: bool = False
    domain_age_days: int = 0
    domain_registrar: str = ""
    domain_suspicious: bool = False
    domain_suspicion_reasons: list[str] = field(default_factory=list)
    graph_nodes: list[dict] = field(default_factory=list)
    graph_edges: list[dict] = field(default_factory=list)
    attribution_confidence: float = 0.0
    recommendations: list[str] = field(default_factory=list)
    executive_summary: str = ""


class ReportGenerator:
    """Generate structured forensic reports for email threat analysis."""

    @staticmethod
    def generate(
        parsed_email,
        header_analysis,
        classification,
        geo_result,
        domain_intel,
        correlation,
    ) -> ForensicReport:
        report = ForensicReport()

        import uuid
        from datetime import datetime

        report.report_id = f"MT-{uuid.uuid4().hex[:8].upper()}"
        report.email_subject = parsed_email.subject
        report.email_from = parsed_email.from_addr
        report.email_to = parsed_email.to_addr
        report.date_analyzed = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

        report.threat_score = classification.confidence * 100

        # Adjust score based on email authentication results
        spf = header_analysis.spf_result.lower()
        dkim = header_analysis.dkim_result.lower()
        dmarc = header_analysis.dmarc_result.lower()

        auth_pass = sum(1 for r in [spf, dkim, dmarc] if r == "pass")
        auth_fail = sum(1 for r in [spf, dkim, dmarc] if r == "fail")

        if auth_pass == 3:
            report.threat_score *= 0.50
        elif auth_pass == 2:
            report.threat_score *= 0.65
        elif auth_pass == 1:
            report.threat_score *= 0.80
        elif auth_fail >= 2:
            report.threat_score = min(100, report.threat_score * 1.15)

        report.threat_score = max(0, min(100, report.threat_score))

        # Domain intelligence adjustments
        if domain_intel.is_suspicious:
            report.threat_score = min(100, report.threat_score * 1.20)
        if domain_intel.domain_age_days is not None and domain_intel.domain_age_days < 30:
            report.threat_score = min(100, report.threat_score * 1.10)

        report.threat_score = round(max(0, min(100, report.threat_score)), 1)

        if report.threat_score >= 70:
            report.threat_level = "CRITICAL"
        elif report.threat_score >= 50:
            report.threat_level = "HIGH"
        elif report.threat_score >= 30:
            report.threat_level = "MEDIUM"
        else:
            report.threat_level = "LOW"

        report.classification = classification.label
        report.classification_confidence = classification.confidence

        report.spf_result = header_analysis.spf_result
        report.dkim_result = header_analysis.dkim_result
        report.dmarc_result = header_analysis.dmarc_result
        report.anomalies = header_analysis.anomalies
        report.relay_path = header_analysis.relay_path

        report.origin_ip = geo_result.ip
        report.origin_country = geo_result.country
        report.origin_city = geo_result.city
        report.origin_isp = geo_result.isp
        report.is_vpn = geo_result.is_vpn
        report.is_tor = geo_result.is_tor

        report.domain_age_days = domain_intel.domain_age_days
        report.domain_registrar = domain_intel.registrar
        report.domain_suspicious = domain_intel.is_suspicious
        report.domain_suspicion_reasons = domain_intel.suspicion_reasons

        report.graph_nodes = correlation.graph_nodes
        report.graph_edges = correlation.graph_edges
        report.attribution_confidence = correlation.attribution_confidence

        report.recommendations = ReportGenerator._generate_recommendations(
            report, header_analysis, classification
        )
        report.executive_summary = ReportGenerator._generate_summary(report)

        return report

    @staticmethod
    def _generate_recommendations(
        report, header_analysis, classification
    ) -> list[str]:
        recs = []

        if classification.label in ("phishing", "business_email_compromise"):
            recs.append("BLOCK this email immediately and quarantine similar messages")
            recs.append("Report to CERT-In (cert-in.org.in) for national threat intelligence")
            recs.append("Alert all users in the organization about this threat pattern")

        if header_analysis.spf_result == "fail":
            recs.append("SPF authentication failed — sender infrastructure is likely spoofed")
        if header_analysis.dkim_result == "fail":
            recs.append("DKIM signature invalid or missing — email integrity cannot be verified")
        if header_analysis.dmarc_result == "fail":
            recs.append("DMARC policy violation — domain owner has not authorized this sender")

        if report.is_vpn:
            recs.append("Sender is using VPN infrastructure — origin location may be masked")
        if report.is_tor:
            recs.append("Sender is using TOR network — origin is anonymized")

        if report.domain_suspicious:
            recs.append(f"Suspicious domain: {'; '.join(report.domain_suspicion_reasons)}")

        if report.domain_age_days > 0 and report.domain_age_days < 30:
            recs.append(
                f"Domain is only {report.domain_age_days} days old — high risk of being a throwaway domain"
            )

        if header_analysis.reply_to_mismatch:
            recs.append("Reply-To address differs from From — common in BEC attacks")

        if not recs:
            recs.append("No critical issues detected — email appears legitimate")

        return recs

    @staticmethod
    def _generate_summary(report) -> str:
        if report.threat_level == "CRITICAL":
            return (
                f"This email classified as {report.classification} with {report.threat_score:.0f}% confidence. "
                f"Origin traced to {report.origin_ip} ({report.origin_city}, {report.origin_country}) "
                f"via {report.origin_isp}. Domain {report.email_from.split('@')[-1] if '@' in report.email_from else 'unknown'} "
                f"is {report.domain_age_days} days old. "
                f"{len(report.anomalies)} anomalies detected. IMMEDIATE ACTION REQUIRED."
            )
        elif report.threat_level == "HIGH":
            return (
                f"This email shows strong indicators of {report.classification} "
                f"({report.threat_score:.0f}% confidence). "
                f"Authentication failures: SPF={report.spf_result}, DKIM={report.dkim_result}, "
                f"DMARC={report.dmarc_result}. Origin: {report.origin_ip} ({report.origin_country}). "
                f"Recommend quarantine and investigation."
            )
        elif report.threat_level == "MEDIUM":
            return (
                f"This email shows moderate risk ({report.threat_score:.0f}% confidence) "
                f"with {len(report.anomalies)} anomalies. "
                f"Review recommended before user interaction."
            )
        else:
            return (
                f"This email appears legitimate ({report.threat_score:.0f}% risk score). "
                f"Authentication passed. No significant anomalies detected."
            )
