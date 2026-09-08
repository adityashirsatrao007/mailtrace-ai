"""
Real-Time Email Forwarding Pipeline.
Users forward suspicious emails to scan@mailtrace.ai → auto-analyze → alert.
Supports IMAP monitoring and webhook-based forwarding.
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
from datetime import datetime
from typing import Optional


DB_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "data", "mailtrace.db")


class EmailPipeline:
    """Real-time email monitoring and auto-analysis pipeline."""

    def __init__(self):
        self._init_db()

    def _init_db(self):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_from TEXT,
                email_to TEXT,
                subject TEXT,
                threat_level TEXT,
                threat_score REAL,
                classification TEXT,
                origin_ip TEXT,
                origin_country TEXT,
                analyzed_at TEXT,
                user_verdict TEXT DEFAULT 'pending',
                raw_email TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                verdict TEXT,
                timestamp TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS threat_intel (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator_type TEXT,
                indicator_value TEXT,
                threat_type TEXT,
                confidence REAL,
                first_seen TEXT,
                last_seen TEXT,
                hit_count INTEGER DEFAULT 1,
                UNIQUE(indicator_type, indicator_value)
            )
        """)
        conn.commit()
        conn.close()

    async def process_forwarded_email(self, raw_email: bytes) -> dict:
        """Process a forwarded email through the full analysis pipeline."""
        from app.services.email_parser import EmailParser
        from app.services.header_forensics import HeaderForensics
        from app.services.geolocation import GeoLocator, GeoResult
        from app.services.domain_intel import DomainAnalyzer, DomainIntel
        from app.services.graph_correlator import GraphCorrelator
        from app.services.report_generator import ReportGenerator
        from app.services.llm_narrator import ThreatNarrator
        from app.services.threat_intel import ThreatIntelligence
        from app.ml.classifier import PhishingClassifier

        classifier = PhishingClassifier()
        correlator = GraphCorrelator()

        parsed = EmailParser.parse(raw_email)
        headers = HeaderForensics.analyze(parsed)
        classification = classifier.classify(parsed, headers)

        earliest_ip = headers.earliest_reliable_ip
        geo = await GeoLocator.locate(earliest_ip) if earliest_ip else GeoResult()

        domain = headers.sender_domain
        domain_intel = await DomainAnalyzer.analyze(domain) if domain else DomainIntel()

        # === NEW: Advanced Threat Intelligence ===

        # 1. Lookalike domain detection
        lookalike = ThreatIntelligence.check_lookalike_domain(domain) if domain else None

        # 2. Display-name spoofing detection
        display_spoof = ThreatIntelligence.check_display_spoofing(
            parsed.from_addr, parsed.reply_to, parsed.return_path
        )

        # 3. Enrich relay path with ASN + geo per hop
        enriched_relay = []
        for hop in headers.relay_path:
            hop_ip = hop.get("ip")
            hop_geo = await GeoLocator.locate(hop_ip) if hop_ip else None
            enriched_hop = {
                **hop,
                "country": hop_geo.country if hop_geo else "",
                "city": hop_geo.city if hop_geo else "",
                "isp": hop_geo.isp if hop_geo else "",
                "asn": hop_geo.as_number if hop_geo else "",
                "hosting_provider": hop_geo.hosting_provider if hop_geo else "",
                "is_vpn": hop_geo.is_vpn if hop_geo else False,
                "is_tor": hop_geo.is_tor if hop_geo else False,
                "latitude": hop_geo.latitude if hop_geo else 0.0,
                "longitude": hop_geo.longitude if hop_geo else 0.0,
            }
            enriched_relay.append(enriched_hop)

        # 4. URL redirect tracing (check first 5 URLs in body)
        url_traces = []
        if hasattr(parsed, 'body') and parsed.body:
            import re as _re
            urls = _re.findall(r'https?://[^\s<>"\']+', parsed.body)[:5]
            for url in urls:
                trace = await ThreatIntelligence.trace_url_redirects(url)
                url_traces.append(trace)

        # 5. IoC extraction
        iocs = ThreatIntelligence.extract_iocs(
            parsed, headers, geo, domain_intel, enriched_relay
        )

        correlation = correlator.correlate(parsed, headers, geo, domain_intel)
        report = ReportGenerator.generate(parsed, headers, classification, geo, domain_intel, correlation)

        # Override relay path with enriched version
        report.relay_path = enriched_relay

        result = {
            "report_id": report.report_id,
            "threat_level": report.threat_level,
            "threat_score": report.threat_score,
            "classification": report.classification,
            "confidence": report.classification_confidence,
            "email": {"subject": report.email_subject, "from": report.email_from, "to": report.email_to},
            "authentication": {"spf": report.spf_result, "dkim": report.dkim_result, "dmarc": report.dmarc_result},
            "origin": {
                "ip": report.origin_ip, "country": report.origin_country,
                "city": report.origin_city, "isp": report.origin_isp,
                "is_vpn": geo.is_vpn, "is_tor": geo.is_tor,
                "latitude": geo.latitude, "longitude": geo.longitude,
                "asn": geo.as_number, "hosting_provider": geo.hosting_provider,
            },
            "domain": {
                "age_days": report.domain_age_days, "registrar": report.domain_registrar,
                "is_suspicious": report.domain_suspicious,
                "suspicion_reasons": report.domain_suspicion_reasons,
            },
            "anomalies": report.anomalies,
            "relay_path": enriched_relay,
            "graph": {"nodes": report.graph_nodes, "edges": report.graph_edges},
            "attribution_confidence": report.attribution_confidence,
            "recommendations": report.recommendations,
            "executive_summary": report.executive_summary,
            # NEW FEATURES
            "lookalike": {
                "is_lookalike": lookalike.is_lookalike if lookalike else False,
                "target_brand": lookalike.target_brand if lookalike else "",
                "target_domain": lookalike.target_domain if lookalike else "",
                "technique": lookalike.technique if lookalike else "",
                "edit_distance": lookalike.edit_distance if lookalike else 0,
                "confidence": lookalike.confidence if lookalike else 0.0,
                "details": lookalike.details if lookalike else "",
            } if lookalike else None,
            "display_spoof": {
                "is_spoofed": display_spoof.is_spoofed,
                "display_name": display_spoof.display_name,
                "envelope_sender": display_spoof.envelope_sender,
                "mismatch_type": display_spoof.mismatch_type,
                "confidence": display_spoof.confidence,
                "details": display_spoof.details,
            },
            "url_traces": [
                {
                    "original": t.original_url,
                    "final": t.final_url,
                    "redirects": t.total_redirects,
                    "chain": t.redirect_chain,
                    "is_suspicious": t.is_suspicious,
                    "reasons": t.suspicion_reasons,
                    "url_shortener": t.url_shortener,
                    "ip_url": t.ip_url,
                } for t in url_traces
            ],
            "iocs": [
                {"type": i.type, "value": i.value, "context": i.context, "confidence": i.confidence}
                for i in iocs
            ],
        }

        narrative = await ThreatNarrator.generate_narrative(result)
        result["ai_narrative"] = narrative

        self._store_scan(result, raw_email.decode("utf-8", errors="replace"))
        self._update_threat_intel(result)

        return result

    def _store_scan(self, result: dict, raw_email: str):
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            """INSERT INTO scans
            (email_from, email_to, subject, threat_level, threat_score,
             classification, origin_ip, origin_country, analyzed_at, raw_email)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                result["email"]["from"],
                result["email"]["to"],
                result["email"]["subject"],
                result["threat_level"],
                result["threat_score"],
                result["classification"],
                result["origin"]["ip"],
                result["origin"]["country"],
                result.get("analyzed_at", datetime.now().isoformat()),
                raw_email,
            ),
        )
        conn.commit()
        conn.close()

    def _update_threat_intel(self, result: dict):
        conn = sqlite3.connect(DB_PATH)

        if result["origin"]["ip"]:
            conn.execute(
                """INSERT INTO threat_intel (indicator_type, indicator_value, threat_type, confidence, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(indicator_type, indicator_value) DO UPDATE SET
                hit_count = hit_count + 1, last_seen = excluded.last_seen, confidence = MAX(confidence, excluded.confidence)""",
                (
                    "ip", result["origin"]["ip"], result["classification"],
                    result["confidence"], datetime.now().isoformat(), datetime.now().isoformat(),
                ),
            )

        sender = result["email"]["from"]
        if "@" in sender:
            domain = sender.split("@")[-1]
            conn.execute(
                """INSERT INTO threat_intel (indicator_type, indicator_value, threat_type, confidence, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(indicator_type, indicator_value) DO UPDATE SET
                hit_count = hit_count + 1, last_seen = excluded.last_seen, confidence = MAX(confidence, excluded.confidence)""",
                (
                    "domain", domain, result["classification"],
                    result["confidence"], datetime.now().isoformat(), datetime.now().isoformat(),
                ),
            )

        conn.commit()
        conn.close()

    def record_feedback(self, scan_id: int, verdict: str):
        conn = sqlite3.connect(DB_PATH)
        conn.execute("UPDATE scans SET user_verdict = ? WHERE id = ?", (verdict, scan_id))
        conn.execute(
            "INSERT INTO feedback (scan_id, verdict, timestamp) VALUES (?, ?, ?)",
            (scan_id, verdict, datetime.now().isoformat()),
        )
        conn.commit()
        conn.close()

    def get_threat_dashboard(self) -> dict:
        conn = sqlite3.connect(DB_PATH)
        total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        critical = conn.execute("SELECT COUNT(*) FROM scans WHERE threat_level = 'CRITICAL'").fetchone()[0]
        high = conn.execute("SELECT COUNT(*) FROM scans WHERE threat_level = 'HIGH'").fetchone()[0]
        phishing = conn.execute("SELECT COUNT(*) FROM scans WHERE classification = 'phishing'").fetchone()[0]

        top_ips = conn.execute(
            "SELECT indicator_value, hit_count, confidence FROM threat_intel WHERE indicator_type = 'ip' ORDER BY hit_count DESC LIMIT 10"
        ).fetchall()
        top_domains = conn.execute(
            "SELECT indicator_value, hit_count, confidence FROM threat_intel WHERE indicator_type = 'domain' ORDER BY hit_count DESC LIMIT 10"
        ).fetchall()

        recent = conn.execute(
            "SELECT email_from, subject, threat_level, threat_score, classification, analyzed_at FROM scans ORDER BY id DESC LIMIT 20"
        ).fetchall()

        conn.close()

        return {
            "total_scans": total,
            "critical_threats": critical,
            "high_threats": high,
            "phishing_detected": phishing,
            "top_threat_ips": [{"ip": r[0], "hits": r[1], "confidence": r[2]} for r in top_ips],
            "top_threat_domains": [{"domain": r[0], "hits": r[1], "confidence": r[2]} for r in top_domains],
            "recent_scans": [
                {"from": r[0], "subject": r[1], "threat_level": r[2], "score": r[3], "class": r[4], "at": r[5]}
                for r in recent
            ],
        }
