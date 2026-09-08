from __future__ import annotations

import os
from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import FileResponse, JSONResponse

from app.services.email_parser import EmailParser
from app.services.header_forensics import HeaderForensics
from app.services.geolocation import GeoLocator, GeoResult
from app.services.domain_intel import DomainAnalyzer, DomainIntel
from app.services.graph_correlator import GraphCorrelator
from app.services.report_generator import ReportGenerator
from app.services.llm_narrator import ThreatNarrator
from app.services.language_analyzer import LanguageAnalyzer
from app.services.pipeline import EmailPipeline
from app.ml.classifier import PhishingClassifier
from app.ml.train import train as train_model

router = APIRouter()
classifier = PhishingClassifier()
graph_correlator = GraphCorrelator()
pipeline = EmailPipeline()


async def _run_analysis(content: bytes) -> dict:
    from app.services.threat_intel import ThreatIntelligence
    import re as _re

    parsed_email = EmailParser.parse(content)
    header_analysis = HeaderForensics.analyze(parsed_email)
    classification = classifier.classify(parsed_email, header_analysis)

    earliest_ip = header_analysis.earliest_reliable_ip
    geo_result = await GeoLocator.locate(earliest_ip) if earliest_ip else GeoResult()

    sender_domain = header_analysis.sender_domain
    domain_intel = await DomainAnalyzer.analyze(sender_domain) if sender_domain else DomainIntel()

    # === Advanced Threat Intelligence ===
    lookalike = ThreatIntelligence.check_lookalike_domain(sender_domain) if sender_domain else None
    display_spoof = ThreatIntelligence.check_display_spoofing(
        parsed_email.from_addr, parsed_email.reply_to, parsed_email.return_path
    )

    # Enrich relay path with ASN + geo per hop
    enriched_relay = []
    for hop in header_analysis.relay_path:
        hop_ip = hop.get("ip")
        hop_geo = await GeoLocator.locate(hop_ip) if hop_ip else None
        enriched_relay.append({
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
        })

    # URL redirect tracing (first 5 URLs)
    url_traces = []
    if hasattr(parsed_email, 'body') and parsed_email.body:
        urls = _re.findall(r'https?://[^\s<>"\']+', parsed_email.body)[:5]
        for url in urls:
            trace = await ThreatIntelligence.trace_url_redirects(url)
            url_traces.append(trace)

    # IoC extraction
    iocs = ThreatIntelligence.extract_iocs(
        parsed_email, header_analysis, geo_result, domain_intel, enriched_relay
    )

    correlation = graph_correlator.correlate(
        parsed_email, header_analysis, geo_result, domain_intel
    )

    report = ReportGenerator.generate(
        parsed_email, header_analysis, classification,
        geo_result, domain_intel, correlation,
    )

    # Override relay path with enriched version
    report.relay_path = enriched_relay

    language = LanguageAnalyzer.analyze(parsed_email.subject, parsed_email.body)

    result = {
        "report_id": report.report_id,
        "threat_level": report.threat_level,
        "threat_score": report.threat_score,
        "classification": report.classification,
        "confidence": report.classification_confidence,
        "email": {
            "subject": report.email_subject,
            "from": report.email_from,
            "to": report.email_to,
        },
        "authentication": {
            "spf": report.spf_result,
            "dkim": report.dkim_result,
            "dmarc": report.dmarc_result,
        },
        "origin": {
            "ip": report.origin_ip,
            "country": report.origin_country,
            "city": report.origin_city,
            "isp": report.origin_isp,
            "is_vpn": report.is_vpn,
            "is_tor": report.is_tor,
            "latitude": geo_result.latitude,
            "longitude": geo_result.longitude,
            "asn": geo_result.as_number,
            "hosting_provider": geo_result.hosting_provider,
        },
        "domain": {
            "age_days": report.domain_age_days,
            "registrar": report.domain_registrar,
            "is_suspicious": report.domain_suspicious,
            "suspicion_reasons": report.domain_suspicion_reasons,
        },
        "language": {
            "sentiment": language.sentiment,
            "sentiment_score": language.sentiment_score,
            "urgency_score": language.urgency_score,
            "fear_score": language.fear_score,
            "greed_score": language.greed_score,
            "authority_score": language.authority_score,
            "template_type": language.template_type,
            "template_confidence": language.template_confidence,
            "social_engineering_tactics": language.social_engineering_tactics,
            "red_flag_phrases": language.red_flag_phrases,
            "reading_level": language.reading_level,
            "caps_ratio": language.caps_ratio,
            "exclamation_count": language.exclamation_count,
            "url_count": language.url_count,
            "obfuscated_words": language.obfuscated_words,
            "localization_clues": language.localization_clues,
        },
        "anomalies": report.anomalies,
        "relay_path": enriched_relay,
        "graph": {
            "nodes": report.graph_nodes,
            "edges": report.graph_edges,
        },
        "attribution_confidence": report.attribution_confidence,
        "recommendations": report.recommendations,
        "executive_summary": report.executive_summary,
        "analyzed_at": report.date_analyzed,
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

    pipeline._store_scan(result, content.decode("utf-8", errors="replace"))
    pipeline._update_threat_intel(result)

    return result


@router.post("/analyze")
async def analyze_email(file: UploadFile = File(...)):
    try:
        content = await file.read()
        if len(content) > 500 * 1024:
            raise HTTPException(status_code=400, detail="File too large (max 500KB)")
        return await _run_analysis(content)
    except HTTPException:
        raise
    except Exception as e:
        import traceback; traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.post("/analyze-text")
async def analyze_raw_text(payload: dict):
    raw_text = payload.get("raw_email", "")
    if not raw_text:
        raise HTTPException(status_code=400, detail="raw_email field is required")
    try:
        return await _run_analysis(raw_text.encode("utf-8"))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.post("/feedback")
async def submit_feedback(payload: dict):
    scan_id = payload.get("scan_id")
    verdict = payload.get("verdict")
    if not scan_id or verdict not in ("phishing", "legitimate", "spam"):
        raise HTTPException(status_code=400, detail="scan_id and valid verdict required")
    pipeline.record_feedback(scan_id, verdict)
    return {"status": "ok", "message": f"Feedback recorded: {verdict}"}


@router.get("/dashboard")
async def get_dashboard():
    return pipeline.get_threat_dashboard()


@router.post("/train")
async def trigger_training():
    try:
        train_model()
        return {"status": "ok", "message": "Model retrained successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Training failed: {str(e)}")


@router.get("/sample/{filename}")
async def get_sample(filename: str):
    sample_dir = os.path.join(os.path.dirname(__file__), "..", "..", "data", "sample_emails")
    filepath = os.path.join(sample_dir, filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Sample not found")
    return FileResponse(filepath, media_type="message/rfc822", filename=filename)


@router.post("/export/pdf")
async def export_pdf(payload: dict):
    try:
        from weasyprint import HTML
        import tempfile

        html_content = f"""<!DOCTYPE html>
<html><head><style>
body {{ font-family: Arial, sans-serif; padding: 40px; color: #1a1a1a; }}
.header {{ border-bottom: 3px solid {'#dc2626' if payload.get('threat_level') == 'CRITICAL' else '#f97316' if payload.get('threat_level') == 'HIGH' else '#eab308' if payload.get('threat_level') == 'MEDIUM' else '#22c55e'}; padding-bottom: 20px; margin-bottom: 20px; }}
h1 {{ font-size: 24px; margin: 0; }}
h2 {{ font-size: 16px; color: #555; margin: 10px 0; }}
.badge {{ display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: bold; color: white; background: {'#dc2626' if payload.get('threat_level') == 'CRITICAL' else '#f97316' if payload.get('threat_level') == 'HIGH' else '#eab308' if payload.get('threat_level') == 'MEDIUM' else '#22c55e'}; }}
table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #eee; font-size: 13px; }}
th {{ background: #f5f5f5; font-weight: 600; }}
.anomaly {{ background: #fef2f2; padding: 8px; margin: 4px 0; border-left: 3px solid #dc2626; font-size: 12px; }}
.rec {{ background: #f0fdf4; padding: 8px; margin: 4px 0; border-left: 3px solid #22c55e; font-size: 12px; }}
.footer {{ margin-top: 30px; padding-top: 15px; border-top: 1px solid #eee; font-size: 11px; color: #888; }}
</style></head><body>
<div class="header">
<h1>MailTrace AI — Forensic Report</h1>
<p>Report ID: {payload.get('report_id', 'N/A')} | Generated: {payload.get('analyzed_at', 'N/A')}</p>
</div>
<span class="badge">{payload.get('threat_level', 'UNKNOWN')}</span>
<p style="font-size:14px; margin-top:10px;"><strong>Classification:</strong> {payload.get('classification', 'N/A')} ({(payload.get('confidence', 0)*100):.0f}% confidence)</p>
<h2>Email Details</h2>
<table>
<tr><th>Subject</th><td>{payload.get('email', {}).get('subject', 'N/A')}</td></tr>
<tr><th>From</th><td>{payload.get('email', {}).get('from', 'N/A')}</td></tr>
<tr><th>To</th><td>{payload.get('email', {}).get('to', 'N/A')}</td></tr>
</table>
<h2>Authentication</h2>
<table>
<tr><th>SPF</th><td>{payload.get('authentication', {}).get('spf', 'N/A')}</td></tr>
<tr><th>DKIM</th><td>{payload.get('authentication', {}).get('dkim', 'N/A')}</td></tr>
<tr><th>DMARC</th><td>{payload.get('authentication', {}).get('dmarc', 'N/A')}</td></tr>
</table>
<h2>Origin</h2>
<table>
<tr><th>IP</th><td>{payload.get('origin', {}).get('ip', 'N/A')}</td></tr>
<tr><th>Country</th><td>{payload.get('origin', {}).get('country', 'N/A')}</td></tr>
<tr><th>ISP</th><td>{payload.get('origin', {}).get('isp', 'N/A')}</td></tr>
<tr><th>VPN</th><td>{payload.get('origin', {}).get('is_vpn', False)}</td></tr>
<tr><th>TOR</th><td>{payload.get('origin', {}).get('is_tor', False)}</td></tr>
</table>
<h2>Anomalies ({len(payload.get('anomalies', []))})</h2>
{''.join(f'<div class="anomaly">{a}</div>' for a in payload.get('anomalies', []))}
<h2>Language Analysis</h2>
<table>
<tr><th>Sentiment</th><td>{payload.get('language', {}).get('sentiment', 'N/A')} ({(payload.get('language', {}).get('sentiment_score', 0)*100):.0f}%)</td></tr>
<tr><th>Template</th><td>{payload.get('language', {}).get('template_type', 'N/A').replace('_', ' ').title()} ({(payload.get('language', {}).get('template_confidence', 0)*100):.0f}%)</td></tr>
<tr><th>Tactics</th><td>{', '.join(payload.get('language', {}).get('social_engineering_tactics', [])) or 'None detected'}</td></tr>
<tr><th>Urgency</th><td>{(payload.get('language', {}).get('urgency_score', 0)*100):.0f}%</td></tr>
<tr><th>Fear</th><td>{(payload.get('language', {}).get('fear_score', 0)*100):.0f}%</td></tr>
<tr><th>Authority Abuse</th><td>{(payload.get('language', {}).get('authority_score', 0)*100):.0f}%</td></tr>
<tr><th>Reading Level</th><td>{payload.get('language', {}).get('reading_level', 'N/A')}</td></tr>
<tr><th>URLs Found</th><td>{payload.get('language', {}).get('url_count', 0)}</td></tr>
<tr><th>Red Flags</th><td>{'; '.join(payload.get('language', {}).get('red_flag_phrases', [])) or 'None'}</td></tr>
</table>
<h2>Recommendations</h2>
{''.join(f'<div class="rec">{r}</div>' for r in payload.get('recommendations', []))}
{'<h2>AI Narrative</h2><p style="font-family:monospace;font-size:12px;white-space:pre-wrap;">' + payload.get('ai_narrative', '') + '</p>' if payload.get('ai_narrative') else ''}
<div class="footer">MailTrace AI v2.0 — SIH 2026 | AI-Powered Email Forensics</div>
</body></html>"""

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            f.write(html_content.encode())
            html_path = f.name

        pdf_path = html_path.replace(".html", ".pdf")
        HTML(filename=html_path).write_pdf(pdf_path)

        return FileResponse(pdf_path, filename=f"MailTrace-{payload.get('report_id', 'report')}.pdf", media_type="application/pdf")

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")


@router.get("/health")
async def health():
    return {"status": "ok", "service": "MailTrace AI", "version": "2.0.0", "features": [
        "distilbert_nlp", "header_forensics", "geolocation",
        "domain_intel", "graph_correlation", "llm_narrative",
        "real_time_pipeline", "feedback_loop", "language_analysis",
        "email_comparison", "push_notifications",
    ]}


# In-memory notification tokens (would be a DB in production)
_notification_tokens: list[dict] = []


@router.post("/notifications/register")
async def register_notification_token(payload: dict):
    token = payload.get("token")
    platform = payload.get("platform", "unknown")
    if not token:
        raise HTTPException(status_code=400, detail="Token required")
    _notification_tokens.append({"token": token, "platform": platform})
    return {"status": "ok", "message": "Notification token registered"}


@router.post("/notifications/send-test")
async def send_test_notification():
    """Send a test push notification to all registered tokens."""
    try:
        import httpx
        messages = []
        for t in _notification_tokens:
            messages.append({
                "to": t["token"],
                "title": "MailTrace AI — Test Alert",
                "body": "Push notifications are working! You will receive alerts for critical threats.",
                "data": {"screen": "dashboard"},
            })
        if messages:
            async with httpx.AsyncClient() as client:
                await client.post("https://exp.host/--/api/v2/push/send", json=messages, timeout=10)
        return {"status": "ok", "sent": len(messages)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/compare")
async def compare_emails(payload: dict):
    emails = payload.get("emails", [])
    if len(emails) < 2:
        raise HTTPException(status_code=400, detail="At least 2 emails required for comparison")
    if len(emails) > 5:
        raise HTTPException(status_code=400, detail="Maximum 5 emails for comparison")

    results = []
    for raw in emails:
        try:
            content = raw.encode("utf-8") if isinstance(raw, str) else raw
            r = await _run_analysis(content)
            results.append(r)
        except Exception:
            results.append({"error": "Failed to analyze one email"})

    # Find common indicators
    common_ips = set()
    common_domains = set()
    common_tactics = set()
    for r in results:
        if "origin" in r and r["origin"].get("ip"):
            common_ips.add(r["origin"]["ip"])
        if "email" in r and "@" in r["email"].get("from", ""):
            common_domains.add(r["email"]["from"].split("@")[-1].lower())
        if "language" in r:
            for t in r["language"].get("social_engineering_tactics", []):
                common_tactics.add(t)

    comparison = {
        "individual_results": results,
        "summary": {
            "email_count": len(results),
            "threat_levels": [r.get("threat_level") for r in results],
            "classifications": [r.get("classification") for r in results],
            "scores": [r.get("threat_score", 0) for r in results],
            "avg_score": sum(r.get("threat_score", 0) for r in results) / max(len(results), 1),
            "common_ips": list(common_ips) if len(common_ips) > 1 else [],
            "common_sender_domains": list(common_domains) if len(common_domains) > 1 else [],
            "common_tactics": list(common_tactics) if len(common_tactics) > 1 else [],
            "is_coordinated": len(common_ips) > 1 or len(common_domains) > 1 or len(common_tactics) >= 2,
        },
    }
    return comparison
