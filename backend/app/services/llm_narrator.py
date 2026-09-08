"""
GROQ LLM Integration — Auto-generates forensic threat narratives.
Uses Llama 3 via GROQ API for instant, human-readable threat analysis.
"""

from __future__ import annotations

import os
import json
from typing import Optional


class ThreatNarrator:
    """Generate AI-written forensic threat narratives using GROQ LLM."""

    GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
    GROQ_MODEL = "llama3-70b-8192"
    GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

    SYSTEM_PROMPT = """You are a senior cybersecurity analyst at a National CERT. 
Write concise, authoritative forensic threat intelligence reports for email security incidents.

Rules:
- Be specific with technical details (IPs, domains, authentication results)
- Assign a clear threat level: CRITICAL, HIGH, MEDIUM, or LOW
- Provide actionable recommendations for SOC analysts
- Mention if the attack could be part of a larger campaign
- Write in professional incident report style
- Keep under 300 words
- No emojis, no hedging — be decisive"""

    @staticmethod
    async def generate_narrative(analysis_result: dict) -> str:
        """Generate an AI-written forensic narrative from analysis results."""
        if not ThreatNarrator.GROQ_API_KEY:
            return ThreatNarrator._fallback_narrative(analysis_result)

        prompt = ThreatNarrator._build_prompt(analysis_result)

        try:
            import httpx
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    ThreatNarrator.GROQ_URL,
                    headers={
                        "Authorization": f"Bearer {ThreatNarrator.GROQ_API_KEY}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": ThreatNarrator.GROQ_MODEL,
                        "messages": [
                            {"role": "system", "content": ThreatNarrator.SYSTEM_PROMPT},
                            {"role": "user", "content": prompt},
                        ],
                        "temperature": 0.3,
                        "max_tokens": 500,
                    },
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return data["choices"][0]["message"]["content"]
        except Exception:
            pass

        return ThreatNarrator._fallback_narrative(analysis_result)

    @staticmethod
    def _build_prompt(result: dict) -> str:
        return f"""Analyze this email threat and write a forensic incident report:

EMAIL:
  Subject: {result.get('email', {}).get('subject', 'N/A')}
  From: {result.get('email', {}).get('from', 'N/A')}
  To: {result.get('email', {}).get('to', 'N/A')}

AUTHENTICATION:
  SPF: {result.get('authentication', {}).get('spf', 'N/A')}
  DKIM: {result.get('authentication', {}).get('dkim', 'N/A')}
  DMARC: {result.get('authentication', {}).get('dmarc', 'N/A')}

CLASSIFICATION:
  Threat Level: {result.get('threat_level', 'N/A')}
  Score: {result.get('threat_score', 0)}/100
  Type: {result.get('classification', 'N/A')}
  Confidence: {result.get('confidence', 0)*100:.0f}%

ORIGIN:
  IP: {result.get('origin', {}).get('ip', 'N/A')}
  Country: {result.get('origin', {}).get('country', 'N/A')}
  City: {result.get('origin', {}).get('city', 'N/A')}
  ISP: {result.get('origin', {}).get('isp', 'N/A')}
  VPN: {result.get('origin', {}).get('is_vpn', False)}
  TOR: {result.get('origin', {}).get('is_tor', False)}

DOMAIN:
  Age: {result.get('domain', {}).get('age_days', 'N/A')} days
  Suspicious: {result.get('domain', {}).get('is_suspicious', False)}
  Reasons: {', '.join(result.get('domain', {}).get('suspicion_reasons', []))}

ANOMALIES ({len(result.get('anomalies', []))}):
{chr(10).join('  - ' + a for a in result.get('anomalies', [])[:10])}

Write the forensic incident report now."""

    @staticmethod
    def _fallback_narrative(result: dict) -> str:
        threat = result.get("threat_level", "UNKNOWN")
        classification = result.get("classification", "unknown")
        score = result.get("threat_score", 0)
        origin_ip = result.get("origin", {}).get("ip", "unknown")
        country = result.get("origin", {}).get("country", "unknown")
        anomalies = result.get("anomalies", [])
        recs = result.get("recommendations", [])

        lines = [
            f"INCIDENT REPORT — Threat Level: {threat}",
            f"",
            f"Email classified as {classification} with {score:.0f}% confidence.",
            f"",
        ]

        if origin_ip and origin_ip != "unknown":
            lines.append(
                f"Origin traced to IP {origin_ip} ({country}). "
                + ("Sender is using anonymized infrastructure (VPN/TOR). " if
                   result.get("origin", {}).get("is_vpn") or result.get("origin", {}).get("is_tor") else "")
            )

        auth = result.get("authentication", {})
        failures = []
        if auth.get("spf") in ("fail", "softfail"):
            failures.append("SPF")
        if auth.get("dkim") in ("fail", "none"):
            failures.append("DKIM")
        if auth.get("dmarc") in ("fail", "none"):
            failures.append("DMARC")
        if failures:
            lines.append(f"Authentication failures: {', '.join(failures)}. Sender infrastructure is not authorized.")

        if anomalies:
            lines.append(f"{len(anomalies)} anomalies detected in email headers and content.")

        lines.append("")
        lines.append("RECOMMENDATIONS:")
        for rec in recs[:5]:
            lines.append(f"  → {rec}")

        return "\n".join(lines)
