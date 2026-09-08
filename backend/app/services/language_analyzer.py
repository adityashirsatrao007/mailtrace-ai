"""
Email Language & Template Analysis Service.
Detects phishing patterns, urgency markers, social engineering tactics,
and sentiment analysis using regex + heuristic scoring (no external NLP deps).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class LanguageAnalysis:
    sentiment: str = "neutral"
    sentiment_score: float = 0.0
    urgency_score: float = 0.0
    fear_score: float = 0.0
    greed_score: float = 0.0
    authority_score: float = 0.0
    template_type: str = "unknown"
    template_confidence: float = 0.0
    social_engineering_tactics: list[str] = field(default_factory=list)
    red_flag_phrases: list[str] = field(default_factory=list)
    language_complexity: float = 0.0
    reading_level: str = "standard"
    caps_ratio: float = 0.0
    exclamation_count: int = 0
    url_count: int = 0
    obfuscated_words: list[str] = field(default_factory=list)
    localization_clues: list[str] = field(default_factory=list)


# --- Phishing template patterns ---
TEMPLATES = {
    "account_verification": {
        "patterns": [
            r"(?:verify|confirm|validate)\s+(?:your|the)\s+(?:account|identity|information|credentials)",
            r"(?:your|the)\s+(?:account|profile)\s+(?:has been|is)\s+(?:locked|suspended|compromised|disabled|limited)",
            r"(?:unusual|suspicious)\s+(?:activity|sign.?in|login)\s+(?:detected|attempted|from)",
            r"(?:act|update|confirm)\s+(?:now|immediately|today)\s+to\s+(?:avoid|prevent|keep)",
            r"(?:click|follow)\s+(?:the\s+)?(?:link|below|button)\s+to\s+(?:verify|confirm|restore|unlock)",
            r"(?:failure|not?\s+confirm)\s+to\s+(?:verify|validate)\s+(?:will\s+)?(?:result|lead|cause)\s+(?:in|to)\s+(?:account\s+)?(?:suspension|closure|deletion|locking)",
        ],
        "weight": 0.9,
    },
    "invoice_scam": {
        "patterns": [
            r"(?:overdue|outstanding|unpaid)\s+(?:invoice|payment|bill|amount)",
            r"(?:attached|see\s+attached|find\s+attached)\s+(?:invoice|receipt|bill|statement|payment)",
            r"(?:kindly|please)\s+(?:remit|pay|settle|process)\s+(?:the\s+)?(?:attached|enclosed|outstanding)",
            r"(?:payment|invoice)\s+(?:\d+|#\d+|\s+detail)",
            r"(?:due|overdue|expires?)\s+(?:date|today|immediately)",
        ],
        "weight": 0.85,
    },
    "prize_winner": {
        "patterns": [
            r"(?:you(?:'ve|\s+have)\s+)?(?:won|selected|chosen|awarded)\s+(?:a\s+)?(?:prize|award|gift|bonus|reward|lottery)",
            r"(?:congratulations|congrats)\s*,?\s*you\s+(?:have\s+)?(?:been|are)",
            r"(?:claim|collect|redeem)\s+(?:your|the)\s+(?:prize|reward|gift|bonus|winnings?)",
            r"(?:limited|act)\s+(?:time|now|before|expires?)\s+(?:offer|deadline|chance)",
            r"(?:free|no\s+cost|complimentary)\s+(?:gift|trip|vacation|iPhone|Samsung|prize)",
        ],
        "weight": 0.95,
    },
    "tech_support": {
        "patterns": [
            r"(?:your|the)\s+(?:computer|device|system|network)\s+(?:is\s+)?(?:infected|compromised|at\s+risk|has\s+a\s+virus)",
            r"(?:call|microsoft|apple|google|amazon)\s+(?:support|technical|help)\s+(?:immediately|now|at)",
            r"(?:your|the)\s+(?:subscription|warranty|license)\s+(?:has\s+)?(?:expired|ended|been\s+cancelled)",
            r"(?:unauthorized|unrecognised|suspicious)\s+(?:access|transaction|activity)\s+(?:on|from)\s+(?:your|the)\s+(?:account|device)",
            r"(?:remote|technical)\s+(?:access|support|assistance)\s+(?:required|needed|recommended)",
        ],
        "weight": 0.88,
    },
    "ceo_wire_fraud": {
        "patterns": [
            r"(?:urgent(?:ly)?|confidential|private|sensitive)\s*(?::|—|-)?\s*(?:need|requir|wire|transfer|payment)",
            r"(?:wire|make|process|send)\s+(?:a\s+)?(?:payment|transfer|wire)\s+(?:of|for|to)",
            r"(?:don'?t|do\s+not)\s+(?:tell|mention|share|discuss)\s+(?:this|it)\s+(?:with|to)\s+(?:anyone|anybody|team|others)",
            r"(?:i'?m?\s+(?:in\s+a\s+meeting|traveling|unavailable|out\s+of\s+office|on\s+a\s+call))",
            r"(?:handle\s+this|take\s+care\s+of\s+this|process\s+this)\s+(?:personally|yourself|immediately|asap)",
            r"(?:new|changed|updated)\s+(?:bank|payment|wire)\s+(?:details?|instructions?|account)",
        ],
        "weight": 0.92,
    },
    "credential_harvest": {
        "patterns": [
            r"(?:update|confirm|re-?verify|validate)\s+(?:your|the)\s+(?:password|credentials?|login|billing|payment\s+method)",
            r"(?:sign|log)\s+in\s+(?:again|immediately|now|to\s+(?:verify|confirm|avoid|prevent))",
            r"(?:your|the)\s+(?:session|token|access)\s+(?:has\s+)?(?:expired|timed?\s*out|been\s+revoked)",
            r"(?:click|tap)\s+(?:the\s+)?(?:link|below|button|here)\s+to\s+(?:keep|maintain|restore|confirm)",
            r"(?:failure|if\s+you\s+don'?t)\s+(?:to\s+)?(?:update|confirm|verify|act)\s+(?:within|before|by)\s+\d+\s+(?:hours?|days?|minutes?)",
        ],
        "weight": 0.87,
    },
}

# --- Social engineering tactic markers ---
TACTICS = {
    "urgency": {
        "markers": [
            r"(?:immediately|urgent(?:ly)?|asap|right\s+away|at\s+once|hurry|now|today|expir)",
            r"(?:limited|last\s+chance|hurry|don'?t\s+miss|final\s+notice|act\s+now)",
            r"(?:\d+\s+(?:hours?|minutes?|days?)\s+(?:left|remaining|before|to))",
            r"(?:before\s+it'?s?\s+too\s+late|time\s+(?:is\s+running|sensitive))",
        ],
        "base_score": 0.7,
    },
    "fear": {
        "markers": [
            r"(?:suspended|locked|compromised|breach|hack|stolen|illegal|unlawful)",
            r"(?:legal\s+(?:action|consequences|proceedings)|police|FBI|arrest|warrant)",
            r"(?:account\s+(?:closure|termination|deletion|suspension))",
            r"(?:data\s+(?:loss|breach|leak|theft)|identity\s+(?:theft|stolen|compromised))",
            r"(?:your\s+(?:IP|computer|device)\s+(?:has\s+been|is)\s+(?:tracked|tracked|identified|logged))",
        ],
        "base_score": 0.75,
    },
    "greed": {
        "markers": [
            r"(?:won|prize|lottery|reward|bonus|gift|free|complimentary|congratulations)",
            r"(?:\$\d[\d,]*(?:\.\d{2})?|\d[\d,]*\s+(?:USD|EUR|GBP|INR))",
            r"(?:million|billion|inheritance|lottery|jackpot)",
            r"(?:exclusive|VIP|premium|special\s+offer|limited\s+time\s+deal)",
        ],
        "base_score": 0.65,
    },
    "authority": {
        "markers": [
            r"(?:CEO|CFO|CTO|director|manager|president|head\s+of|chief)",
            r"(?:IRS|FBI|CIA|police|government|ministry|official|authority)",
            r"(?:IT\s+(?:department|team|admin)|security\s+(?:team|department|center))",
            r"(?:bank|paypal|amazon|microsoft|apple|google|facebook|support\s+team)",
            r"(?:authorized|verified|certified|approved|official)",
        ],
        "base_score": 0.6,
    },
    "scarcity": {
        "markers": [
            r"(?:only\s+\d+\s+(?:left|remaining|spots?|available))",
            r"(?:exclusive|rare|limited\s+(?:edition|quantity|supply))",
            r"(?:first\s+\d+\s+(?:customers?|users?|respondents?))",
            r"(?:while\s+(?:stocks?|supplies)\s+last|one[- ]time\s+offer)",
        ],
        "base_score": 0.55,
    },
}

# --- Red flag phrases (verbatim or near) ---
RED_FLAG_PHRASES = [
    r"(?:kindly|please\s+urgent(?:ly)?|dear\s+(?:sir|madam|friend|user|customer|account\s+holder))",
    r"(?:i\s+am\s+(?:a\s+)?(?:prince|minister|official|widow|barrister|lawyer|doctor))",
    r"(?:next\s+of\s+kin|belonged\s+to|no\s+risk|100%\s+(?:free|guaranteed|safe|secure))",
    r"(?:do\s+not\s+(?:tell|share|mention|discuss|inform))",
    r"(?:this\s+is\s+(?:not|a)\s+(?:scam|fake|joke|fraud))",
    r"(?:god\s+bless|bless\s+you|prayers?)",
    r"(?:transfer\s+to\s+(?:a\s+)?(?:secure|safe|new)\s+(?:account|wallet))",
    r"(?:confidential|top\s+secret|classified|eyes\s+only)",
]


class LanguageAnalyzer:
    """Analyze email language for phishing patterns, sentiment, and social engineering."""

    @staticmethod
    def analyze(subject: str, body: str) -> LanguageAnalysis:
        text = f"{subject} {body}".lower()
        analysis = LanguageAnalysis()

        analysis.caps_ratio = LanguageAnalyzer._caps_ratio(f"{subject} {body}")
        analysis.exclamation_count = text.count("!")
        analysis.url_count = len(re.findall(r"https?://\S+", text))
        analysis.obfuscated_words = LanguageAnalyzer._find_obfuscated(body)
        analysis.localization_clues = LanguageAnalyzer._localization_clues(text)
        analysis.language_complexity = LanguageAnalyzer._complexity(text)
        analysis.reading_level = LanguageAnalyzer._reading_level(analysis.language_complexity)

        # Template detection
        best_template = "unknown"
        best_confidence = 0.0
        for name, tmpl in TEMPLATES.items():
            matches = sum(1 for p in tmpl["patterns"] if re.search(p, text))
            if matches > 0:
                conf = min(matches / 3.0, 1.0) * tmpl["weight"]
                if conf > best_confidence:
                    best_confidence = conf
                    best_template = name
        analysis.template_type = best_template
        analysis.template_confidence = best_confidence

        # Social engineering tactics
        for tactic_name, tactic in TACTICS.items():
            matches = sum(1 for m in tactic["markers"] if re.search(m, text))
            if matches > 0:
                analysis.social_engineering_tactics.append(tactic_name)
                score = min(matches / 3.0, 1.0) * tactic["base_score"]
                if tactic_name == "urgency":
                    analysis.urgency_score = score
                elif tactic_name == "fear":
                    analysis.fear_score = score
                elif tactic_name == "greed":
                    analysis.greed_score = score
                elif tactic_name == "authority":
                    analysis.authority_score = score

        # Red flag phrases
        for phrase in RED_FLAG_PHRASES:
            match = re.search(phrase, text)
            if match:
                analysis.red_flag_phrases.append(match.group(0))

        # Overall sentiment
        analysis.sentiment, analysis.sentiment_score = LanguageAnalyzer._sentiment(text)

        return analysis

    @staticmethod
    def _caps_ratio(text: str) -> float:
        alpha = [c for c in text if c.isalpha()]
        if not alpha:
            return 0.0
        return sum(1 for c in alpha if c.isupper()) / len(alpha)

    @staticmethod
    def _find_obfuscated(text: str) -> list[str]:
        obfuscated = []
        patterns = [
            (r"[a-zA-Z]\s+[a-zA-Z]\s+[a-zA-Z]", "spaced letters"),
            (r"[a-zA-Z]@[a-zA-Z]", "@ in word"),
            (r"(?:d0t|d0t|d0t)", "leetspeak dot"),
            (r"(?:0|[oO])\s*(?:r|@\s*round)", "obfuscated round"),
            (r"\b\w+(?:\.\w+){2,}\b", "dotted word"),
        ]
        for pat, desc in patterns:
            matches = re.findall(pat, text)
            if matches:
                obfuscated.append(f"{desc}: {matches[0][:30]}")
        return obfuscated[:5]

    @staticmethod
    def _localization_clues(text: str) -> list[str]:
        clues = []
        if re.search(r"(?:\+?91[\s-]?\d{10})", text):
            clues.append("Indian phone number")
        if re.search(r"(?:\+?1[\s-]?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{4})", text):
            clues.append("US phone number")
        if re.search(r"(?:\+?44[\s-]?\d{10})", text):
            clues.append("UK phone number")
        if re.search(r"(?:Nigeria|Lagos|Accra|Ghana|Kenya|Nairobi)", text, re.I):
            clues.append("West Africa reference")
        if re.search(r"(?:SEZ|Mumbai|Delhi|Bangalore|Hyderabad|Chennai|Kolkata)", text, re.I):
            clues.append("Indian city reference")
        if re.search(r"(?:UTC|GMT|IST|EST|PST|CET)\s*[+-]?\d*", text):
            clues.append("timezone reference")
        return clues

    @staticmethod
    def _complexity(text: str) -> float:
        words = text.split()
        if not words:
            return 0.0
        avg_len = sum(len(w) for w in words) / len(words)
        unique_ratio = len(set(words)) / len(words) if words else 0
        sentences = re.split(r"[.!?]+", text)
        sentences = [s for s in sentences if s.strip()]
        avg_sent_len = len(words) / max(len(sentences), 1)
        return min(((avg_len / 8.0) * 0.3 + unique_ratio * 0.4 + (avg_sent_len / 25.0) * 0.3), 1.0)

    @staticmethod
    def _reading_level(complexity: float) -> str:
        if complexity < 0.3:
            return "simple"
        elif complexity < 0.5:
            return "standard"
        elif complexity < 0.7:
            return "advanced"
        return "complex"

    @staticmethod
    def _sentiment(text: str) -> tuple[str, float]:
        positive = len(re.findall(
            r"(?:thank|grateful|appreciate|congratulations|won|prize|reward|free|bonus|exclusive|winner|happy|pleased|great|good|wonderful|amazing)", text
        ))
        negative = len(re.findall(
            (r"(?:urgent|immediately|suspended|locked|compromised|breach|hack|stolen|illegal|threat|warning|alert|"
             r"fail|error|denied|blocked|unauthorized|fraud|scam|phishing|malware|virus|danger|risk|threaten|"
             r"penalty|fine|arrest|prosecute|terminate|cancel|deactivate|remove)"),
            text,
        ))
        total = positive + negative
        if total == 0:
            return "neutral", 0.5
        score = positive / total
        if score > 0.6:
            return "positive", score
        elif score < 0.4:
            return "negative", 1.0 - score
        return "neutral", 0.5
