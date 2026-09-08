from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Optional

import numpy as np


@dataclass
class ClassificationResult:
    label: str = "legitimate"
    confidence: float = 0.0
    phishing_score: float = 0.0
    spam_score: float = 0.0
    bec_score: float = 0.0
    malware_score: float = 0.0
    features_used: list[str] = None

    def __post_init__(self):
        if self.features_used is None:
            self.features_used = []


class PhishingClassifier:
    """Real DistilBERT-based classifier with header feature ensemble."""

    MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")

    MALICIOUS_URL_PATTERNS = [
        r"bit\.ly/", r"tinyurl\.com/", r"t\.co/", r"go\.gg/",
        r"\d+\.\d+\.\d+\.\d+", r"https?://[^\s]*@",
        r"https?://[^\s]*-[^\s]*\.(com|net|org)",
    ]

    def __init__(self):
        self.nlp_model = None
        self.nlp_tokenizer = None
        self._load_nlp_model()

    def _load_nlp_model(self):
        try:
            from transformers import AutoTokenizer, AutoModelForSequenceClassification
            import torch

            if os.path.exists(os.path.join(self.MODEL_DIR, "config.json")):
                self.nlp_tokenizer = AutoTokenizer.from_pretrained(self.MODEL_DIR)
                self.nlp_model = AutoModelForSequenceClassification.from_pretrained(
                    self.MODEL_DIR
                )
                self.nlp_model.eval()
                print("[MailTrace AI] Loaded trained DistilBERT model")
            else:
                self.nlp_tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")
                self.nlp_model = AutoModelForSequenceClassification.from_pretrained(
                    "distilbert-base-uncased", num_labels=2
                )
                self.nlp_model.eval()
                print("[MailTrace AI] Using base DistilBERT (run train.py to fine-tune)")
        except Exception as e:
            print(f"[MailTrace AI] NLP model load failed: {e}")
            self.nlp_model = None

    def classify(self, parsed_email, header_analysis) -> ClassificationResult:
        result = ClassificationResult()

        text = f"{parsed_email.subject} {parsed_email.body}"
        nlp_score = self._nlp_predict(text)

        header_score = self._header_risk_score(header_analysis)
        url_score = self._url_risk_score(parsed_email)
        social_score = self._social_engineering_score(parsed_email)

        combined = 0.50 * nlp_score + 0.25 * header_score + 0.15 * url_score + 0.10 * social_score

        result.phishing_score = combined
        result.confidence = combined

        if combined >= 0.7:
            result.label = "phishing"
        elif combined >= 0.5:
            result.label = "suspicious"
        elif combined >= 0.3:
            result.label = "spam"
        else:
            result.label = "legitimate"

        if header_score > 0.6 and any(
            kw in text.lower()
            for kw in ["wire transfer", "bank account", "invoice", "payment"]
        ):
            result.bec_score = header_score
            if result.bec_score > combined:
                result.label = "business_email_compromise"

        result.features_used = ["distilbert_nlp", "header_auth", "url_analysis", "social_engineering"]
        return result

    def _nlp_predict(self, text: str) -> float:
        if self.nlp_model is None or self.nlp_tokenizer is None:
            return self._fallback_keyword_score(text)

        try:
            import torch
            encoding = self.nlp_tokenizer(
                text,
                add_special_tokens=True,
                max_length=256,
                padding="max_length",
                truncation=True,
                return_attention_mask=True,
                return_tensors="pt",
            )
            with torch.no_grad():
                outputs = self.nlp_model(
                    input_ids=encoding["input_ids"],
                    attention_mask=encoding["attention_mask"],
                )
            probs = torch.softmax(outputs.logits, dim=1)
            phishing_prob = probs[0][1].item()
            return phishing_prob
        except Exception:
            return self._fallback_keyword_score(text)

    def _fallback_keyword_score(self, text: str) -> float:
        phishing_keywords = [
            "verify your account", "confirm your identity", "update your payment",
            "unusual activity", "suspended", "click here immediately",
            "act now", "security alert", "unauthorized access",
            "reset your password", "account will be locked", "urgent action required",
        ]
        text_lower = text.lower()
        hits = sum(1 for kw in phishing_keywords if kw in text_lower)
        return min(hits * 0.15, 1.0)

    def _header_risk_score(self, header_analysis) -> float:
        score = 0.0
        if header_analysis.spf_result == "fail":
            score += 0.3
        elif header_analysis.spf_result == "softfail":
            score += 0.1
        if header_analysis.dkim_result in ("fail", "none"):
            score += 0.25
        if header_analysis.dmarc_result in ("fail", "none"):
            score += 0.2
        if header_analysis.reply_to_mismatch:
            score += 0.1
        if header_analysis.return_path_mismatch:
            score += 0.1
        score += min(len(header_analysis.anomalies) * 0.03, 0.15)
        return min(score, 1.0)

    def _url_risk_score(self, parsed_email) -> float:
        text = f"{parsed_email.subject} {parsed_email.body}"
        urls = re.findall(r"https?://[^\s<>\"']+", text)
        if not urls:
            return 0.0

        score = 0.0
        for url in urls:
            if re.search(r"https?://\d+\.\d+\.\d+\.\d+", url):
                score += 0.3
            if any(re.search(pat, url) for pat in self.MALICIOUS_URL_PATTERNS):
                score += 0.2
            if len(url) > 80:
                score += 0.1
        if len(urls) > 5:
            score += 0.15
        return min(score, 1.0)

    def _social_engineering_score(self, parsed_email) -> float:
        text = f"{parsed_email.subject} {parsed_email.body}".lower()
        score = 0.0
        if any(w in text for w in ["act now", "immediately", "within 24 hours"]):
            score += 0.25
        if any(w in text for w in ["account will be", "will be deleted", "will be suspended"]):
            score += 0.25
        if any(w in text for w in ["verify your password", "confirm your identity"]):
            score += 0.3
        if any(w in text for w in ["congratulations", "you won", "lottery"]):
            score += 0.2
        return min(score, 1.0)
