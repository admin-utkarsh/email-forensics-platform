"""
nlp_model.py

MailTrace AI NLP engine.

Uses the trained TF-IDF + Logistic Regression model from:
    ml/model/email_classifier.pkl
    ml/model/tfidf_vectorizer.pkl

Also provides rule-based linguistic and URL indicators.
"""

import os
import re
import joblib


# ============================================================
# MODEL PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

MODEL_PATH = os.path.join(
    BASE_DIR,
    "ml",
    "model",
    "email_classifier.pkl"
)

VECTORIZER_PATH = os.path.join(
    BASE_DIR,
    "ml",
    "model",
    "tfidf_vectorizer.pkl"
)


# ============================================================
# LOAD TRAINED MODEL
# ============================================================

_MODEL = None
_VECTORIZER = None


def _load_model():

    global _MODEL
    global _VECTORIZER

    if _MODEL is None or _VECTORIZER is None:

        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"ML model not found: {MODEL_PATH}"
            )

        if not os.path.exists(VECTORIZER_PATH):
            raise FileNotFoundError(
                f"TF-IDF vectorizer not found: "
                f"{VECTORIZER_PATH}"
            )

        _MODEL = joblib.load(MODEL_PATH)
        _VECTORIZER = joblib.load(VECTORIZER_PATH)

        print("MailTrace AI ML model loaded.")


# ============================================================
# LINGUISTIC RULES
# ============================================================

URGENCY_WORDS = [
    "urgent",
    "immediately",
    "verify your account",
    "act now",
    "suspended",
    "click here",
    "limited time",
    "final notice",
    "action required",
    "confirm your identity",
    "unusual activity",
    "your account will be",
    "password expires",
    "unauthorized access",
    "wire transfer",
    "invoice attached",
    "payment overdue",
    "gift card",
    "kindly",
    "dear customer",
    "dear user",
    "security alert",
    "reset your password",
    "update your billing",
]


IMPERSONATION_PHRASES = [
    "ceo",
    "chief executive",
    "hr department",
    "it support",
    "accounts payable",
    "bank of",
    "paypal",
    "microsoft account",
    "apple id",
    "amazon security",
    "netflix",
    "irs",
    "tax refund",
    "government",
    "law enforcement",
]


# ============================================================
# NLP CLASSIFICATION
# ============================================================

def classify_text(subject: str, body: str) -> dict:

    text = f"{subject or ''} {body or ''}".strip()

    if not text:

        return {
            "ml_phishing_probability": 0.0,
            "ml_prediction": "UNKNOWN",
            "urgency_signals": [],
            "impersonation_signals": [],
            "flagged_phrases": [],
        }

    # Load trained model
    _load_model()

    # Convert email text to TF-IDF
    vector = _VECTORIZER.transform([text])

    # Probability
    probabilities = _MODEL.predict_proba(vector)[0]

    # Find class 1 = phishing
    phishing_index = list(
        _MODEL.classes_
    ).index(1)

    phishing_probability = float(
        probabilities[phishing_index]
    )

    # ML classification
    if phishing_probability >= 0.50:
        prediction = "PHISHING"
    else:
        prediction = "LEGITIMATE"

    # ========================================================
    # RULE-BASED LINGUISTIC ANALYSIS
    # ========================================================

    lower = text.lower()

    urgency_hits = [
        word
        for word in URGENCY_WORDS
        if word in lower
    ]

    impersonation_hits = [
        phrase
        for phrase in IMPERSONATION_PHRASES
        if phrase in lower
    ]

    return {

        "ml_phishing_probability": round(
            phishing_probability,
            4
        ),

        "ml_prediction": prediction,

        "urgency_signals": urgency_hits,

        "impersonation_signals": impersonation_hits,

        "flagged_phrases": list(
            dict.fromkeys(
                urgency_hits +
                impersonation_hits
            )
        )[:10],
    }


# ============================================================
# URL ANALYSIS
# ============================================================

def suspicious_url_signals(urls: list) -> dict:

    shorteners = (
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly"
    )

    ip_literal_re = re.compile(
        r'https?://(?:\d{1,3}\.){3}\d{1,3}'
    )

    findings = []

    for url in urls:

        reasons = []

        if ip_literal_re.match(url):

            reasons.append(
                "Link uses a raw IP address instead of a domain"
            )

        if any(
            s in url.lower()
            for s in shorteners
        ):

            reasons.append(
                "Link uses a URL-shortening service"
            )

        if url.count(".") >= 4:

            reasons.append(
                "Unusually deep subdomain structure"
            )

        if "xn--" in url.lower():

            reasons.append(
                "Punycode domain - possible homograph attack"
            )

        if "@" in url:

            reasons.append(
                "URL contains @ - possible redirection trick"
            )

        if reasons:

            findings.append({
                "url": url,
                "reasons": reasons
            })

    return {
        "total_urls": len(urls),
        "suspicious_urls": findings
    }