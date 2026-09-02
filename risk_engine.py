"""
risk_engine.py
Combines header forensics, auth results, NLP scoring, URL analysis, and
domain intelligence into a single 0-100 fraud confidence score + verdict.

Weights are intentionally explicit and easy to defend/tune during a judge
Q&A -- this is not a black box.
"""
from typing import Dict, List

WEIGHTS = {
    "ml_text": 30,
    "auth_failure": 20,
    "alignment_mismatch": 15,
    "suspicious_urls": 15,
    "lookalike_domain": 10,
    "suspicious_tld": 5,
    "proxy_or_hosting_origin": 5,
}


def compute_risk(parsed: Dict, auth: Dict, alignment: Dict, nlp: Dict,
                  url_signals: Dict, dom_report: Dict, geo: Dict = None) -> Dict:
    score = 0.0
    reasons: List[str] = []

    # 1. ML text classification
    ml_p = nlp.get("ml_phishing_probability", 0.0)
    contrib = ml_p * WEIGHTS["ml_text"]
    score += contrib
    if ml_p > 0.5:
        reasons.append(f"Language model flags phishing/BEC language ({ml_p*100:.0f}% probability)")

    # 2. Auth failures (SPF/DKIM/DMARC)
    fails = sum(1 for k in ("spf", "dkim", "dmarc") if auth.get(k) in ("fail", "softfail", "none"))
    auth_contrib = (fails / 3) * WEIGHTS["auth_failure"]
    score += auth_contrib
    if fails:
        reasons.append(f"{fails}/3 authentication checks failed or absent (SPF={auth.get('spf')}, "
                        f"DKIM={auth.get('dkim')}, DMARC={auth.get('dmarc')})")

    # 3. From/Return-Path/Reply-To alignment
    if alignment.get("mismatches"):
        score += WEIGHTS["alignment_mismatch"]
        reasons.extend(alignment["mismatches"])

    # 4. Suspicious URLs
    if url_signals.get("suspicious_urls"):
        score += WEIGHTS["suspicious_urls"]
        reasons.append(f"{len(url_signals['suspicious_urls'])} suspicious link(s) detected in body")

    # 5. Lookalike domain
    if dom_report.get("lookalike", {}).get("is_lookalike"):
        score += WEIGHTS["lookalike_domain"]
        brand = dom_report["lookalike"].get("closest_brand")
        reasons.append(f"Sender domain closely resembles trusted brand '{brand}' (possible typosquat)")

    # 6. Suspicious TLD
    if dom_report.get("suspicious_tld"):
        score += WEIGHTS["suspicious_tld"]
        reasons.append("Sender domain uses a TLD commonly abused for abuse/phishing infrastructure")

    # 7. Origin is a proxy/VPN/hosting provider rather than a normal residential/corporate IP
    if geo and (geo.get("is_proxy_or_vpn") or geo.get("is_hosting_provider")):
        score += WEIGHTS["proxy_or_hosting_origin"]
        reasons.append("Originating IP is associated with a hosting/proxy/VPN provider, not typical mail infrastructure")

    score = min(round(score, 1), 100.0)

    if score >= 70:
        verdict = "Malicious / High Confidence Fraud"
    elif score >= 40:
        verdict = "Suspicious -- Manual Review Recommended"
    elif score >= 15:
        verdict = "Low Risk -- Minor Anomalies"
    else:
        verdict = "Likely Legitimate"

    return {
        "fraud_score": score,
        "verdict": verdict,
        "reasons": reasons,
        "score_breakdown": {
            "ml_text_contribution": round(ml_p * WEIGHTS["ml_text"], 1),
            "auth_failure_contribution": round(auth_contrib, 1),
            "alignment_mismatch_contribution": WEIGHTS["alignment_mismatch"] if alignment.get("mismatches") else 0,
            "suspicious_url_contribution": WEIGHTS["suspicious_urls"] if url_signals.get("suspicious_urls") else 0,
            "lookalike_domain_contribution": WEIGHTS["lookalike_domain"] if dom_report.get("lookalike", {}).get("is_lookalike") else 0,
            "suspicious_tld_contribution": WEIGHTS["suspicious_tld"] if dom_report.get("suspicious_tld") else 0,
            "proxy_hosting_contribution": WEIGHTS["proxy_or_hosting_origin"] if geo and (geo.get("is_proxy_or_vpn") or geo.get("is_hosting_provider")) else 0,
        },
    }
