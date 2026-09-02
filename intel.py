"""
intel.py
Domain intelligence (lookalike/typosquat detection, free-mail check,
suspicious TLD check) and IP geolocation via the free ip-api.com service.

Geolocation requires outbound internet access from wherever this backend
is deployed (it is NOT called during this sandbox build/test -- deploy
and it will work live). If the lookup fails (offline, rate-limited, or
a private IP), we degrade gracefully instead of crashing.
"""
import re
import socket
from typing import Optional, Dict
from difflib import SequenceMatcher

try:
    import requests
except ImportError:
    requests = None

FREE_MAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
    "protonmail.com", "icloud.com", "mail.com", "zoho.com", "rediffmail.com",
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".gq", ".tk", ".ml", ".cf", ".ga", ".work",
    ".click", ".link", ".zip", ".review", ".country",
}

# Common brands targeted by lookalike/typosquat domains -- extend this list
# with your organization's own brand names for a real deployment.
WATCHED_BRANDS = [
    "paypal", "microsoft", "apple", "google", "amazon", "netflix", "irs",
    "bankofamerica", "chase", "wellsfargo", "hdfcbank", "icicibank", "sbi",
    "gov.in", "rbi", "outlook", "office365",
]


def domain_similarity_check(domain: str) -> Dict:
    """Flag domains that are suspiciously similar to a watched brand
    (classic typosquatting: paypa1.com, micros0ft-support.com, etc.)."""
    if not domain:
        return {"is_lookalike": False, "closest_brand": None, "similarity": 0.0}
    core = domain.split(".")[0].lower()
    best_brand, best_score = None, 0.0
    for brand in WATCHED_BRANDS:
        score = SequenceMatcher(None, core, brand).ratio()
        if score > best_score:
            best_brand, best_score = brand, score
    is_lookalike = 0.6 <= best_score < 1.0  # similar but not an exact/legit match
    return {
        "is_lookalike": is_lookalike,
        "closest_brand": best_brand if best_score >= 0.5 else None,
        "similarity": round(best_score, 2),
    }


def domain_report(domain: str) -> Dict:
    if not domain:
        return {"domain": None, "is_free_mail": False, "suspicious_tld": False,
                 "lookalike": domain_similarity_check(None), "resolvable": False}

    tld = "." + domain.split(".")[-1].lower()
    resolvable = True
    try:
        socket.gethostbyname(domain)
    except Exception:
        resolvable = False

    return {
        "domain": domain,
        "is_free_mail": domain.lower() in FREE_MAIL_DOMAINS,
        "suspicious_tld": tld in SUSPICIOUS_TLDS,
        "lookalike": domain_similarity_check(domain),
        "resolvable": resolvable,
    }


def geolocate_ip(ip: str, timeout: float = 3.0) -> Optional[Dict]:
    """Look up an IP's approximate geolocation via ip-api.com (free, no key).
    Returns None on failure instead of raising -- callers must handle that."""
    if not ip or requests is None:
        return None
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,message,country,countryCode,region,regionName,"
                               "city,lat,lon,isp,org,as,proxy,hosting,query"},
            timeout=timeout,
        )
        data = resp.json()
        if data.get("status") != "success":
            return None
        return {
            "ip": data.get("query"),
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "as": data.get("as"),
            "is_proxy_or_vpn": data.get("proxy", False),
            "is_hosting_provider": data.get("hosting", False),
        }
    except Exception:
        return None
