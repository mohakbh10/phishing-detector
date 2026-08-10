import ipaddress
import re
from urllib.parse import urlparse
from src.config import HIGH_RISK_KEYWORDS, MEDIUM_RISK_KEYWORDS, SUSPICIOUS_TLDS
from src.utils import get_domain
from src.whitelist import is_whitelisted

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"}

def _is_ip(domain):
    try: ipaddress.ip_address(domain); return True
    except ValueError: return False

def get_features(url):
    domain = get_domain(url)
    lower = url.lower() if isinstance(url, str) else ""
    return {"has_ip": int(_is_ip(domain)), "too_many_hyphens": int(domain.count("-") >= 2), "is_long_url": int(len(url or "") > 75), "has_high_risk_keyword": int(any(w in lower for w in HIGH_RISK_KEYWORDS)), "has_medium_risk_keyword": int(any(w in lower for w in MEDIUM_RISK_KEYWORDS)), "is_http": int(lower.startswith("http://")), "has_suspicious_tld": int(domain.endswith(SUSPICIOUS_TLDS))}

def score_url(url):
    domain = get_domain(url)
    if not domain: return 0, "UNKNOWN", ["Malformed or unsupported URL"]
    trusted, matched = is_whitelisted(url)
    if trusted: return 0, "LOW RISK", [f"Trusted domain: {matched}"]
    features, score, reasons = get_features(url), 0, []
    rules = (("has_ip", 40, "Raw IP address"), ("has_suspicious_tld", 25, "Suspicious TLD"), ("is_http", 20, "Uses HTTP"), ("too_many_hyphens", 15, "Excessive hyphens in domain"), ("has_high_risk_keyword", 20, "High-risk keyword"), ("has_medium_risk_keyword", 10, "Medium-risk keyword"), ("is_long_url", 10, "Long URL"))
    for key, weight, reason in rules:
        if features[key]: score += weight; reasons.append(reason)
    if domain in SHORTENERS: score += 20; reasons.append("URL shortener")
    if sum(c.isdigit() for c in domain) >= 5: score += 15; reasons.append("Excessive digits in domain")
    if len(domain) > 40: score += 10; reasons.append("Long domain")
    if re.search(r"(@|%40).+@", url.lower()): score += 15; reasons.append("Suspicious URL user-info structure")
    flags = sum(features.values())
    if flags >= 3: score += min(20, (flags - 2) * 10); reasons.append(f"Multiple risk indicators ({flags})")
    score = min(score, 100)
    return score, "HIGH RISK" if score > 60 else "SUSPICIOUS" if score > 30 else "LOW RISK", reasons
