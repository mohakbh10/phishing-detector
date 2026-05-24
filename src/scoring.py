import re

from src.utils import get_domain
from src.config import (
    HIGH_RISK_KEYWORDS,
    MEDIUM_RISK_KEYWORDS,
    SUSPICIOUS_TLDS,
    LOW_RISK_THRESHOLD,
    MEDIUM_RISK_THRESHOLD
)

from src.whitelist import is_whitelisted


def get_features(url):
    domain = get_domain(url)

    return {
        'has_ip': int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', domain))),
        'too_many_hyphens': int(domain.count('-') >= 2),
        'is_long_url': int(len(url) > 75),
        'has_high_risk_keyword': int(any(w in url.lower() for w in HIGH_RISK_KEYWORDS)),
        'has_medium_risk_keyword': int(any(w in url.lower() for w in MEDIUM_RISK_KEYWORDS)),
        'is_http': int(url.startswith('http://')),
        'has_suspicious_tld': int(domain.endswith(SUSPICIOUS_TLDS)),
    }

SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl"
]

def score_url(url):

    trusted, matched = is_whitelisted(url)

    if trusted:
        return 0, "✅ Whitelisted", [f"Trusted domain: {matched}"]

    features = get_features(url)

    score = 0
    reasons = []

    if features['has_ip']:
        score += 40
        reasons.append("Raw IP address in URL")

    if features['has_suspicious_tld']:
        score += 25
        reasons.append("Suspicious TLD")

    if features['is_http']:
        score += 20
        reasons.append("Uses HTTP")

    if features['too_many_hyphens']:
        score += 15
        reasons.append("Too many hyphens")

    if features['has_high_risk_keyword']:
        score += 20
        reasons.append("High-risk keyword")
    
    if any(short in domain for short in SHORTENERS):
        score += 20
        reasons.append("Shortened URL detected")

    elif features['has_medium_risk_keyword']:
        score += 10
        reasons.append("Medium-risk keyword")

    if features['is_long_url']:
        score += 10
        reasons.append("Long URL")

    flags = sum(features.values())

    if flags >= 3:
        bonus = (flags - 2) * 10
        score += bonus
        reasons.append(f"Combo bonus ({flags} flags)")

    if score <= LOW_RISK_THRESHOLD:
        verdict = "SAFE"
    elif score <= MEDIUM_RISK_THRESHOLD:
        verdict = "SUSPICIOUS"
    else:
        verdict = "PHISHING"

    return score, verdict, reasons