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

def score_url(url):

    domain = get_domain(url)

    if not domain:
        return 0, "INVALID URL", ["Could not extract domain"]

    trusted, matched = is_whitelisted(url)

    if trusted:
        return 0, "LOW RISK", [f"Trusted domain: {matched}"]

    features = get_features(url)

    score = 0
    reasons = []

    SHORTENERS = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl"
    ]

    try:

        if features['has_ip']:
            score += 40
            reasons.append("Raw IP address")

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

        elif features['has_medium_risk_keyword']:
            score += 10
            reasons.append("Medium-risk keyword")

        if features['is_long_url']:
            score += 10
            reasons.append("Long URL")

        if any(short in domain for short in SHORTENERS):
            score += 20
            reasons.append("Shortened URL")

        digit_count = sum(c.isdigit() for c in domain)

        if digit_count >= 5:
            score += 20
            reasons.append("Too many digits")

        if len(domain) > 25:
            score += 15
            reasons.append("Long domain")

        flags = sum(features.values())

        if flags >= 3:
            bonus = (flags - 2) * 10
            score += bonus
            reasons.append(f"Multiple risk indicators ({flags})")

    except Exception:
        return 0, "ERROR", ["Scoring engine failure"]

    if score <= 30:
        verdict = "LOW RISK"
    elif score <= 60:
        verdict = "SUSPICIOUS"
    else:
        verdict = "HIGH RISK"

    return score, verdict, reasons