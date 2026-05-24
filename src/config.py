WHITELISTED_DOMAINS = [
    "google.com",
    "github.com",
    "stackoverflow.com",
    "amazon.com",
    "paypal.com",
    "linkedin.com",
    "reddit.com",
]

HIGH_RISK_KEYWORDS = ['verify', 'confirm', 'suspend']
MEDIUM_RISK_KEYWORDS = ['login', 'secure', 'account', 'update']

SUSPICIOUS_TLDS = ('.tk', '.ml', '.ga', '.cf')

LOW_RISK_THRESHOLD = 30
MEDIUM_RISK_THRESHOLD = 60