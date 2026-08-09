import os

# Whitelist of trusted domains
WHITELISTED_DOMAINS = [
    "google.com",
    "github.com",
    "stackoverflow.com",
    "amazon.com",
    "paypal.com",
    "linkedin.com",
    "reddit.com",
    "microsoft.com",
    "apple.com",
    "netflix.com",
    "facebook.com",
    "twitter.com",
    "instagram.com"
]

# URL Heuristics
HIGH_RISK_KEYWORDS = ['verify', 'confirm', 'suspend', 'billing', 'invoice', 'security', 'password', 'login', 'signin']
MEDIUM_RISK_KEYWORDS = ['account', 'update', 'secure', 'alert', 'notice', 'banking', 'payment']
SUSPICIOUS_TLDS = ('.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.pw', '.loan', '.click', '.zip')

# Thresholds
LOW_RISK_THRESHOLD = 30
MEDIUM_RISK_THRESHOLD = 60

# Weights
URL_RISK_WEIGHT = 0.7
HEADER_RISK_WEIGHT = 0.2
ATTACHMENT_RISK_WEIGHT = 0.1

# External APIs
URLSCAN_API_KEY = os.environ.get("URLSCAN_API_KEY")
URLSCAN_TIMEOUT = 10

# Redirect Analysis
REDIRECT_MAX_HOPS = 10
REDIRECT_TIMEOUT = 5

# Attachment Analysis
SUSPICIOUS_EXTENSIONS = {
    '.exe', '.scr', '.bat', '.cmd', '.js', '.vbs',
    '.ps1', '.zip', '.rar', '.iso', '.img', '.docm', '.xlsm',
    '.jar', '.msi', '.pif', '.com', '.gadget', '.vb', '.vbe',
    '.jse', '.ws', '.wsf', '.wsc', '.wsh', '.msc', '.msp'
}

