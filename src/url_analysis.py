import re

def extract_urls(text):
    pattern = r'https?://[^\s]+'
    return re.findall(pattern, text)

def get_domain(url):
    # Grabs just the domain from a full URL
    # "https://paypal.fakesite.com/login" → "paypal.fakesite.com"
    match = re.search(r'https?://([^\s/]+)', url)
    if match:
        return match.group(1)
    return ""

def is_suspicious(url):
    domain = get_domain(url)
    reasons = []

    # Check 1: IP address instead of domain name
    if re.search(r'\d+\.\d+\.\d+\.\d+', domain):
        reasons.append("uses raw IP address")

    # Check 2: Too many hyphens (common in fake domains)
    if domain.count('-') >= 2:
        reasons.append("too many hyphens in domain")

    # Check 3: URL is suspiciously long
    if len(url) > 75:
        reasons.append("URL is very long")

    # Check 4: Known suspicious keywords
    keywords = ['login', 'verify', 'secure', 'account', 'update', 'confirm']
    for word in keywords:
        if word in url.lower():
            reasons.append(f"contains suspicious keyword: '{word}'")
            break
    if url.startswith('http://'):
        reasons.append('http website not https no encryption')
    is_sus = len(reasons) > 0
    return is_sus, reasons

# --- Test it ---

urls = [
    "https://www.google.com",
    "https://paypal-secure-login.fakesite.com/verify?id=123",
    "http://192.168.1.1/account/update",
    "https://amazon.com/orders",
    "http://secure-account-verify.paypa1.com/login/confirm?user=you"
]

for url in urls:
    flagged, reasons = is_suspicious(url)
    status = "🚨 SUSPICIOUS" if flagged else "✅ OK"
    print(f"{status} — {url}")
    if reasons:
        for r in reasons:
            print(f"   → {r}")