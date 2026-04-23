import re
import pandas as pd

def extract_urls(text):
    pattern = r'https?://[^\s]+'
    return re.findall(pattern, text)

def get_domain(url):
    match = re.search(r'https?://([^\s/]+)', url)
    if match:
        return match.group(1)
    return ""

def get_features(url,label):
    domain = get_domain(url)
    keywords = ['login', 'verify', 'secure', 'account', 'update', 'confirm']
    suspicious_tlds = ('.tk', '.ml', '.ga', '.cf')


    features = { #dictionary
        'has_ip':          int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', domain))),
        'too_many_hyphens': int(domain.count('-') >= 2),
        'is_long_url':     int(len(url) > 75),
        'has_keyword':     int(any(word in url.lower() for word in keywords)),
        'is_http':         int(url.startswith('http://')),
        'has_suspicious_tld': int(url.endswith(suspicious_tlds)),
        'label':            label, 
    }
    return features


# --- Build a dataset from a list of URLs ---

urls = [
    ("https://www.google.com",                                              0),
    ("https://paypal-secure-login.fakesite.com/verify?id=123",              1),
    ("http://192.168.1.1/account/update",                                   1),
    ("https://amazon.com/orders",                                           0),
    ("http://secure-account-verify.paypa1.com/login/confirm?user=you",      1),
]


rows = [get_features(url, label) for url, label in urls]
df = pd.DataFrame(rows)
df.insert(0, 'url', [u for u, _ in urls])

print(df.to_string(index=False))