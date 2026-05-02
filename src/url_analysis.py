# ============================================================
# PHISHING EMAIL DETECTOR
# ============================================================
# HOW THIS FILE IS ORGANIZED:
#
#   PART 1 — IMPORTS
#   PART 2 — WHITELIST (trusted domains)
#   PART 3 — HELPER FUNCTIONS (get_domain, extract_urls)
#   PART 4 — FEATURE EXTRACTION (get_features)
#              ↑ single source of truth for ALL checks
#   PART 5 — SCORING (score_url)
#              ↑ reuses get_features, no repeated checks
#   PART 6 — REDIRECT CHAIN FOLLOWER (get_redirect_chain)
#   PART 7 — FULL EMAIL PREDICTOR (predict_email)
#   PART 8 — TRAINING THE MODEL
#   PART 9 — RUNNING EVERYTHING
# ============================================================


# ============================================================
# PART 1 — IMPORTS
# ============================================================

import re
import requests
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report


# ============================================================
# PART 2 — WHITELIST
# ============================================================
# WHY WHITELISTS MATTER IN REAL SYSTEMS:
#
# Without a whitelist, your detector will flag legitimate emails.
# Example: your bank sends you "https://secure.bankofamerica.com/login"
# That URL has "login" and "secure" — both red flags in our system.
# But it's a completely real, trusted website.
#
# This is called a FALSE POSITIVE — flagging something legit as phishing.
# False positives are a big problem because:
#   1. Users start ignoring warnings (the "cry wolf" effect)
#   2. Real phishing slips through because users stop trusting alerts
#   3. Legitimate emails get blocked, causing frustration
#
# A whitelist says: "I already know these domains are safe.
# Don't run any checks — just trust them immediately."
# ============================================================

WHITELISTED_DOMAINS = [
    # Big tech
    "google.com", "gmail.com", "youtube.com",
    "microsoft.com", "apple.com", "github.com", "stackoverflow.com",
    # Shopping
    "amazon.com", "ebay.com", "etsy.com",
    # Social
    "linkedin.com", "reddit.com", "twitter.com",
    "facebook.com", "instagram.com",
    # Banking (real ones)
    "paypal.com", "chase.com", "bankofamerica.com",
    # Entertainment
    "netflix.com", "spotify.com",
]


def is_whitelisted(url):
    """
    Checks if a URL belongs to a trusted domain.

    WHY "ends with" AND NOT "equals":
    Because subdomains should also be trusted.
    "mail.google.com" ends with ".google.com" → trusted ✅
    But "google.com.fakesite.com" does NOT end with ".google.com" → not trusted 🚨

    This catches a common phishing trick:
    "paypal.com.steal-login.tk" — looks like paypal at first glance, but isn't.

    Returns: (is_trusted, matched_domain)
    """
    domain = get_domain(url)

    if not domain:
        return False, None

    # Remove port number if present ("google.com:8080" → "google.com")
    domain = domain.split(':')[0]

    for trusted in WHITELISTED_DOMAINS:
        if domain == trusted or domain.endswith('.' + trusted):
            return True, trusted

    return False, None


# ============================================================
# PART 3 — HELPER FUNCTIONS
# ============================================================

def extract_urls(text):
    """
    Scans a block of text and returns all URLs found in it.
    "Click here: https://google.com" → ['https://google.com']
    """
    pattern = r'https?://[^\s]+'
    # https?   → matches http or https (s is optional due to ?)
    # ://      → literal colon-slash-slash
    # [^\s]+   → any character that is NOT a space, one or more times
    return re.findall(pattern, text)


def get_domain(url):
    """
    Pulls out just the domain from a full URL.
    "https://paypal.fakesite.com/login" → "paypal.fakesite.com"
    """
    match = re.search(r'https?://([^\s/]+)', url)
    if match:
        return match.group(1)   # group(1) returns what was inside the ( )
    return ""


# ============================================================
# PART 4 — FEATURE EXTRACTION
# ============================================================
# THIS IS THE ONLY PLACE WHERE CHECKS ARE WRITTEN.
# Both the scoring system and the ML model use this function.
#
# ---- BUG THAT WAS FIXED ----
# In the previous version, the model was trained with 'has_keyword'
# as one column. Then we refactored to 'has_high_risk_keyword' and
# 'has_medium_risk_keyword' — but didn't retrain the model.
# Result: prediction used different columns than training → wrong results.
#
# FIX: get_features() is now the single source of truth.
# Training uses it. Prediction uses it. Columns always match.
# ============================================================

def get_features(url, label=None):
    """
    Runs all phishing checks on a URL.
    Returns a dictionary where every value is 0 (not present) or 1 (present).

    label=0 → legit (used when training)
    label=1 → phishing (used when training)
    label=None → we don't know yet (used when predicting)
    """
    domain = get_domain(url)

    # Two tiers of keyword risk
    high_risk_keywords   = ['verify', 'confirm', 'suspend']   # almost always phishing
    medium_risk_keywords = ['login', 'secure', 'account', 'update']  # sometimes legit

    suspicious_tlds = ('.tk', '.ml', '.ga', '.cf')  # free domains abused by phishers

    features = {
        # Real websites use domain names, not raw IPs
        'has_ip': int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', domain))),

        # Fake domains love hyphens: "paypal-secure-login.com"
        'too_many_hyphens': int(domain.count('-') >= 2),

        # Phishing URLs tend to be long with lots of junk parameters
        'is_long_url': int(len(url) > 75),

        # "verify your account immediately!" is a classic phishing tactic
        'has_high_risk_keyword': int(any(w in url.lower() for w in high_risk_keywords)),

        # Common in phishing but also appears on legitimate sites
        'has_medium_risk_keyword': int(any(w in url.lower() for w in medium_risk_keywords)),

        # Legitimate sites almost always use HTTPS now
        'is_http': int(url.startswith('http://')),

        # Free domains heavily abused by phishers
        'has_suspicious_tld': int(domain.endswith(suspicious_tlds)),
    }

    # Only add label when training — not when predicting
    if label is not None:
        features['label'] = label

    return features


# ============================================================
# PART 5 — SCORING SYSTEM
# ============================================================
# Converts feature checks into a human-readable risk score.
# Reuses get_features() so no logic is ever duplicated.
#
# WHITELIST INTEGRATION:
# Whitelisted URLs skip all checks and return score = 0.
# This prevents false positives on trusted domains like paypal.com
# which naturally contain words like "login" and "secure".
# ============================================================

def score_url(url):
    """
    Scores a URL from 0 to 135+ based on phishing risk.
    Whitelisted URLs automatically score 0.
    Returns: (score, verdict, reasons)
    """

    # Always check whitelist FIRST — if trusted, skip everything
    trusted, matched = is_whitelisted(url)
    if trusted:
        return 0, "✅ Whitelisted (trusted domain)", [f"Matched trusted domain: {matched}"]

    # Use get_features() — the single source of truth
    features = get_features(url)

    score = 0
    reasons = []

    if features['has_ip']:
        score += 40
        reasons.append("+40  Raw IP address in URL")

    if features['has_suspicious_tld']:
        score += 25
        reasons.append("+25  Suspicious domain ending (.tk/.ml/.ga/.cf)")

    if features['is_http']:
        score += 20
        reasons.append("+20  Uses HTTP not HTTPS")

    if features['too_many_hyphens']:
        score += 15
        reasons.append("+15  Too many hyphens in domain")

    # High-risk keywords score more than medium-risk
    if features['has_high_risk_keyword']:
        score += 20
        reasons.append("+20  High-risk keyword (verify/confirm/suspend)")
    elif features['has_medium_risk_keyword']:
        score += 10
        reasons.append("+10  Medium-risk keyword (login/account/update)")

    if features['is_long_url']:
        score += 10
        reasons.append("+10  URL is unusually long")

    # Combo bonus — multiple red flags together = extra suspicious
    # 3 red flags at once is WAY worse than 3 separate single-flag URLs
    number_of_flags = sum(features.values())  # count how many features are 1

    if number_of_flags >= 3:
        bonus = (number_of_flags - 2) * 10
        score += bonus
        reasons.append(f"+{bonus}  Combo bonus ({number_of_flags} flags at once)")

    # Convert score to a verdict
    if score <= 30:
        verdict = "✅ Low Risk"
    elif score <= 60:
        verdict = "⚠️  Moderate Risk"
    else:
        verdict = "🚨 High Risk"

    return score, verdict, reasons


# ============================================================
# PART 6 — REDIRECT CHAIN FOLLOWER
# ============================================================

def get_redirect_chain(url, max_hops=10, timeout=5):
    """
    Follows a URL step by step, recording every redirect hop.
    Phishers hide behind redirect chains — we follow each hop.
    Returns: (chain_of_urls, error_message_or_None)
    """
    chain = [url]
    current_url = url
    headers = {'User-Agent': 'Mozilla/5.0'}  # look like a real browser

    try:
        for _ in range(max_hops):  # max_hops prevents infinite loops

            # allow_redirects=False = take ONE step, don't auto-follow
            response = requests.get(
                current_url,
                allow_redirects=False,
                timeout=timeout,
                headers=headers
            )

            # Not a redirect status code — we've arrived, stop
            if response.status_code not in (301, 302, 303, 307, 308):
                break

            # Next destination is in the "Location" header
            next_url = response.headers.get('Location')

            if not next_url:
                break  # server said redirect but gave no destination

            # Fix partial paths like "/login" → "https://site.com/login"
            if next_url.startswith('/'):
                from urllib.parse import urlparse
                parsed = urlparse(current_url)
                next_url = f"{parsed.scheme}://{parsed.netloc}{next_url}"

            chain.append(next_url)
            current_url = next_url

        return chain, None  # None = no error

    except requests.exceptions.Timeout:
        return chain, "Took too long to respond"
    except requests.exceptions.ConnectionError:
        return chain, "Could not reach this URL"
    except requests.exceptions.MissingSchema:
        return chain, "URL is missing http:// at the start"
    except Exception as e:
        return chain, f"Something went wrong: {str(e)}"


# ============================================================
# PART 7 — FULL EMAIL PREDICTOR
# ============================================================

def predict_email(email_text, model):
    """
    Analyzes a raw email for phishing URLs.
    For each URL: checks whitelist → follows redirect chain
    → runs ML model + scoring on every hop → gives final verdict.
    """
    urls = extract_urls(email_text)

    if not urls:
        print("No URLs found in this email.")
        return

    print(f"Found {len(urls)} URL(s) in email.\n")

    for original_url in urls:
        print(f"{'='*60}")
        print(f"Original URL: {original_url}")

        # Whitelist check BEFORE following redirects or running model
        trusted, matched = is_whitelisted(original_url)
        if trusted:
            print(f"  ✅ WHITELISTED — trusted domain ({matched}), skipping checks.\n")
            continue  # skip to the next URL

        # Follow the redirect chain
        chain, error = get_redirect_chain(original_url)

        if error:
            print(f"  Could not follow redirects: {error}")
            print(f"  Checking original URL only...")
            chain = [original_url]

        print(f"\n  Redirect chain ({len(chain)} hop(s)):")
        for i, hop in enumerate(chain):
            tag = "START" if i == 0 else f"HOP {i}"
            print(f"    {tag} → {hop}")

        print(f"\n  Checking each hop:")

        any_suspicious = False  # one suspicious hop = whole email flagged

        for hop_url in chain:

            # Whitelist check for each hop too —
            # a redirect might land on a trusted domain
            hop_trusted, hop_matched = is_whitelisted(hop_url)
            if hop_trusted:
                print(f"\n    ✅ WHITELISTED hop ({hop_matched}) → {hop_url}")
                continue

            # ML prediction
            features = get_features(hop_url)  # no label — predicting
            X_new = pd.DataFrame([features])
            prediction = model.predict(X_new)[0]
            probability = model.predict_proba(X_new)[0]
            confidence = probability[prediction] * 100

            # Risk score
            score, verdict, reasons = score_url(hop_url)

            ml_result = "🚨 PHISHING" if prediction == 1 else "✅ LEGIT"
            print(f"\n    URL: {hop_url}")
            print(f"    ML Model  : {ml_result} ({confidence:.0f}% confidence)")
            print(f"    Risk Score: {score} → {verdict}")
            for r in reasons:
                print(f"      {r}")

            if prediction == 1:
                any_suspicious = True
                flagged = [f for f, v in features.items() if v == 1]
                print(f"    ML triggered by: {', '.join(flagged)}")

        print(f"\n  FINAL VERDICT: {'🚨 PHISHING EMAIL' if any_suspicious else '✅ LEGIT EMAIL'}")
        print()
#for backend api
def analyze_email_api(email_text):
    urls = extract_urls(email_text)

    total_url_score = 0
    url_results = []

    for url in urls:
        score, verdict, reasons = score_url(url)

        features = get_features(url)
        X_new = pd.DataFrame([features])

        prediction = model.predict(X_new)[0]
        probability = model.predict_proba(X_new)[0]

        url_results.append({
            "url": url,
            "prediction": int(prediction),
            "confidence": float(probability[prediction]),
            "score": score,
            "verdict": verdict,
            "reasons": reasons
        })

        total_url_score += score

    # 🔹 Fake for now (until UI supports real input)
    attachment_score = 0
    header_score = 0

    total_score = total_url_score + attachment_score + header_score

    # 🔹 Final classification
    if total_score <= 40:
        final_verdict = "SAFE"
    elif total_score <= 80:
        final_verdict = "SUSPICIOUS"
    else:
        final_verdict = "PHISHING"

    return {
        "final_verdict": final_verdict,
        "total_score": total_score,
        "url_results": url_results
    }

# ============================================================
# PART 8 — TRAINING THE MODEL
# ============================================================
# Training uses get_features() to build feature rows.
# Prediction also uses get_features().
# → Columns always match. The previous bug cannot happen again.
# ============================================================

urls_data = [
    ("https://www.google.com",                                              0),
    ("https://amazon.com/orders",                                           0),
    ("https://github.com/features",                                         0),
    ("https://stackoverflow.com/questions",                                 0),
    ("https://linkedin.com/in/profile",                                     0),
    ("https://reddit.com/r/python",                                         0),
    ("https://paypal-secure-login.fakesite.com/verify?id=123",              1),
    ("http://192.168.1.1/account/update",                                   1),
    ("http://secure-account-verify.paypa1.com/login/confirm?user=you",      1),
    ("http://apple-id-login-verify.tk/confirm?session=abc123xyz",           1),
    ("http://your-bank-account-suspended.ml/login",                         1),
    ("https://netflix-account-update.fakesite.com/verify",                  1),
    ("http://172.16.0.1/secure/account/login?user=victim",                  1),
    ("https://amazon-order-confirm-login.suspicious.cf/update",             1),
    ("http://paypal.account-alert-verify.com/login?secure=true&id=999",     1),
]

rows = [get_features(url, label) for url, label in urls_data]
df = pd.DataFrame(rows)

X = df.drop(columns=['label'])
y = df['label']

print("Missing values:\n", X.isnull().sum())

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

print(f"\nTraining samples: {len(X_train)}")
print(f"Testing samples:  {len(X_test)}")

model = DecisionTreeClassifier(random_state=42)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print("\n--- Model Results ---")
print(classification_report(y_test, y_pred, target_names=['Legit', 'Phishing']))

if __name__ == "__main__":
    # ============================================================
    # PART 9 — RUNNING EVERYTHING
    # ============================================================

    # --- Whitelist demo: show what gets trusted and what doesn't ---
    print("\n" + "="*60)
    print("WHITELIST DEMO")
    print("="*60)

    demo_urls = [
        "https://paypal.com/login",                      # real paypal — trusted
        "https://paypal-login.fakesite.com/verify",      # fake paypal — not trusted
        "https://mail.google.com/inbox",                 # subdomain — trusted
        "https://google.com.phishing-site.tk/steal",     # sneaky fake — not trusted
    ]

    for url in demo_urls:
        trusted, matched = is_whitelisted(url)
        status = f"✅ Trusted (matched: {matched})" if trusted else "🚨 Not whitelisted"
        print(f"  {status}")
        print(f"  → {url}\n")

    # --- Scoring demo ---
    print("="*60)
    print("SCORING DEMO")
    print("="*60)

    score_test_urls = [
        "https://paypal.com/login",                               # whitelisted → score 0
        "http://paypal-secure.fakesite.com/login",                # moderate risk
        "http://192.168.1.1/account/update",                      # high risk
        "http://verify-account-login.suspicious.tk/confirm?id=123abc",  # very high risk
    ]

    for url in score_test_urls:
        score, verdict, reasons = score_url(url)
        print(f"\nURL: {url}")
        print(f"Score: {score} → {verdict}")
        for r in reasons:
            print(f"  {r}")

    # --- Full email tests ---
    phishing_email = """
    Dear Customer, your account has been suspended.
    Verify immediately: http://paypal-account-login-verify.ml/confirm?id=USER123
    """

    # This would have been a FALSE POSITIVE before the whitelist
    tricky_email = """
    Your PayPal account needs attention.
    Please login at https://paypal.com/login to review.
    """

    legit_email = """
    Great ML resources:
    https://github.com/features and https://stackoverflow.com/questions
    """

    print("\n" + "="*60)
    print("TEST 1 — OBVIOUS PHISHING EMAIL")
    print("="*60)
    predict_email(phishing_email, model)

    print("="*60)
    print("TEST 2 — TRICKY EMAIL (would be false positive without whitelist)")
    print("="*60)
    predict_email(tricky_email, model)

    print("="*60)
    print("TEST 3 — LEGIT EMAIL")
    print("="*60)
    predict_email(legit_email, model)