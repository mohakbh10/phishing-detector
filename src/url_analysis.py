# %%
import re
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report


# %%
def extract_urls(text):
    pattern = r'https?://[^\s]+'
    return re.findall(pattern, text)

def get_domain(url):
    match = re.search(r'https?://([^\s/]+)', url)
    if match:
        return match.group(1)
    return ""

def get_features(url, label):
    domain = get_domain(url)
    keywords = ['login', 'verify', 'secure', 'account', 'update', 'confirm']
    suspicious_tlds = ('.tk', '.ml', '.ga', '.cf')

    features = {
        'has_ip': int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', domain))),
        'too_many_hyphens': int(domain.count('-') >= 2),
        'is_long_url': int(len(url) > 75),
        'has_keyword': int(any(word in url.lower() for word in keywords)),
        'is_http': int(url.startswith('http://')),
        'has_suspicious_tld': int(domain.endswith(suspicious_tlds)),  # small fix
        'label': label,
    }
    return features


# %%
urls = [
    ("https://www.google.com", 0),
    ("https://amazon.com/orders", 0),
    ("https://github.com/features", 0),
    ("https://stackoverflow.com/questions", 0),
    ("https://linkedin.com/in/profile", 0),
    ("https://reddit.com/r/python", 0),
    ("https://paypal-secure-login.fakesite.com/verify?id=123", 1),
    ("http://192.168.1.1/account/update", 1),
    ("http://secure-account-verify.paypa1.com/login/confirm?user=you", 1),
    ("http://apple-id-login-verify.tk/confirm?session=abc123xyz", 1),
    ("http://your-bank-account-suspended.ml/login", 1),
    ("https://netflix-account-update.fakesite.com/verify", 1),
    ("http://172.16.0.1/secure/account/login?user=victim", 1),
    ("https://amazon-order-confirm-login.suspicious.cf/update", 1),
    ("http://paypal.account-alert-verify.com/login?secure=true&id=999", 1),
]

rows = [get_features(url, label) for url, label in urls]
df = pd.DataFrame(rows)

# --- Step 1 ---
X = df.drop(columns=['label'])
y = df['label']

# --- Step 2 ---
print("Missing values:\n", X.isnull().sum())

# --- Step 3 ---
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.5, random_state=42
)

print(X_train)
print(X_test)
print(f"\nTraining samples: {len(X_train)}")
print(f"Testing samples:  {len(X_test)}")

# --- Step 4 ---
model = DecisionTreeClassifier(random_state=42)
model.fit(X_train, y_train)

# --- Step 5 ---
y_pred = model.predict(X_test)
print("\n--- Results ---")
print(classification_report(y_test, y_pred, target_names=['Legit', 'Phishing']))


# =====================================================
# 🔥 STEP 5: PREDICTING ON REAL EMAIL (ADDED PART)
# =====================================================

def predict_email(email_text, model):
    urls = extract_urls(email_text)

    if not urls:
        print("No URLs found in this email.")
        return

    print(f"Found {len(urls)} URL(s):\n")

    for url in urls:
        features = get_features(url, label=0)   # dummy label
        features.pop('label')                   # remove before prediction

        X_new = pd.DataFrame([features])

        prediction = model.predict(X_new)[0]
        probability = model.predict_proba(X_new)[0]

        status = "🚨 PHISHING" if prediction == 1 else "✅ LEGIT"
        confidence = probability[prediction] * 100

        print(f"URL: {url}")
        print(f"Result: {status} (confidence: {confidence:.0f}%)")
        print(f"Features: {features}\n")


# =====================================================
# 🧪 TEST EMAILS
# =====================================================

phishing_email = """
Dear Customer,
Your account has been suspended. Verify your identity immediately:
http://paypal-account-login-verify.ml/confirm?id=USER123
Failure to verify within 24 hours will result in permanent suspension.
"""

legit_email = """
Hey, just sharing some resources for your ML project:
Check out https://github.com/features and https://stackoverflow.com/questions
Both are super useful!
"""

print("\n" + "=" * 55)
print("PHISHING EMAIL TEST")
print("=" * 55)
predict_email(phishing_email, model)

print("\n" + "=" * 55)
print("LEGIT EMAIL TEST")
print("=" * 55)
predict_email(legit_email, model)