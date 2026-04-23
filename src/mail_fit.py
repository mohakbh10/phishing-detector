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


# %%

urls = [
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

rows = [get_features(url, label) for url, label in urls]
df = pd.DataFrame(rows)

# --- Step 1: Separate features (X) and labels (y) ---
X = df.drop(columns=['label'])
y = df['label']

# --- Step 2: Check for missing values ---
print("Missing values:\n", X.isnull().sum())

# --- Step 3: Train/test split ---
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.5, random_state=42
)
print (X_train)
print (X_test)
print(f"\nTraining samples: {len(X_train)}")
print(f"Testing samples:  {len(X_test)}")

# --- Step 4: Train the model ---
model = DecisionTreeClassifier(random_state=42)
model.fit(X_train, y_train)

# --- Step 5: Evaluate ---
y_pred = model.predict(X_test)
print("\n--- Results ---")
print(classification_report(y_test, y_pred, target_names=['Legit', 'Phishing']))


