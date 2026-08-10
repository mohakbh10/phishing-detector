import requests
from src.config import GOOGLE_SAFE_BROWSING_API_KEY, GOOGLE_SAFE_BROWSING_TIMEOUT
from src.utils import get_domain

def check_google_safe_browsing(url):
    if not get_domain(url): return {"available": False, "malicious": None, "error": "Could not extract domain"}
    if not GOOGLE_SAFE_BROWSING_API_KEY: return {"available": False, "malicious": None, "error": "GOOGLE_SAFE_BROWSING_API_KEY not configured"}
    payload={"client":{"clientId":"phishing-email-detector","clientVersion":"1.0"},"threatInfo":{"threatTypes":["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],"platformTypes":["ANY_PLATFORM"],"threatEntryTypes":["URL"],"threatEntries":[{"url":url}]}}
    try:
        response=requests.post("https://safebrowsing.googleapis.com/v4/threatMatches:find", params={"key":GOOGLE_SAFE_BROWSING_API_KEY}, json=payload, timeout=GOOGLE_SAFE_BROWSING_TIMEOUT)
        if response.status_code != 200: return {"available":False,"malicious":None,"error":f"Google Safe Browsing API error: {response.status_code}"}
        return {"available":True,"malicious":bool(response.json().get("matches")),"error":None}
    except requests.RequestException as exc: return {"available":False,"malicious":None,"error":f"Google Safe Browsing request failed: {exc.__class__.__name__}"}
    except ValueError: return {"available":False,"malicious":None,"error":"Google Safe Browsing returned invalid JSON"}
