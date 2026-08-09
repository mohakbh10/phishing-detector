from src.utils import extract_urls, get_domain
from src.whitelist import is_whitelisted
from src.scoring import score_url
from src.redirects import get_redirect_chain
from src.urlscan import check_urlscan
from src.header_analysis import analyze_headers
from src.attachment_analysis import analyze_attachments
from src.analyzer import analyze_url_full, aggregate_risk
from src.email_parser import parse_eml

def run_tests():
    print("==================================================")
    print("RUNNING BACKEND ENGINE UNIT TESTS")
    print("==================================================")

    # 1. Utilities
    print("\n--- 1. Testing Utilities ---")
    urls = extract_urls("Please click: https://google.com/test and http://192.168.1.1/login.")
    print("Extracted URLs:", urls)
    assert "https://google.com/test" in urls
    assert "http://192.168.1.1/login" in urls
    assert get_domain("https://mail.google.com/inbox") == "mail.google.com"
    assert get_domain("http://192.168.1.1:8080/index.html") == "192.168.1.1"

    # 2. Whitelist
    print("\n--- 2. Testing Whitelist ---")
    assert is_whitelisted("https://google.com/")[0] is True
    assert is_whitelisted("https://sub.google.com/path")[0] is True
    assert is_whitelisted("https://google.com.evil.com/")[0] is False
    assert is_whitelisted("https://evilgoogle.com/")[0] is False

    # 3. Scoring
    print("\n--- 3. Testing Heuristics ---")
    legit_s, legit_v, legit_r = score_url("https://github.com/features")
    assert legit_v == "LOW RISK"
    phish_s, phish_v, phish_r = score_url("http://paypal-account-verify.tk/login")
    assert phish_v == "HIGH RISK"
    ip_s, ip_v, ip_r = score_url("http://192.168.1.1/update")
    assert ip_v == "HIGH RISK"

    # 4. Redirects
    print("\n--- 4. Testing Redirects ---")
    chain, err = get_redirect_chain("https://github.com", max_hops=3)
    print(f"Github Redirect Chain: {chain} (Error: {err})")
    assert len(chain) >= 1

    # 5. urlscan
    print("\n--- 5. Testing urlscan.io ---")
    scan_res = check_urlscan("https://google.com")
    print("urlscan.io response:", scan_res)
    assert scan_res["available"] is False
    assert "not configured" in scan_res["error"]

    # 6. Header Analysis
    print("\n--- 6. Testing Header Analysis ---")
    class DummyMsg:
        def __init__(self, headers, received=None, auth_results=None, received_spf=None):
            self.headers = headers
            self._received = received or []
            self._auth_results = auth_results or []
            self._received_spf = received_spf or []
        def get(self, name, default=''):
            return self.headers.get(name, default)
        def get_all(self, name, default=None):
            if name == 'Received': return self._received
            if name == 'Authentication-Results': return self._auth_results
            if name == 'Received-SPF': return self._received_spf
            val = self.headers.get(name)
            return [val] if val else default or []

    msg_spoof = DummyMsg({"From": '"PayPal Support" <attacker@gmail.com>'})
    h_analysis = analyze_headers(msg_spoof)
    assert any(f['type'] == 'brand_spoofing' for f in h_analysis['findings'])
    assert h_analysis['risk_score'] >= 30

    msg_mismatch = DummyMsg({"From": "<support@paypal.com>", "Reply-To": "attacker@gmail.com"})
    h_mismatch = analyze_headers(msg_mismatch)
    assert any(f['type'] == 'reply_to_mismatch' for f in h_mismatch['findings'])

    msg_fail = DummyMsg({
        "From": "<support@paypal.com>",
        "Authentication-Results": "mx.google.com; spf=fail; dkim=fail; dmarc=fail"
    }, auth_results=["mx.google.com; spf=fail; dkim=fail; dmarc=fail"])
    h_fail = analyze_headers(msg_fail)
    assert any(f['type'] == 'spf_fail' for f in h_fail['findings'])
    assert any(f['type'] == 'dkim_fail' for f in h_fail['findings'])
    assert any(f['type'] == 'dmarc_fail' for f in h_fail['findings'])

    # 7. Attachments
    print("\n--- 7. Testing Attachment Analysis ---")
    atts = [
        {"filename": "invoice.pdf", "content": b"PDF", "mime_type": "application/pdf"},
        {"filename": "malware.exe", "content": b"EXE", "mime_type": "application/octet-stream"}
    ]
    att_res = analyze_attachments(atts)
    assert att_res['attachment_results'][0]['risk'] == 'LOW RISK'
    assert att_res['attachment_results'][1]['risk'] == 'SUSPICIOUS'
    assert att_res['attachment_risk_score'] == 25

    # 8. EML Parsing
    print("\n--- 8. Testing EML Parser ---")
    eml_raw = b"""From: "GitHub Security" <noreply@github.com>
To: user@example.com
Subject: Security alert!
Date: Mon, 9 Aug 2026 12:00:00 +0000
Message-ID: <123456@github.com>
Content-Type: multipart/mixed; boundary="boundary"

--boundary
Content-Type: text/plain; charset=utf-8

Please verify immediately: https://github.com/login?secure=true
Also find your invoice attached.

--boundary
Content-Type: application/octet-stream; name="invoice.exe"
Content-Disposition: attachment; filename="invoice.exe"

EXE-BYTES
--boundary--
"""
    parsed = parse_eml(eml_raw)
    assert "https://github.com/login?secure=true" in parsed['urls']
    assert len(parsed['attachments']) == 1
    assert parsed['attachments'][0]['filename'] == "invoice.exe"

    print("\n==================================================")
    print("ALL TESTS COMPLETED SUCCESSFULLY!")
    print("==================================================")

if __name__ == "__main__":
    run_tests()
