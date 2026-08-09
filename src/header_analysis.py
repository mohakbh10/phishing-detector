import re
from email.utils import parseaddr
from src.config import SUSPICIOUS_TLDS

def analyze_headers(msg):
    findings, risk_score = [], 0

    def get_header(name):
        val = msg.get(name, '')
        return val[0] if isinstance(val, list) else str(val) if val else ''

    from_header = get_header('From')
    reply_to = get_header('Reply-To')
    return_path = get_header('Return-Path')

    display_name, sender_email = parseaddr(from_header)
    sender_domain = extract_domain_from_email(sender_email)

    # 1. Display-name / brand spoofing
    if display_name:
        dn_lower = display_name.lower()
        email_match = re.search(r'([a-zA-Z0-9.-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', display_name)
        if email_match:
            disp_email = email_match.group(1).lower()
            disp_domain = extract_domain_from_email(disp_email)
            if disp_domain and sender_domain and disp_domain != sender_domain:
                findings.append({
                    "type": "display_name_email_spoof",
                    "severity": "high",
                    "message": f"Display name contains spoofed email ({disp_email}) differing from actual sender ({sender_email})"
                })
                risk_score += 35

        BRANDS = ["paypal", "google", "microsoft", "apple", "amazon", "netflix", "linkedin", "github", "facebook", "chase", "bankofamerica"]
        for brand in BRANDS:
            if brand in dn_lower and sender_domain and brand not in sender_domain:
                findings.append({
                    "type": "brand_spoofing",
                    "severity": "high",
                    "message": f"Display name contains brand '{brand.capitalize()}', but sender domain ({sender_domain}) does not match"
                })
                risk_score += 30
                break

    # 2. From vs Reply-To mismatch
    if from_header and reply_to:
        _, reply_email = parseaddr(reply_to)
        reply_domain = extract_domain_from_email(reply_email)
        if sender_domain and reply_domain and sender_domain != reply_domain:
            findings.append({
                "type": "reply_to_mismatch",
                "severity": "medium",
                "message": f"Reply-To domain ({reply_domain}) differs from sender domain ({sender_domain})"
            })
            risk_score += 20

    # 3. Return-Path mismatch
    if from_header and return_path and return_path != '<>':
        ret_domain = extract_domain_from_email(return_path.strip('<>'))
        if sender_domain and ret_domain and sender_domain != ret_domain:
            findings.append({
                "type": "return_path_mismatch",
                "severity": "medium",
                "message": f"Return-Path domain ({ret_domain}) differs from sender domain ({sender_domain})"
            })
            risk_score += 15

    # 4. Suspicious domain characteristics
    if sender_domain:
        if sender_domain.endswith(SUSPICIOUS_TLDS):
            findings.append({
                "type": "suspicious_sender_tld",
                "severity": "high",
                "message": f"Sender domain has suspicious TLD ({sender_domain})"
            })
            risk_score += 25
        if re.search(r'\d+\.\d+\.\d+\.\d+', sender_domain):
            findings.append({
                "type": "sender_ip_address",
                "severity": "high",
                "message": f"Sender domain is a raw IP ({sender_domain})"
            })
            risk_score += 35

    # 5. Auth analysis
    auth_list = msg.get_all('Authentication-Results', [])
    spf_list = msg.get_all('Received-SPF', [])
    
    spf, dkim, dmarc = None, None, None
    for auth in auth_list:
        auth_lower = auth.lower()
        if not spf:
            m = re.search(r'\bspf=([a-z]+)', auth_lower)
            if m: spf = m.group(1)
        if not dkim:
            m = re.search(r'\bdkim=([a-z]+)', auth_lower)
            if m: dkim = m.group(1)
        if not dmarc:
            m = re.search(r'\bdmarc=([a-z]+)', auth_lower)
            if m: dmarc = m.group(1)

    for s_hdr in spf_list:
        if not spf:
            s_lower = s_hdr.lower()
            for v in ["pass", "fail", "softfail", "neutral", "none"]:
                if v in s_lower:
                    spf = v
                    break

    if spf in ['fail', 'softfail']:
        findings.append({"type": "spf_fail", "severity": "high", "message": f"SPF authentication failed ({spf})"})
        risk_score += 30
    elif not spf:
        findings.append({"type": "spf_missing", "severity": "info", "message": "SPF results missing"})

    if dkim == 'fail':
        findings.append({"type": "dkim_fail", "severity": "high", "message": "DKIM authentication failed"})
        risk_score += 30
    elif not dkim:
        findings.append({"type": "dkim_missing", "severity": "info", "message": "DKIM results missing"})

    if dmarc == 'fail':
        findings.append({"type": "dmarc_fail", "severity": "high", "message": "DMARC authentication failed"})
        risk_score += 35
    elif not dmarc:
        findings.append({"type": "dmarc_missing", "severity": "info", "message": "DMARC results missing"})

    # 6. Received Hops
    rec_headers = msg.get_all('Received', [])
    if len(rec_headers) > 10:
        findings.append({
            "type": "excessive_hops",
            "severity": "low",
            "message": f"High number of relay hops ({len(rec_headers)})"
        })
        risk_score += 10

    return {
        "risk_score": min(risk_score, 100),
        "findings": findings,
        "auth_status": {"spf": spf, "dkim": dkim, "dmarc": dmarc}
    }

def extract_domain_from_email(email_str):
    if not email_str: return None
    match = re.search(r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', email_str)
    return match.group(1).lower() if match else None

