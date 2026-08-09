import email
from email import policy
import re
from src.utils import extract_urls

def parse_eml(file_content):
    # Safe parsing using Python's standard email package
    msg = email.message_from_bytes(file_content, policy=policy.default)
    
    headers = {
        "From": msg.get("From"),
        "To": msg.get("To"),
        "Subject": msg.get("Subject"),
        "Date": msg.get("Date"),
        "Reply-To": msg.get("Reply-To"),
        "Return-Path": msg.get("Return-Path"),
        "Message-ID": msg.get("Message-ID"),
        "Authentication-Results": msg.get("Authentication-Results"),
    }
    
    # Received headers (multiple)
    received = msg.get_all("Received", [])
    
    body_text = ""
    body_html = ""
    attachments = []
    mime_structure = []
    
    for part in msg.walk():
        content_type = part.get_content_type()
        content_disposition = str(part.get("Content-Disposition", ""))
        filename = part.get_filename()

        # Capture MIME structure
        mime_structure.append({
            "content_type": content_type,
            "filename": filename,
            "is_multipart": part.is_multipart()
        })

        if "attachment" in content_disposition or filename:
            payload = part.get_payload(decode=True)
            if payload is not None:
                attachments.append({
                    "filename": filename or "unnamed_attachment",
                    "mime_type": content_type,
                    "content": payload
                })
            continue

        if content_type == "text/plain":
            payload = part.get_payload(decode=True)
            if payload:
                body_text += payload.decode(errors='replace')
        elif content_type == "text/html":
            payload = part.get_payload(decode=True)
            if payload:
                body_html += payload.decode(errors='replace')

    # If no plain text body but we have HTML, fallback/strip HTML or just use HTML to find URLs
    urls = set(extract_urls(body_text))
    urls.update(extract_urls(body_html))

    # Parse Authentication indicators
    auth_indicators = extract_auth_indicators(msg)

    return {
        "headers": headers,
        "received": received,
        "body_text": body_text,
        "body_html_present": bool(body_html),
        "urls": list(urls),
        "attachments": attachments,
        "mime_structure": mime_structure,
        "auth_indicators": auth_indicators,
        "raw_msg": msg # Keep for header analysis get_all/get calls
    }

def extract_auth_indicators(msg):
    spf_status = None
    dkim_status = None
    dmarc_status = None

    auth_results_list = msg.get_all("Authentication-Results", [])
    received_spf_list = msg.get_all("Received-SPF", [])
    
    # Extract from Authentication-Results
    for auth in auth_results_list:
        auth_lower = auth.lower()
        
        spf_match = re.search(r'\bspf=([a-z]+)', auth_lower)
        if spf_match and not spf_status:
            spf_status = spf_match.group(1)
        
        dkim_match = re.search(r'\bdkim=([a-z]+)', auth_lower)
        if dkim_match and not dkim_status:
            dkim_status = dkim_match.group(1)
            
        dmarc_match = re.search(r'\bdmarc=([a-z]+)', auth_lower)
        if dmarc_match and not dmarc_status:
            dmarc_status = dmarc_match.group(1)

    # Fallback to Received-SPF headers if SPF still not identified
    for spf_header in received_spf_list:
        spf_lower = spf_header.lower()
        for verdict in ["pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"]:
            if verdict in spf_lower:
                if not spf_status:
                    spf_status = verdict
                break

    return {
        "spf": spf_status,
        "dkim": dkim_status,
        "dmarc": dmarc_status
    }

