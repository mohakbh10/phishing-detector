import hashlib
from src.config import SUSPICIOUS_EXTENSIONS

def analyze_attachments(attachments):
    results = []
    total_risk_score = 0

    if not attachments:
        return {
            "attachment_results": [],
            "attachment_risk_score": 0
        }

    for att in attachments:
        filename = att.get('filename') or 'unknown'
        content = att.get('content', b'')
        mime_type = att.get('mime_type', 'application/octet-stream')
        
        extension = ''
        if '.' in filename:
            extension = '.' + filename.split('.')[-1].lower()

        risk = "LOW RISK"
        reason = None
        
        if extension in SUSPICIOUS_EXTENSIONS:
            risk = "SUSPICIOUS"
            reason = "Suspicious file extension"
            total_risk_score += 25

        # Calculate SHA-256 safely
        sha256_hash = hashlib.sha256(content).hexdigest() if isinstance(content, bytes) else hashlib.sha256(str(content).encode()).hexdigest()

        results.append({
            "filename": filename,
            "mime_type": mime_type,
            "size": len(content) if isinstance(content, bytes) else len(str(content)),
            "extension": extension,
            "risk": risk,
            "reason": reason,
            "sha256": sha256_hash
        })

    return {
        "attachment_results": results,
        "attachment_risk_score": min(total_risk_score, 100)
    }

