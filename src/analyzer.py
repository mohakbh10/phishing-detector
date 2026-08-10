from src.scoring import score_url
from src.redirects import get_redirect_chain
from src.google_safe_browsing import check_google_safe_browsing
from src.whitelist import is_whitelisted
from src.ml.predictor import predict_url

def analyze_url_full(url):
    try:
        score, verdict, reasons = score_url(url)
        trusted, _ = is_whitelisted(url)
        chain, redirect_error = get_redirect_chain(url)
        for hop in chain[1:]:
            hop_score, _, hop_reasons = score_url(hop)
            if hop_score > score:
                score = hop_score
                for reason in hop_reasons:
                    message = f"Redirect landing page: {reason}"
                    if message not in reasons: reasons.append(message)
        threat_intelligence = check_google_safe_browsing(chain[-1] if chain else url)
        ml = predict_url(url)
        if threat_intelligence.get("malicious"):
            score = max(score, 85); verdict = "HIGH RISK"; reasons.append("Flagged by Google Safe Browsing")
        elif not trusted and ml.get("available") and ml.get("phishing_probability", 0) >= .85 and score < 31:
            score = max(score, 35); verdict = "SUSPICIOUS"; reasons.append("ML model reports a high phishing probability")
        elif trusted:
            score, verdict = 0, "LOW RISK"
        else:
            verdict = "HIGH RISK" if score > 60 else "SUSPICIOUS" if score > 30 else "LOW RISK"
        return {"url":url,"score":min(int(score),100),"verdict":verdict,"reasons":reasons,"redirect_chain":chain,"redirect_error":redirect_error,"threat_intelligence":threat_intelligence,"google_safe_browsing":threat_intelligence,"ml":ml}
    except Exception as exc:
        unavailable={"available":False,"malicious":None,"error":"Analysis component unavailable"}
        return {"url":url,"score":0,"verdict":"ERROR","reasons":["URL analysis failed safely"],"redirect_chain":[url],"redirect_error":exc.__class__.__name__,"threat_intelligence":unavailable,"google_safe_browsing":unavailable,"ml":{"available":False,"prediction":None,"phishing_probability":None,"legitimate_probability":None,"error":"Model unavailable"}}

def aggregate_risk(url_results, header_risk=0, attachment_risk=0, header_findings=None, attachment_results=None):
    reasons=[]; max_url=max((int(item.get("score",0)) for item in url_results),default=0)
    highs=[item.get("url","") for item in url_results if item.get("verdict")=="HIGH RISK"]
    suspicious=[item.get("url","") for item in url_results if item.get("verdict")=="SUSPICIOUS"]
    if highs: reasons.append("High-risk URL(s) detected: " + ", ".join(highs[:3]))
    elif suspicious: reasons.append("Suspicious URL(s) detected: " + ", ".join(suspicious[:3]))
    if header_findings:
        reasons.extend("Header alert: " + f["message"] for f in header_findings if f.get("severity") in {"high", "medium"})
    if attachment_results:
        flagged=[a.get("filename", "unknown") for a in attachment_results if a.get("risk")=="SUSPICIOUS"]
        if flagged: reasons.append("Suspicious attachment(s): " + ", ".join(flagged))
    score=round(max_url*.70 + min(header_risk,100)*.20 + min(attachment_risk,100)*.10) if url_results else round(min(header_risk,100)*.6 + min(attachment_risk,100)*.4)
    score=min(max(score,0),100)
    verdict="HIGH RISK" if highs or score>60 else "SUSPICIOUS" if suspicious or score>30 or attachment_risk>0 else "LOW RISK"
    return score, verdict, reasons[:8]
