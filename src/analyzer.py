from src.scoring import score_url
from src.redirects import get_redirect_chain
from src.urlscan import check_urlscan
from src.header_analysis import analyze_headers
from src.attachment_analysis import analyze_attachments

def analyze_url_full(url):
    """
    Complete analysis for a single URL, including redirects and urlscan.io threat-intel.
    """
    try:
        # 1. Follow redirect chain safely
        redirect_chain, redirect_error = get_redirect_chain(url)
        
        # 2. Calculate heuristic score of the initial URL
        score, verdict, reasons = score_url(url)
        
        max_score = score
        final_reasons = list(reasons)
        final_verdict = verdict
        
        # 3. Analyze each landing hop in the redirect chain to prevent redirect bypass
        if len(redirect_chain) > 1:
            for hop in redirect_chain[1:]:
                hop_score, hop_verdict, hop_reasons = score_url(hop)
                if hop_score > max_score:
                    max_score = hop_score
                    final_verdict = hop_verdict
                    # Add unique reasons
                    for r in hop_reasons:
                        msg = f"Redirect landing page: {r}"
                        if msg not in final_reasons:
                            final_reasons.append(msg)

        # 4. Query urlscan.io for reputation
        urlscan_result = check_urlscan(url)
        # If urlscan was clean, also check the final redirect destination to be thorough
        if redirect_chain and len(redirect_chain) > 1:
            if not (urlscan_result.get("available") and urlscan_result.get("malicious")):
                final_url_scan = check_urlscan(redirect_chain[-1])
                if final_url_scan.get("available") and final_url_scan.get("malicious"):
                    urlscan_result = final_url_scan

        # 5. Integrate external intelligence
        if urlscan_result.get("available") and urlscan_result.get("malicious"):
            final_verdict = "HIGH RISK"
            max_score = max(max_score, 85)
            if "Flagged by urlscan.io threat intelligence" not in final_reasons:
                final_reasons.append("Flagged by urlscan.io threat intelligence")

        # 6. Re-evaluate final verdict based on final aggregated URL score
        if final_verdict != "HIGH RISK":
            if max_score > 60:
                final_verdict = "HIGH RISK"
            elif max_score > 30:
                final_verdict = "SUSPICIOUS"
            else:
                final_verdict = "LOW RISK"

        return {
            "url": url,
            "score": max_score,
            "verdict": final_verdict,
            "reasons": final_reasons,
            "redirect_chain": redirect_chain,
            "redirect_error": redirect_error,
            "urlscan": urlscan_result
        }
    except Exception as e:
        return {
            "url": url,
            "score": 0,
            "verdict": "ERROR",
            "reasons": [f"Analysis failure: {str(e)}"],
            "redirect_chain": [url],
            "redirect_error": str(e),
            "urlscan": {
                "available": False,
                "malicious": None,
                "results_found": 0,
                "error": str(e)
            }
        }

def aggregate_risk(url_results, header_risk=0, attachment_risk=0, header_findings=None, attachment_results=None):
    """
    Aggregates risk from all components: URLs, Headers, and Attachments.
    """
    explainable_reasons = []
    
    # URL Risk Signal
    max_url_score = 0
    if url_results:
        max_url_score = max([r['score'] for r in url_results])
        high_risk_urls = [r['url'] for r in url_results if r['verdict'] == "HIGH RISK"]
        susp_urls = [r['url'] for r in url_results if r['verdict'] == "SUSPICIOUS"]
        
        if high_risk_urls:
            explainable_reasons.append(f"High-risk URL(s) detected: {', '.join(high_risk_urls[:3])}")
        elif susp_urls:
            explainable_reasons.append(f"Suspicious URL(s) detected: {', '.join(susp_urls[:3])}")
            
        # Weighting: URLs are the strongest signal (0.7)
        overall_score = (max_url_score * 0.7) + (header_risk * 0.2) + (attachment_risk * 0.1)
    else:
        # No URLs in email - redistribute weights between headers and attachments
        overall_score = (header_risk * 0.6) + (attachment_risk * 0.4)

    # Header Risk Signal
    if header_findings:
        for finding in header_findings:
            if finding.get('severity') == 'high':
                explainable_reasons.append(f"Header Alert: {finding.get('message')}")
            elif finding.get('severity') == 'medium' and len(explainable_reasons) < 5:
                explainable_reasons.append(f"Header Warning: {finding.get('message')}")

    # Attachment Risk Signal
    if attachment_results:
        susp_attachments = [a['filename'] for a in attachment_results if a['risk'] == 'SUSPICIOUS']
        if susp_attachments:
            explainable_reasons.append(f"Suspicious attachment(s) found: {', '.join(susp_attachments)}")

    # Decisioning & Verdict
    # 1. Any malicious URL instantly makes the email HIGH RISK
    has_high_risk_url = any(r['verdict'] == "HIGH RISK" for r in url_results) if url_results else False
    has_suspicious_url = any(r['verdict'] == "SUSPICIOUS" for r in url_results) if url_results else False
    
    verdict = "LOW RISK"
    if has_high_risk_url or overall_score > 60:
        verdict = "HIGH RISK"
    elif has_suspicious_url or overall_score > 30 or header_risk > 20 or attachment_risk > 0:
        verdict = "SUSPICIOUS"

    # Make sure score is cleanly capped at 100 and returned as integer
    return int(min(overall_score, 100)), verdict, explainable_reasons

