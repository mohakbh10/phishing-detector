from fastapi import FastAPI
from pydantic import BaseModel

from src.utils import extract_urls
from src.scoring import score_url
from src.redirects import get_redirect_chain
from src.urlscan import check_urlscan


app = FastAPI()


# ============================================================
# REQUEST MODEL
# ============================================================

class EmailRequest(BaseModel):
    email_text: str


# ============================================================
# ROOT ROUTE
# ============================================================

@app.get("/")
def home():

    return {
        "message": "Phishing Detector API running"
    }


# ============================================================
# ANALYZE EMAIL
# ============================================================

@app.post("/analyze/email")
def analyze_email(request: EmailRequest):

    # Extract URLs from email text
    urls = extract_urls(request.email_text)

    results = []

    overall_verdict = "LOW RISK"

    # Analyze every URL
    for url in urls:

        try:

            # ----------------------------
            # Heuristic scoring
            # ----------------------------
            score, verdict, reasons = score_url(url)

            # ----------------------------
            # Redirect chain analysis
            # ----------------------------
            redirect_chain, redirect_error = get_redirect_chain(url)

            # ----------------------------
            # urlscan.io intelligence
            # ----------------------------
            urlscan_result = check_urlscan(url)

            # ----------------------------
            # Upgrade verdict if urlscan says malicious
            # ----------------------------
            if (
                urlscan_result["available"]
                and urlscan_result["malicious"]
            ):

                verdict = "HIGH RISK"

                reasons.append(
                    "Flagged by urlscan.io threat intelligence"
                )

                if score < 70:
                    score = 70

            # ----------------------------
            # Overall email verdict
            # ----------------------------
            if verdict == "HIGH RISK":
                overall_verdict = "HIGH RISK"

            elif (
                verdict == "SUSPICIOUS"
                and overall_verdict != "HIGH RISK"
            ):
                overall_verdict = "SUSPICIOUS"

            # ----------------------------
            # Final response object
            # ----------------------------
            results.append({

                "url": url,

                "score": score,

                "verdict": verdict,

                "reasons": reasons,

                "redirect_chain": redirect_chain,

                "redirect_error": redirect_error,

                "urlscan": urlscan_result
            })

        except Exception as e:

            # Never crash backend because of one bad URL
            results.append({

                "url": url,

                "score": 0,

                "verdict": "ERROR",

                "reasons": [str(e)],

                "redirect_chain": [],

                "redirect_error": "Analysis failed",

                "urlscan": {
                    "available": False,
                    "malicious": None,
                    "results_found": 0,
                    "error": "Analysis failed"
                }
            })

    # ========================================================
    # FINAL RESPONSE
    # ========================================================

    return {

        "urls_found": len(urls),

        "overall_verdict": overall_verdict,

        "results": results
    }