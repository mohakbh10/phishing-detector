from fastapi import FastAPI
from pydantic import BaseModel

from src.utils import extract_urls
from src.scoring import score_url
from src.redirects import get_redirect_chain
from src.phishtank import check_phishtank


app = FastAPI()


class EmailRequest(BaseModel):
    email_text: str


@app.get("/")
def home():
    return {
        "message": "Phishing Detector API running"
    }


@app.post("/analyze/email")
def analyze_email(request: EmailRequest):

    urls = extract_urls(request.email_text)

    results = []

    for url in urls:

        score, verdict, reasons = score_url(url)

        redirect_chain, redirect_error = get_redirect_chain(url)

        phishtank_result = check_phishtank(url)

        results.append({
            "url": url,
            "score": score,
            "verdict": verdict,
            "reasons": reasons,
            "redirect_chain": redirect_chain,
            "redirect_error": redirect_error,
            "phishtank": phishtank_result
        })

    return {
        "urls_found": len(urls),
        "results": results
    }