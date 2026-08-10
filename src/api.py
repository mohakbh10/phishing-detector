from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

from src.utils import extract_urls
from src.email_parser import parse_eml
from src.header_analysis import analyze_headers
from src.attachment_analysis import analyze_attachments
from src.analyzer import analyze_url_full, aggregate_risk

app = FastAPI(title="Phishing Detector API")

# ============================================================
# CORS CONFIGURATION
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# MODELS
# ============================================================

class EmailRequest(BaseModel):
    email_text: str

class URLRequest(BaseModel):
    url: str

# ============================================================
# ENDPOINTS
# ============================================================

@app.get("/")
def home():
    return {"message": "Phishing Detector API is running"}

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "services": {
            "url_heuristics": "online",
            "header_analysis": "online",
            "attachment_analysis": "online",
            "threat_intelligence": "configured-or-graceful-degradation",
            "ml": "configured-or-graceful-degradation"
        }
    }

@app.post("/analyze/url")
def analyze_url(request: URLRequest):
    if not request.url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    return analyze_url_full(request.url)

@app.post("/analyze/email")
def analyze_email(request: EmailRequest):
    if not request.email_text:
        return {
            "urls_found": 0,
            "url_results": [],
            "overall_score": 0,
            "overall_verdict": "LOW RISK",
            "reasons": ["Empty email content provided"]
        }

    urls = extract_urls(request.email_text)
    url_results = [analyze_url_full(url) for url in urls]
    
    overall_score, overall_verdict, reasons = aggregate_risk(url_results)
    
    return {
        "urls_found": len(urls),
        "url_results": url_results,
        "overall_score": overall_score,
        "overall_verdict": overall_verdict,
        "reasons": reasons
    }

@app.post("/analyze/eml")
async def analyze_eml_file(file: UploadFile = File(...)):
    if not file.filename.lower().endswith('.eml'):
        raise HTTPException(status_code=400, detail="Only .eml files are supported")
    
    try:
        content = await file.read()
        parsed = parse_eml(content)
        
        # Analyze components
        header_analysis = analyze_headers(parsed['raw_msg'])
        attachment_analysis = analyze_attachments(parsed['attachments'])
        
        url_results = [analyze_url_full(url) for url in parsed['urls']]
        
        overall_score, overall_verdict, overall_reasons = aggregate_risk(
            url_results, 
            header_risk=header_analysis['risk_score'],
            attachment_risk=attachment_analysis['attachment_risk_score'],
            header_findings=header_analysis['findings'],
            attachment_results=attachment_analysis['attachment_results']
        )
        
        return {
            "email": {
                "filename": file.filename,
                "subject": parsed['headers'].get('Subject'),
                "from": parsed['headers'].get('From'),
                "to": parsed['headers'].get('To'),
                "reply_to": parsed['headers'].get('Reply-To'),
                "return_path": parsed['headers'].get('Return-Path'),
                "date": parsed['headers'].get('Date'),
                "message_id": parsed['headers'].get('Message-ID')
            },
            "headers": {
                "received": parsed['received'],
                "authentication_results": parsed['headers'].get('Authentication-Results'),
                "spf": header_analysis['auth_status']['spf'],
                "dkim": header_analysis['auth_status']['dkim'],
                "dmarc": header_analysis['auth_status']['dmarc'],
                "findings": header_analysis['findings'],
                "risk_score": header_analysis['risk_score']
            },
            "body": {
                "text": parsed['body_text'],
                "html_present": parsed['body_html_present']
            },
            "urls_found": len(parsed['urls']),
            "url_results": url_results,
            "attachments": attachment_analysis['attachment_results'],
            "overall_score": overall_score,
            "overall_verdict": overall_verdict,
            "reasons": overall_reasons
        }
    except Exception:
        raise HTTPException(status_code=400, detail="Failed to safely parse .eml")
